
import express from 'express';
import cors from 'cors';
import { createServer } from 'node:http';
import {
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual
} from 'node:crypto';
import { Server } from 'socket.io';
import { createClient } from '@supabase/supabase-js';

const FRONTEND =
  process.env.FRONTEND_ORIGIN ||
  'https://mio-frontend-o4kw.onrender.com';

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

if (
  ![
    BOT_TOKEN,
    SESSION_SECRET,
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
  ].every(Boolean)
) {
  console.error('Missing required environment variables');
  process.exit(1);
}

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const app = express();

app.use(
  cors({
    origin: FRONTEND,
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'Idempotency-Key'
    ]
  })
);

app.use(express.json({ limit: '20kb' }));

const server = createServer(app);

const io = new Server(server, {
  cors: { origin: FRONTEND },
  transports: ['websocket', 'polling']
});

const fail = (res, code, status = 400) =>
  res.status(status).json({ code });

const hmac = (key, data) =>
  createHmac('sha256', key)
    .update(data)
    .digest('hex');

function same(a, b) {
  const x = Buffer.from(a || '');
  const y = Buffer.from(b || '');

  return (
    x.length === y.length &&
    timingSafeEqual(x, y)
  );
}

function telegramUser(initData) {
  if (
    typeof initData !== 'string' ||
    !initData ||
    initData.length > 8192
  ) return null;

  const p = new URLSearchParams(initData);

  const hash = p.get('hash');
  const date = Number(p.get('auth_date'));

  if (
    !hash ||
    !/^[a-f0-9]{64}$/i.test(hash) ||
    !Number.isSafeInteger(date) ||
    Math.abs(Date.now() / 1000 - date) > 3600
  ) return null;

  if (
    [...p.keys()].length !==
    new Set(p.keys()).size
  ) return null;

  const data = [...p.entries()]
    .filter(([k]) => k !== 'hash')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secret = createHmac(
    'sha256',
    'WebAppData'
  ).update(BOT_TOKEN).digest();

  const expected = createHmac(
    'sha256',
    secret
  ).update(data).digest('hex');

  if (!same(hash.toLowerCase(), expected)) {
    return null;
  }

  try {
    const u = JSON.parse(p.get('user') || 'null');

    return (
      u &&
      Number.isSafeInteger(u.id) &&
      u.id > 0
    ) ? u : null;
  } catch {
    return null;
  }
}

function issueToken(id) {
  const payload = Buffer.from(
    JSON.stringify({
      id: String(id),
      exp: Date.now() + 12 * 3600_000,
      nonce: randomBytes(8).toString('hex')
    })
  ).toString('base64url');

  return `${payload}.${hmac(SESSION_SECRET, payload)}`;
}

function parseToken(token) {
  if (typeof token !== 'string') return null;

  const [p, s, ...rest] = token.split('.');

  if (
    !p ||
    !s ||
    rest.length ||
    !same(hmac(SESSION_SECRET, p), s)
  ) return null;

  try {
    const obj = JSON.parse(
      Buffer.from(p, 'base64url').toString()
    );

    return (
      /^\d{1,20}$/.test(obj.id) &&
      Number.isFinite(obj.exp) &&
      obj.exp > Date.now()
    ) ? obj.id : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const token = (req.get('authorization') || '')
    .replace(/^Bearer /i, '');

  const id = parseToken(token);

  if (!id) return fail(res, 'AUTH_EXPIRED', 401);

  req.telegramId = id;
  next();
}

async function profile(id) {
  const [u, w, c] = await Promise.all([
    db.from('users')
      .select('*')
      .eq('telegram_id', id)
      .single(),

    db.from('wallets')
      .select('*')
      .eq('telegram_id', id)
      .single(),

    db.from('meowie_cards')
      .select('*')
      .eq('telegram_id', id)
      .eq('is_active', true)
      .maybeSingle()
  ]);

  if (u.error || w.error || c.error) {
    throw Error('Database read failed');
  }

  const card = c.data
    ? {
        number: c.data.card_number,
        status: 'verified'
      }
    : null;

  return {
    revision: Math.floor(
      new Date(u.data.updated_at).getTime() / 1000
    ),
    user: {
      id: String(id),
      firstName: u.data.display_name || '',
      lastName: '',
      photoUrl: u.data.photo_url || null
    },
    wallet: {
      balance: String(w.data.balance),
      revision: Math.floor(
        new Date(w.data.updated_at).getTime() / 1000
      )
    },
    card,
    pendingCard: null,
    challenge: null
  };
}

app.get('/', (_req, res) => {
  res.json({
    name: 'MIO Backend',
    status: 'online'
  });
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    crashEngine: engineStatus
  });
});

app.post('/api/session', async (req, res) => {
  const user = telegramUser(req.body?.initData);

  if (!user) {
    return fail(res, 'INIT_DATA_INVALID', 401);
  }

  const id = String(user.id);

  try {
    const { error: e1 } = await db
      .from('users')
      .upsert({
        telegram_id: id,
        display_name: [
          user.first_name,
          user.last_name
        ].filter(Boolean).join(' ').slice(0, 200),
        username: user.username || null,
        photo_url:
          user.photo_url?.startsWith('https://')
            ? user.photo_url
            : null,
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'telegram_id'
      });

    if (e1) throw e1;

    const { error: e2 } = await db
      .from('wallets')
      .upsert({
        telegram_id: id
      }, {
        onConflict: 'telegram_id',
        ignoreDuplicates: true
      });

    if (e2) throw e2;

    res.json({
      accessToken: issueToken(id),
      profile: await profile(id)
    });
  } catch (e) {
    console.error('session:', e.message);
    fail(res, 'SERVER_ERROR', 500);
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    res.json(await profile(req.telegramId));
  } catch (e) {
    console.error('profile:', e.message);
    fail(res, 'SERVER_ERROR', 500);
  }
});

app.post('/api/cards', auth, async (req, res) => {
  const number = req.body?.number;

  if (
    typeof number !== 'string' ||
    !/^\d{12}$/.test(number) ||
    /^(\d)\1{11}$/.test(number)
  ) {
    return fail(res, 'INVALID_CARD');
  }

  try {
    const { data: existing, error: readErr } =
      await db.from('meowie_cards')
        .select('id,card_number')
        .eq('telegram_id', req.telegramId)
        .eq('is_active', true)
        .maybeSingle();

    if (readErr) throw readErr;

    if (existing && existing.card_number !== number) {
      return fail(
        res,
        'VERIFICATION_UNAVAILABLE',
        409
      );
    }

    if (!existing) {
      const { error } = await db
        .from('meowie_cards')
        .insert({
          telegram_id: req.telegramId,
          card_number: number,
          is_active: true
        });

      if (error?.code === '23505') {
        return fail(res, 'CARD_IN_USE', 409);
      }

      if (error) throw error;
    }

    res.json(await profile(req.telegramId));
  } catch (e) {
    console.error('cards:', e.message);
    fail(res, 'SERVER_ERROR', 500);
  }
});

app.post(
  '/api/cards/verify',
  auth,
  (_req, res) => res.json({ success: true })
);

// ------------------------------
// Crash engine
// ------------------------------

const WAITING_MS = 5000;
const AFTER_CRASH_MS = 3000;
const TICK_MS = 100;

let currentRound = null;
let revision = 0;
let roundNumber = 0;
let targetCents = 120;
let timer = null;
let currentBets = [];
let history = [];

let engineStatus = 'starting';

const now = () => Date.now();

const centsAt = elapsed =>
  Math.max(
    100,
    Math.floor(
      Math.exp(
        Math.max(0, elapsed) / 10000
      ) * 100
    )
  );

function checkDb(result) {
  if (result.error) throw result.error;
  return result.data;
}

function publicBet(b) {
  const cashout = b.crash_cashouts?.[0];

  return {
    id: b.id,
    userId: String(b.telegram_id),
    name: b.users?.display_name || 'کاربر تلگرام',
    photoUrl: b.users?.photo_url || null,
    stake: String(b.stake),
    status:
      b.status === 'cashed_out'
        ? 'CASHED_OUT'
        : b.status === 'lost'
          ? 'LOST'
          : currentRound?.status === 'waiting'
            ? 'WAITING'
            : 'ACTIVE',
    cashoutCents: cashout
      ? Math.round(Number(cashout.multiplier) * 100)
      : null,
    payout: cashout
      ? String(cashout.payout)
      : null
  };
}

async function reloadBets() {
  if (!currentRound) return;

  const rows = checkDb(
    await db.from('crash_bets')
      .select(
        'id,telegram_id,stake,status,users(display_name,photo_url),crash_cashouts(multiplier,payout)'
      )
      .eq('round_id', currentRound.id)
      .order('placed_at', { ascending: true })
  );

  currentBets = rows.map(publicBet);
}

function snapshot() {
  return {
    revision,
    serverNow: now(),
    round: currentRound
      ? { ...currentRound }
      : null,
    bets: currentBets.map(b => ({ ...b })),
    history: history.map(h => ({ ...h }))
  };
}

function broadcast() {
  revision++;
  io.emit('crash:state', snapshot());
}

function failRpc(res, e) {
  const msg = String(e?.message || '');

  const codes = [
    'INVALID_STAKE',
    'BETTING_CLOSED',
    'INSUFFICIENT_BALANCE',
    'CASHOUT_CLOSED',
    'CRASHED',
    'BET_NOT_FOUND',
    'ROUND_NOT_FOUND',
    'ROUND_NOT_READY'
  ];

  const code = codes.find(x => msg.includes(x));

  if (code) {
    return fail(
      res,
      code,
      code === 'INSUFFICIENT_BALANCE'
        ? 409
        : 400
    );
  }

  console.error('Betting DB error:', msg);
  return fail(res, 'SERVER_ERROR', 500);
}

app.get('/api/crash/snapshot', auth, (_req, res) => {
  res.json(snapshot());
});

app.get('/api/crash/stats', auth, async (req, res) => {
  try {
    const bets = checkDb(
      await db.from('crash_bets')
        .select(
          'status,stake,crash_cashouts(payout)'
        )
        .eq('telegram_id', req.telegramId)
    );

    const wins = bets.filter(
      b => b.status === 'cashed_out'
    );

    const losses = bets.filter(
      b => b.status === 'lost'
    );

    const won = wins.reduce(
      (a, b) =>
        a + BigInt(
          b.crash_cashouts?.[0]?.payout || 0
        ),
      0n
    );

    const lost = losses.reduce(
      (a, b) => a + BigInt(b.stake),
      0n
    );

    const best = wins.reduce(
      (a, b) =>
        Math.max(
          a,
          Math.round(
            Number(
              b.crash_cashouts?.[0]?.payout || 0
            ) / Number(b.stake) * 100
          )
        ),
      0
    );

    res.json({
      rounds: wins.length + losses.length,
      wins: wins.length,
      losses: losses.length,
      won: String(won),
      lost: String(lost),
      bestCents: best
    });
  } catch (e) {
    console.error('stats:', e.message);
    fail(res, 'SERVER_ERROR', 500);
  }
});

// Disable balance-changing requests when
// the engine is not healthy.
function requireEngine(req, res, next) {
  if (engineStatus !== 'running') {
    return fail(res, 'ENGINE_UNAVAILABLE', 503);
  }
  next();
}

app.post(
  '/api/crash/bets',
  auth,
  requireEngine,
  async (req, res) => {
    const { roundId, stake } = req.body || {};

    if (
      typeof roundId !== 'string' ||
      !/^[a-f0-9-]{36}$/i.test(roundId) ||
      typeof stake !== 'string' ||
      !/^[1-9]\d{0,15}$/.test(stake)
    ) {
      return fail(res, 'INVALID_STAKE');
    }

    try {
      const betId = checkDb(
        await db.rpc('mio_place_bet', {
          p_user: req.telegramId,
          p_round: roundId,
          p_stake: stake
        })
      );

      if (currentRound?.id === roundId) {
        await reloadBets();
        broadcast();
      }

      res.json({
        accepted: true,
        betId
      });
    } catch (e) {
      failRpc(res, e);
    }
  }
);

app.post(
  '/api/crash/cashouts',
  auth,
  requireEngine,
  async (req, res) => {
    const { roundId, betId } = req.body || {};

    if (
      ![roundId, betId].every(
        x =>
          typeof x === 'string' &&
          /^[a-f0-9-]{36}$/i.test(x)
      )
    ) {
      return fail(res, 'INVALID_REQUEST');
    }

    try {
      const result = checkDb(
        await db.rpc('mio_cashout', {
          p_user: req.telegramId,
          p_round: roundId,
          p_bet: betId
        })
      );

      if (currentRound?.id === roundId) {
        await reloadBets();
        broadcast();
      }

      res.json({
        accepted: true,
        ...result
      });
    } catch (e) {
      failRpc(res, e);
    }
  }
);

app.use('/api', (_req, res) => {
  fail(res, 'NOT_FOUND', 404);
});

// ------------------------------
// Socket.IO
// ------------------------------

io.use((socket, next) => {
  const id = parseToken(
    socket.handshake.auth?.token
  );

  if (!id) {
    const e = new Error(
      'Authentication required'
    );

    e.data = { code: 'AUTH_EXPIRED' };
    return next(e);
  }

  socket.data.userId = id;
  next();
});

io.on('connection', socket => {
  socket.emit('crash:state', snapshot());

  socket.on('crash:sync', (_payload, ack) => {
    if (typeof ack === 'function') {
      ack(snapshot());
    }

    socket.emit('crash:state', snapshot());
  });
});

// ------------------------------
// Round lifecycle
// ------------------------------

async function startWaiting() {
  const start = now();

  const id = randomBytes(16)
    .toString('hex')
    .replace(
      /^(.{8})(.{4})(.{4})(.{4})(.{12})$/,
      '$1-$2-$3-$4-$5'
    );

  const row = checkDb(
    await db.from('crash_rounds')
      .insert({
        id,
        status: 'waiting',
        betting_closes_at:
          new Date(start + WAITING_MS)
            .toISOString()
      })
      .select('round_number')
      .single()
  );

  roundNumber = Number(row.round_number);

  currentRound = {
    id,
    roundNumber,
    status: 'waiting',
    multiplier: 1,
    bettingClosesAt: start + WAITING_MS,
    startedAt: null,
    crashedAt: null,
    crashMultiplier: null
  };

  currentBets = [];
  engineStatus = 'running';

  broadcast();

  timer = setTimeout(() => {
    void startFlying().catch(fatal);
  }, WAITING_MS);
}

async function startFlying() {
  if (
    !currentRound ||
    currentRound.status !== 'waiting'
  ) return;

  const id = currentRound.id;

  // Cryptographically secure random integer.
  targetCents = randomInt(120, 801);

  checkDb(
    await db.from('mio_round_targets')
      .insert({
        round_id: id,
        target_cents: targetCents
      })
  );

  const started = new Date();

  checkDb(
    await db.from('crash_rounds')
      .update({
        status: 'flying',
        started_at: started.toISOString()
      })
      .eq('id', id)
      .eq('status', 'waiting')
      .select('id')
      .single()
  );

  currentRound.status = 'flying';
  currentRound.startedAt = started.getTime();
  currentRound.multiplier = 1;

  await reloadBets();
  broadcast();

  timer = setInterval(() => {
    if (
      currentRound?.id !== id ||
      currentRound.status !== 'flying'
    ) return;

    const cents = centsAt(
      now() - currentRound.startedAt
    );

    if (cents >= targetCents) {
      clearInterval(timer);
      timer = null;

      void crashRound(id).catch(fatal);
      return;
    }

    currentRound.multiplier = cents / 100;

    io.emit('crash:tick', {
      roundId: id,
      multiplier: cents / 100,
      serverNow: now()
    });
  }, TICK_MS);
}

async function crashRound(id) {
  if (
    !currentRound ||
    currentRound.id !== id ||
    currentRound.status !== 'flying'
  ) return;

  checkDb(
    await db.rpc('mio_finish_round', {
      p_round: id,
      p_target: targetCents
    })
  );

  currentRound.status = 'crashed';
  currentRound.crashedAt = now();
  currentRound.crashMultiplier =
    targetCents / 100;
  currentRound.multiplier =
    targetCents / 100;

  await reloadBets();

  history.unshift({
    roundId: id,
    roundNumber,
    multiplier: targetCents / 100,
    crashMultiplier: targetCents / 100,
    crashedAt: currentRound.crashedAt
  });

  history = history.slice(0, 10);

  broadcast();

  timer = setTimeout(() => {
    void startWaiting().catch(fatal);
  }, AFTER_CRASH_MS);
}

function fatal(e) {
  console.error(
    'FATAL CRASH ENGINE:',
    e
  );

  engineStatus = 'stopped';

  if (timer) {
    clearTimeout(timer);
    clearInterval(timer);
    timer = null;
  }

  io.emit('crash:error', {
    code: 'ENGINE_UNAVAILABLE'
  });
}

// ------------------------------
// Startup and shutdown
// ------------------------------

const port = Number(
  process.env.PORT || 10000
);

server.listen(
  port,
  '0.0.0.0',
  () => {
    console.log(
      `MIO backend listening on ${port}`
    );

    (async () => {
      const rows = checkDb(
        await db.from('crash_rounds')
          .select('id,status')
          .in('status', [
            'waiting',
            'flying'
          ])
          .limit(1)
      );

      if (rows.length) {
        throw Error(
          'Unfinished round found. ' +
          'Reconcile or cancel it ' +
          'before restarting.'
        );
      }

      await startWaiting();
    })().catch(fatal);
  }
);

function shutdown() {
  engineStatus = 'stopped';

  if (timer) {
    clearTimeout(timer);
    clearInterval(timer);
  }

  io.close(() => {
    server.close(() => process.exit(0));
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
