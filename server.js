
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
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (
  ![BOT_TOKEN, SESSION_SECRET, SUPABASE_URL, SERVICE_KEY]
    .every(Boolean)
) {
  console.error('Missing required environment variables');
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

const app = express();
app.use(cors({
  origin: FRONTEND,
  allowedHeaders: [
    'Authorization',
    'Content-Type',
    'Idempotency-Key'
  ]
}));
app.use(express.json({ limit: '20kb' }));

const server = createServer(app);

const io = new Server(server, {
  cors: { origin: FRONTEND },
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 20000
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

  return x.length === y.length &&
    timingSafeEqual(x, y);
}

// TELEGRAM AUTH

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
    [...p.keys()].length !== new Set(p.keys()).size
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
    const user = JSON.parse(p.get('user') || 'null');

    return user &&
      Number.isSafeInteger(user.id) &&
      user.id > 0 ? user : null;
  } catch {
    return null;
  }
}

function issueToken(id) {
  const payload = Buffer.from(JSON.stringify({
    id: String(id),
    exp: Date.now() + 12 * 3600_000,
    nonce: randomBytes(8).toString('hex')
  })).toString('base64url');

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

    return /^\d{1,20}$/.test(obj.id) &&
      Number.isFinite(obj.exp) &&
      obj.exp > Date.now()
      ? obj.id
      : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const token = (req.get('authorization') || '')
    .replace(/^Bearer /i, '');

  const id = parseToken(token);

  if (!id) {
    return fail(res, 'AUTH_EXPIRED', 401);
  }

  req.telegramId = id;
  next();
}

// USER PROFILE

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

  const card = c.data ? {
    number: c.data.card_number,
    status: 'verified'
  } : null;

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

// BASIC API

app.get('/', (_req, res) => {
  res.json({
    name: 'MIO Backend',
    status: 'online',
    game: 'running',
    version: '0.2.0'
  });
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    gameStatus: currentRound?.status || 'starting'
  });
});

// SESSION

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

    return res.json({
      accessToken: issueToken(id),
      profile: await profile(id)
    });

  } catch (e) {
    console.error('session:', e.message);
    return fail(res, 'SERVER_ERROR', 500);
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

// MEOWIE CARD

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

    if (
      existing &&
      existing.card_number !== number
    ) {
      return fail(res, 'CARD_CHANGE_UNAVAILABLE', 409);
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

    return res.json(await profile(req.telegramId));

  } catch (e) {
    console.error('cards:', e.message);
    return fail(res, 'SERVER_ERROR', 500);
  }
});

// Compatibility endpoint.
// No ownership verification required.
app.post('/api/cards/verify', auth, (_req, res) => {
  res.json({
    success: true,
    message: 'Card verification is not required'
  });
});

// CRASH ENGINE

const WAITING_MS = 5000;
const AFTER_CRASH_MS = 3000;
const TICK_MS = 100;

let currentRound = null;
let crashRevision = 0;
let roundNumber = 0;

const crashHistory = [];

let phaseTimer = null;
let tickTimer = null;
let targetMultiplier = 1;

function multiplierAt(elapsed) {
  return Math.max(
    1,
    Math.floor(
      Math.exp(elapsed / 10000) * 100
    ) / 100
  );
}

function snapshot() {
  return {
    revision: crashRevision,
    serverNow: Date.now(),
    round: currentRound ? { ...currentRound } : null,
    bets: [],
    history: [...crashHistory]
  };
}

function broadcastState() {
  crashRevision++;

  io.emit('crash:state', snapshot());
}

function clearTimers() {
  if (phaseTimer) clearTimeout(phaseTimer);
  if (tickTimer) clearInterval(tickTimer);

  phaseTimer = null;
  tickTimer = null;
}

function startWaiting() {
  clearTimers();

  const now = Date.now();

  roundNumber++;

  currentRound = {
    id: randomBytes(16).toString('hex'),
    roundNumber,
    status: 'waiting',
    multiplier: 1,
    bettingClosesAt: now + WAITING_MS,
    startedAt: null,
    crashedAt: null,
    crashMultiplier: null
  };

  broadcastState();

  console.log(
    `Round ${roundNumber}: waiting`
  );

  phaseTimer = setTimeout(
    startFlying,
    WAITING_MS
  );
}

function startFlying() {
  if (currentRound?.status !== 'waiting') {
    return;
  }

  const roundId = currentRound.id;

  // Demo-only outcome.
  // Not a production fairness or payout system.
  targetMultiplier = randomInt(120, 801) / 100;

  const now = Date.now();

  currentRound.status = 'flying';
  currentRound.startedAt = now;
  currentRound.multiplier = 1;

  broadcastState();

  console.log(
    `Round ${roundNumber}: flying`
  );

  tickTimer = setInterval(() => {
    if (
      !currentRound ||
      currentRound.id !== roundId ||
      currentRound.status !== 'flying'
    ) {
      clearInterval(tickTimer);
      tickTimer = null;
      return;
    }

    const elapsed =
      Date.now() - currentRound.startedAt;

    const multiplier = multiplierAt(elapsed);

    if (multiplier >= targetMultiplier) {
      crashRound();
      return;
    }

    currentRound.multiplier = multiplier;

    io.emit('crash:tick', {
      roundId,
      multiplier,
      serverNow: Date.now()
    });

  }, TICK_MS);
}

function crashRound() {
  if (currentRound?.status !== 'flying') {
    return;
  }

  if (tickTimer) {
    clearInterval(tickTimer);
    tickTimer = null;
  }

  const now = Date.now();

  currentRound.status = 'crashed';
  currentRound.multiplier = targetMultiplier;
  currentRound.crashMultiplier = targetMultiplier;
  currentRound.crashedAt = now;

  crashHistory.unshift({
    roundId: currentRound.id,
    roundNumber: currentRound.roundNumber,
    multiplier: targetMultiplier,
    crashMultiplier: targetMultiplier,
    crashedAt: now
  });

  if (crashHistory.length > 10) {
    crashHistory.length = 10;
  }

  broadcastState();

  console.log(
    `Round ${roundNumber}: crashed at ${targetMultiplier}x`
  );

  phaseTimer = setTimeout(
    startWaiting,
    AFTER_CRASH_MS
  );
}

// CRASH API

app.get('/api/crash/snapshot', auth, (_req, res) => {
  res.json(snapshot());
});

app.get('/api/crash/stats', auth, (_req, res) => {
  res.json({
    totalRounds: roundNumber,
    recentCrashes: crashHistory,
    activePlayers: 0
  });
});

// Keep money-changing endpoints disabled
// until atomic DB transactions are implemented.
app.post(
  ['/api/crash/bets', '/api/crash/cashouts'],
  auth,
  (_req, res) => {
    fail(res, 'SERVICE_NOT_READY', 503);
  }
);

app.use('/api', (_req, res) => {
  fail(res, 'NOT_FOUND', 404);
});

// SOCKET.IO AUTH

io.use((socket, next) => {
  const id = parseToken(
    socket.handshake.auth?.token
  );

  if (!id) {
    const error = new Error(
      'Authentication required'
    );

    error.data = {
      code: 'AUTH_EXPIRED'
    };

    return next(error);
  }

  socket.data.userId = id;
  next();
});

// SOCKET.IO EVENTS

io.on('connection', socket => {
  console.log('Socket connected:', socket.id);

  socket.emit('crash:state', snapshot());

  socket.on('crash:sync', (_payload, ack) => {
    if (typeof ack === 'function') {
      ack(snapshot());
    }

    socket.emit('crash:state', snapshot());
  });

  socket.on('disconnect', reason => {
    console.log(
      'Socket disconnected:',
      reason
    );
  });
});

// START SERVER

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

    startWaiting();
  }
);

// GRACEFUL SHUTDOWN

function shutdown() {
  clearTimers();

  io.close(() => {
    server.close(() => {
      process.exit(0);
    });
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
