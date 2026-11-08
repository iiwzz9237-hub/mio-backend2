import express from 'express';
import cors from 'cors';
import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { Server } from 'socket.io';
import { createClient } from '@supabase/supabase-js';

const FRONTEND = process.env.FRONTEND_ORIGIN || 'https://mio-frontend-o4kw.onrender.com';
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (![BOT_TOKEN, SESSION_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY].every(Boolean)) {
  console.error('Missing required environment variables'); process.exit(1);
}
const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {auth:{persistSession:false,autoRefreshToken:false}});
const app = express();
app.use(cors({origin:FRONTEND,allowedHeaders:['Authorization','Content-Type','Idempotency-Key']}));
app.use(express.json({limit:'20kb'}));
const server = createServer(app);
const io = new Server(server,{cors:{origin:FRONTEND}});
const fail=(res,code,status=400)=>res.status(status).json({code});
const hmac=(key,data)=>createHmac('sha256',key).update(data).digest('hex');
const same=(a,b)=>{const x=Buffer.from(a||''),y=Buffer.from(b||'');return x.length===y.length&&timingSafeEqual(x,y)};
function telegramUser(initData){
  if(typeof initData!=='string'||initData.length>8192||!initData)return null;
  const p=new URLSearchParams(initData);
  const hash=p.get('hash');const date=Number(p.get('auth_date'));
  if(!hash||!/^[a-f0-9]{64}$/i.test(hash)||!Number.isSafeInteger(date)||Math.abs(Date.now()/1000-date)>3600)return null;
  if([...p.keys()].length!==new Set(p.keys()).size)return null;
  const data=[...p.entries()].filter(([k])=>k!=='hash').sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join('\n');
  const secret=createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();
  const expected=createHmac('sha256',secret).update(data).digest('hex');
  if(!same(hash.toLowerCase(),expected))return null;
  try {const u=JSON.parse(p.get('user')||'null');return u&&Number.isSafeInteger(u.id)&&u.id>0?u:null;}catch{return null;}
}
function issueToken(id){
  const payload=Buffer.from(JSON.stringify({id:String(id),exp:Date.now()+12*3600_000,nonce:randomBytes(8).toString('hex')})).toString('base64url');
  return `${payload}.${hmac(SESSION_SECRET,payload)}`;
}
function parseToken(token){
  if(typeof token!=='string')return null;
  const [p,s,...rest]=token.split('.');if(!p||!s||rest.length||!same(hmac(SESSION_SECRET,p),s))return null;
  try {const obj=JSON.parse(Buffer.from(p,'base64url').toString());return /^\d{1,20}$/.test(obj.id)&&Number.isFinite(obj.exp)&&obj.exp>Date.now()?obj.id:null;}catch{return null;}
}
function auth(req,res,next){
  const id=parseToken((req.get('authorization')||'').replace(/^Bearer /i,''));
  if(!id)return fail(res,'AUTH_EXPIRED',401);
  req.telegramId=id;next();
}
async function profile(id){
  const [u,w,c]=await Promise.all([
    db.from('users').select('*').eq('telegram_id',id).single(),
    db.from('wallets').select('*').eq('telegram_id',id).single(),
    db.from('meowie_cards').select('*').eq('telegram_id',id).eq('is_active',true).maybeSingle()
  ]);
  if(u.error||w.error||c.error)throw Error('Database read failed');
  const card=c.data?{number:c.data.card_number,status:c.data.verified_at?'verified':'pending'}:null;
  return {revision:Math.floor(new Date(u.data.updated_at).getTime()/1000),user:{id:String(id),firstName:u.data.display_name||'',lastName:'',photoUrl:u.data.photo_url||null},wallet:{balance:String(w.data.balance),revision:Math.floor(new Date(w.data.updated_at).getTime()/1000)},card,pendingCard:null,challenge:card?.status==='pending'?{id:c.data.id,method:'manual',instructions:'کارت ثبت شد؛ تأیید مالکیت هنوز فعال نشده است.'}:null};
}
app.get('/',(_req,res)=>res.json({name:'MIO Backend',status:'online'}));
app.get('/health',(_req,res)=>res.json({ok:true}));
app.post('/api/session',async(req,res)=>{
  const user=telegramUser(req.body?.initData);if(!user)return fail(res,'INIT_DATA_INVALID',401);
  const id=String(user.id);
  try{
    const {error:e1}=await db.from('users').upsert({telegram_id:id,display_name:[user.first_name,user.last_name].filter(Boolean).join(' ').slice(0,200),username:user.username||null,photo_url:user.photo_url?.startsWith('https://')?user.photo_url:null,updated_at:new Date().toISOString()},{onConflict:'telegram_id'});
    if(e1)throw e1;
    const {error:e2}=await db.from('wallets').upsert({telegram_id:id},{onConflict:'telegram_id',ignoreDuplicates:true});
    if(e2)throw e2;
    return res.json({accessToken:issueToken(id),profile:await profile(id)});
  }catch(e){console.error('session:',e.message);return fail(res,'SERVER_ERROR',500);}
});
app.get('/api/me',auth,async(req,res)=>{try{res.json(await profile(req.telegramId));}catch(e){console.error(e.message);fail(res,'SERVER_ERROR',500);}});
app.post('/api/cards',auth,async(req,res)=>{
  const number=req.body?.number;
  if(typeof number!=='string'||!/^\d{12}$/.test(number)||/^(\d)\1{11}$/.test(number))return fail(res,'INVALID_CARD');
  try{
    const {data:existing,error:readErr}=await db.from('meowie_cards').select('id,card_number').eq('telegram_id',req.telegramId).eq('is_active',true).maybeSingle();
    if(readErr)throw readErr;
    if(existing&&existing.card_number!==number)return fail(res,'VERIFICATION_UNAVAILABLE',409);
    if(!existing){
      const {error}=await db.from('meowie_cards').insert({telegram_id:req.telegramId,card_number:number,is_active:true});
      if(error?.code==='23505')return fail(res,'CARD_IN_USE',409);
      if(error)throw error;
    }
    return res.json(await profile(req.telegramId));
  }catch(e){console.error('cards:',e.message);return fail(res,'SERVER_ERROR',500);}
});
app.post('/api/cards/verify',auth,(_req,res)=>fail(res,'VERIFICATION_UNAVAILABLE',503));
app.get('/api/crash/snapshot',auth,(_req,res)=>res.json({revision:0,serverNow:Date.now(),round:null,bets:[],history:[]}));
app.get('/api/crash/stats',auth,(_req,res)=>fail(res,'SERVICE_NOT_READY',503));
app.post(['/api/crash/bets','/api/crash/cashouts'],auth,(_req,res)=>fail(res,'SERVICE_NOT_READY',503));
app.use('/api',(_req,res)=>fail(res,'NOT_FOUND',404));
io.use((socket,next)=>{const id=parseToken(socket.handshake.auth?.token);if(!id){const err=new Error('Authentication required');err.data={code:'AUTH_EXPIRED'};return next(err);}socket.data.userId=id;next();});
io.on('connection',socket=>{socket.on('crash:sync',(_payload,ack)=>{if(typeof ack==='function')ack({revision:0,serverNow:Date.now(),round:null,bets:[],history:[]});});});
const port=Number(process.env.PORT||10000);
server.listen(port,'0.0.0.0',()=>console.log(`MIO backend listening on ${port}`));
