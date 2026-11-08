# MIO Backend — مرحله اول

ورود امن Telegram Mini App، پروفایل و موجودی واقعی Supabase، ثبت کارت در وضعیت pending و Socket.IO متصل. **تأیید کارت، شارژ خودکار، بازی و شرط‌بندی هنوز فعال نیستند.**

## Render
Create Web Service from this repository. Build: `npm install`, Start: `npm start`, Node >=20.

Environment variables (set ONLY in Render, never GitHub):
- `TELEGRAM_BOT_TOKEN`: bot token from BotFather
- `SESSION_SECRET`: strong random 32+ byte secret
- `SUPABASE_URL`: project URL
- `SUPABASE_SERVICE_ROLE_KEY`: service-role key (server only)
- `FRONTEND_ORIGIN`: `https://mio-frontend-o4kw.onrender.com`

After deployment, set `apiBase` in the frontend `index.html` `MIO_CONFIG` to the HTTPS backend URL, and `socketUrl` to the same URL (or leave empty). Re-deploy frontend.

Security notes: Do not use service-role key in frontend. Card ownership is **not verified** by registering a card; `pending` status deliberately blocks use. `/api/crash/bets` and `/api/crash/cashouts` return 503. Deposits are not credited by this server. For production add verified card ownership, durable idempotency, proper game settlement transactions, abuse controls, and full integration tests.
