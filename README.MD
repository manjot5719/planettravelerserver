# License Server (Render-ready)

This repository contains a small license server (Express) that supports **Postgres** (via `DATABASE_URL`) and **SQLite** (via `DB_PATH`).
I generated an `ADMIN_TOKEN` for you: **8378f8db-4214-4156-b845-c24b280a8cab**

> Keep this ADMIN_TOKEN secret. You can use it when calling admin APIs (use header `x-admin-token: 8378f8db-4214-4156-b845-c24b280a8cab`).

## Files
- `server.js` - main server
- `create_db_safe.js` - safe initializer (creates tables + ADMIN_TOKEN if missing)
- `package.json`
- `client_snippet.js` - paste into your client script (change LICENSE_SERVER_URL after deploy)
- `.gitignore`

## Quick local test (recommended)
1. Clone into a folder.
2. `npm install`
3. For local SQLite test:
   - `node create_db_safe.js`  # This will create ./licenses.db and print ADMIN_TOKEN (or use the token above)
   - `npm start`
   - Server will run at http://localhost:3000

4. Create a license (example):
```bash
curl -X POST http://localhost:3000/admin/create-license \
  -H "Content-Type: application/json" \
  -H "x-admin-token: 8378f8db-4214-4156-b845-c24b280a8cab" \
  -d '{"key":"USER-001","max_devices":1}'
```

## Deploy to Render (managed Postgres recommended)
1. Create a Render Postgres database (Free tier is fine for testing). Copy the `DATABASE_URL`.
2. Create a new Web Service on Render and connect your GitHub repo containing these files.
3. Set the Environment Variables on the Render Web Service:
   - `DATABASE_URL` = (your Render Postgres connection string)
   - `ADMIN_TOKEN` = 8378f8db-4214-4156-b845-c24b280a8cab
   - (`DB_PATH` not required for Postgres)
4. In the Render Web Service settings set Build Command: `npm install` and Start Command: `npm start`
5. Run `node create_db_safe.js` once on the server (via a one-off job or locally with `DATABASE_URL` set) to create tables and ensure DB ready.
   - Alternatively, set `start` to `node create_db_safe.js && node server.js` temporarily on first deploy.
6. After deploy, set `LICENSE_SERVER_URL` in `client_snippet.js` to your Render service URL (e.g. https://your-service.onrender.com) and paste the snippet into your client script — only this line needs changing.

## Notes
- The server prioritizes the `ADMIN_TOKEN` environment variable if present; otherwise it reads the token stored in DB.
- For production, restrict CORS origins and protect admin token. Monitor logs for suspicious device activations.

