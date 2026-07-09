# D'zine Brand Studio — Client Portal

A full-stack client portal for D'zine Brand Studio. Clients log in, fill out a brand questionnaire, review color palettes, logo concepts, and design deliverables at each stage.

## Tech Stack
- **Backend:** Node.js, Express, Sequelize, MySQL
- **Frontend:** Vanilla HTML/CSS/JS (glassmorphism UI)
- **Auth:** JWT + bcrypt (bcryptjs, rounds = 12)

---

## Quick Start (Local)

### 1. Database Setup
```bash
# In phpMyAdmin or MySQL CLI:
mysql -u root -p < server/schema.sql
```
This creates the `dzine_portal` database and a default admin user.

**Default Admin:** `admin@dzine.com` / `admin123`
> ⚠️ Change the admin password immediately after first login!

### 2. Backend
```bash
cd server
cp .env.example .env          # Fill in your values
npm install
npm run dev                   # http://localhost:5000
```

### 3. Frontend
Open with a Live Server extension (VS Code) on port 5500 or 5501:
- Client login: `client/pages/login.html`
- Register: `client/pages/register.html`
- Admin login: `client/pages/admin/admin-login.html`

---

## Production Deployment

### Environment Variables (server/.env)
| Variable | Description |
|---|---|
| `NODE_ENV` | Set to `production` |
| `PORT` | Port to listen on (default 5000) |
| `DB_HOST` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | MySQL credentials |
| `JWT_SECRET` | **Long random string — generate with:** `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `ALLOWED_ORIGINS` | Comma-separated frontend URLs, e.g. `https://portal.yourdomain.com` |

### Frontend API URL
Edit `client/assets/js/config.js` — in production the `CONFIG.API_BASE` auto-detects `window.location.origin + '/api'` when not on localhost. If your frontend and backend are on different domains, hardcode it there.

### Serve with PM2 (recommended)
```bash
npm install -g pm2
pm2 start server/server.js --name dzine-portal
pm2 save
pm2 startup
```

---

## API Overview

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | Register new client |
| POST | `/api/auth/login` | — | Login (returns JWT) |
| GET | `/api/auth/me` | JWT | Current user info |
| GET | `/api/projects` | JWT | List projects |
| GET | `/api/projects/:id/stages` | JWT | Project stage status |
| POST | `/api/questionnaire/:id` | JWT | Save questionnaire draft |
| POST | `/api/questionnaire/:id/submit` | JWT | Submit questionnaire |
| GET | `/api/admin/users` | Admin JWT | List all clients |
| POST | `/api/admin/users` | Admin JWT | Create client |
| PUT | `/api/admin/users/:id` | Admin JWT | Update client |
| DELETE | `/api/admin/users/:id` | Admin JWT | Delete client |
| POST | `/api/admin/projects` | Admin JWT | Create project for client |

---

## Resetting Admin Password (SQL)
```sql
-- Generate hash first: node -e "require('bcryptjs').hash('NEW_PASSWORD', 12).then(console.log)"
UPDATE users SET password_hash = 'PASTE_HASH_HERE' WHERE email = 'admin@dzine.com';
```
