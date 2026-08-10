# Totem

> A tiny self-hosted TOTP authenticator.

Totem is a small, single-user web authenticator for a private server. The Rust backend stores TOTP secrets encrypted in SQLite, calculates codes server-side, and streams complete snapshots to every open browser over SSE. The React interface works on desktop and mobile browsers.

The UI is intentionally focused on authenticator entries only. Totem is not a password manager, identity platform, or multi-user vault.

## What is included

- Rust, Axum, Tokio, rusqlite, and SQLite with WAL mode.
- Argon2id password hashing and server-side sessions in an HttpOnly cookie.
- XChaCha20-Poly1305 encryption with a unique nonce for every stored secret.
- RFC 6238 TOTP using SHA1, SHA256, or SHA512; 6/8 digits; custom periods.
- REST CRUD endpoints plus an SSE stream that refreshes on period boundaries and CRUD changes.
- Responsive React + TypeScript + Vite UI with system dark mode.
- otpauth URI paste, QR image/camera scanning, QR screenshot paste with Ctrl+V/Cmd+V, search, copy, show-secret, export, and import.
- A single production binary containing the built frontend.

## Project layout

```text
totem/
├── backend/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── api.rs
│       ├── auth.rs
│       ├── config.rs
│       ├── crypto.rs
│       ├── db.rs
│       ├── static_files.rs
│       └── totp.rs
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── deploy/
│   ├── Caddyfile
│   ├── nginx.conf
│   └── totem.service
└── README.md
```

The main page at `/` is the authenticator list. `/login` is handled by the same small React app and shows the password screen when the session is absent. Import/export is available under the Settings button.

## First run

Requirements: Rust 1.88+, Cargo, Node.js 22+, npm, and OpenSSL for generating the master key.

```bash
cp .env.example .env
openssl rand -hex 32
```

Put the generated 64-character value in `MASTER_KEY`, and choose a strong `ADMIN_PASSWORD`. On the first start Totem hashes that password with Argon2id and stores only the hash in SQLite. Once the database has been initialized, `ADMIN_PASSWORD` can be removed from `.env`.

Development mode uses Vite for the frontend and Axum for the API:

```bash
cd frontend
npm install
npm run dev
```

In a second terminal:

```bash
cargo run --manifest-path backend/Cargo.toml
```

Open <http://127.0.0.1:5173>. Vite proxies `/api` and `/health` to the Rust server at `127.0.0.1:8080`.

## Production build

Build the frontend first so its files are embedded into the Rust binary:

```bash
cd frontend
npm install
npm run build

cd ../backend
cargo build --release
```

The binary is `backend/target/release/totem`. A simple deployment directory is:

```text
/usr/local/totem/
├── totem
├── totem.db
└── .env
```

Run it directly with `./totem`, or install `deploy/totem.service` as a systemd unit. Totem listens on `127.0.0.1:8080` by default; terminate HTTPS in Nginx or Caddy.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind host |
| `PORT` | `8080` | Bind port |
| `DATABASE_PATH` | `./totem.db` | SQLite database path |
| `ADMIN_PASSWORD` | — | First-run password only |
| `MASTER_KEY` | — | Exactly 32 random bytes encoded as 64 hex characters |
| `COOKIE_SECURE` | `false` | Add the Secure cookie flag; set `true` behind HTTPS |
| `SESSION_TTL_HOURS` | `168` | Server-side session lifetime |
| `RUST_LOG` | `info` | `tracing` filter |

`MASTER_KEY` is essential: if it is lost, the encrypted secrets in `totem.db` cannot be recovered. Back up the database and key, but keep them in separate secure locations. Totem never logs `MASTER_KEY`, `ADMIN_PASSWORD`, secrets, otpauth URIs, or complete codes.

## Password reset

The database is not overwritten on normal startup. To replace the administrator password, stop the running service and run:

```bash
./totem reset-password
```

The command prompts for the new password twice and does not require `MASTER_KEY`.

## Reverse proxy

The SSE endpoint must not be buffered. An Nginx example is in [`deploy/nginx.conf`](./deploy/nginx.conf): the important directives are `proxy_buffering off`, `proxy_cache off`, an HTTP/1.1 proxy, and a long read timeout. The Caddy example in [`deploy/Caddyfile`](./deploy/Caddyfile) uses `flush_interval -1`.

Totem itself does not issue certificates. Set `COOKIE_SECURE=true` when the public URL is HTTPS.

## Backup and restore

Do not copy an active SQLite file with a plain `cp`. Use SQLite's online backup while Totem is running:

```bash
sqlite3 /usr/local/totem/totem.db ".backup '/secure/backups/totem-$(date +%F).db'"
```

Alternatively, Settings → Export downloads a logical JSON export containing plaintext secrets. Treat it like a key file. For a file-level restore, stop Totem, replace `totem.db` with a verified backup, restore the matching `MASTER_KEY`, and start Totem again. The JSON export can be imported into a running instance when you want to merge entries instead.

## Security notes

- Secrets are decrypted only on the server to calculate a code or fulfill an explicit Show Secret, URI, or export request. Normal entry lists contain codes but not secrets.
- QR screenshots are handled only in the Add TOTP dialog. Totem processes the image from the user-triggered paste/drop event locally in the browser; it does not call `navigator.clipboard.read()`, upload the image, or persist it.
- Session tokens are random and only their SHA-256 hashes are stored in SQLite. Cookies are HttpOnly, SameSite=Lax, Path=/, and optionally Secure.
- State-changing requests require the same-origin `X-Totem-Request: 1` header in addition to the SameSite cookie. This is a small CSRF defense suitable for the same-origin JSON API; no permissive CORS middleware is enabled.
- Login attempts are limited to five per client key per minute in process memory. With a reverse proxy, configure it to pass `X-Real-IP` or `X-Forwarded-For` as shown in the examples.
- API responses are `no-store`; the app sets CSP, `X-Content-Type-Options`, `X-Frame-Options`, and a strict Referrer-Policy.
- SQLite enables WAL mode, foreign keys, and a busy timeout. The app uses one connection because the expected scale is one user and a small number of browsers.

## API overview

```text
GET    /health
POST   /api/login
POST   /api/logout
GET    /api/session
GET    /api/entries
POST   /api/entries
PUT    /api/entries/:id
DELETE /api/entries/:id
GET    /api/entries/:id/secret
GET    /api/entries/:id/uri
GET    /api/totp/stream
GET    /api/export
POST   /api/import
```

The SSE stream sends a complete JSON array immediately after connecting and again when a TOTP period changes or an entry is created, edited, deleted, or imported. It sends a comment heartbeat every 20 seconds; browsers automatically reconnect EventSource when the connection is interrupted.

## Checks

```bash
cargo fmt --manifest-path backend/Cargo.toml --check
cargo test --manifest-path backend/Cargo.toml
cargo clippy --manifest-path backend/Cargo.toml --all-targets -- -D warnings
cd frontend && npm run build
```
