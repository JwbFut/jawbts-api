# jawbts-api

Rework of [jawbts-api-next](https://github.com/JwbFut/jawbts-api-next).

Security-focused JSON API for GitHub login, short-lived RS256 JWTs,
single-use refresh tokens, delegated access tokens, confirmed email changes,
and email alerts for new login/refresh devices.

Built with Next.js 16 route handlers, Prisma 7 on PostgreSQL/Neon, `jose`,
Zod, and Resend. Authentication is bearer-only; there is **no registration** —
users must be provisioned in the database.

## Deploy

### Requirements

- Node.js **>= 22.5**
- PostgreSQL or Neon
- Vercel
- Cloudflare in front of the API (the app trusts `CF-Connecting-IP`)
- A GitHub OAuth app and a Resend account/API key

### 1. Install and configure

```bash
npm ci
cp .env.example .env
```

Set these environment variables in production:

| Variable | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | yes | PostgreSQL/Neon URL. `postgresql://` uses the WebSocket pool; `https://` uses the Neon HTTP transport (no transactions). |
| `DATABASE_SCHEMA` | yes | Dedicated PostgreSQL schema, e.g. `jawbts-api`. The CLI and runtime both use it. |
| `GITHUB_CLIENT_ID` | yes | GitHub OAuth app client ID. |
| `GITHUB_CLIENT_SECRET` | yes | GitHub OAuth app client secret. |
| `GITHUB_REDIRECT_URI` | yes | UI callback URL registered on the GitHub OAuth app. The UI forwards GitHub's `code` + `state` to `POST /auth/github/callback`. |
| `ACTIVITY_HASH_SALT` | yes | Deployment-wide salt for IP+UA fingerprints. Keep it stable. |
| `JWKS_ENCRYPTION_KEY` | yes | Encrypts JWKS private keys at rest. Keep it stable and backed up like a root secret. |
| `RESEND_API_KEY` | yes | Required for login/refresh alerts and email-change notices. |
| `RESEND_FROM` | no | Verified Resend sender. Defaults to `Api Bot <api-bot@noreply.jawbts.org>`. |
| `JWKS_ORIGIN` | yes in production | Public API origin used for remote JWKS verification; without it production refuses the Host-header fallback. |

Generate the two required secrets once and keep them stable:

```bash
node -e 'const c=require("node:crypto"); for (const k of ["ACTIVITY_HASH_SALT","JWKS_ENCRYPTION_KEY"]) console.log(`${k}="${c.randomBytes(48).toString("base64url")}"`);'
```

Do not put `NEON_HTTP_ENDPOINT` in production. It is only for the local
Prisma Dev bridge; localhost values are ignored when `NODE_ENV=production`.

Local `.env*` files are git/vercel-ignored and must not be uploaded. If this
working tree has been shared or backed up, rotate the database password and the
GitHub/Resend secrets.

### 2. Create the database schema

Run this once against the production database, before deploying code that uses
the new tables:

```bash
DATABASE_URL='postgresql://...' \
DATABASE_SCHEMA='jawbts-api' \
npm run db:push
```

`db:push` creates all tables, including `jwks_lock`; JWKS rotation fails
without it. It also creates the case-insensitive `lower(email)` unique index
(Prisma cannot express that in `schema.prisma`). If existing rows contain
`a@x.com`/`A@x.com` duplicates, resolve them and rerun `npm run db:index`.

There are no Prisma migration files in this repository, so use `db:push`, not
`db:deploy`.

Do **not** run `npm run db:seed` against production. It uses
`--accept-data-loss` and creates a known test account.

### 3. Create the first user

There is no registration and no user-management endpoint. Insert the account
directly; `name` must be the GitHub username and `githubId` the GitHub numeric
ID (as text):

```sql
INSERT INTO "jawbts-api"."users"
  ("email", "name", "githubId", "permissions", "updatedAt")
VALUES
  ('you@example.com', 'your-github-username', '12345678',
   ARRAY['issue_tokens'], NOW());
```

Add `play_sequence_override` to `permissions` if that permission is needed.
Replace the quoted schema if `DATABASE_SCHEMA` differs.

### 4. Deploy to Vercel

1. Import the repository into Vercel and add the environment variables above
   to the **Production** environment.
2. Use the default build command (`npm run build`); `postinstall` generates the
   Prisma client.
3. Deploy.
4. `vercel.json` schedules a daily Vercel cron at **10:00 UTC**:

   ```json
   {
     "crons": [
       { "path": "/.well-known/jwks.json", "schedule": "0 10 * * *" }
     ]
   }
   ```

   It calls the existing public JWKS route, so the lazy key-rotation check runs
   even on days with no user traffic. No cron endpoint or cron secret is used.
5. Put Cloudflare in front of the deployment, keep the origin firewalled, and
   ensure `CF-Connecting-IP` reaches the app.
6. Verify:

   ```bash
   curl https://your-api.example.com/.well-known/jwks.json
   ```

   Then complete one GitHub login and one refresh.

### Local development

Use a development-only `.env` and a local PostgreSQL/Neon connection. The
Prisma Dev bridge setup, seed account, and `NEON_HTTP_ENDPOINT` example are
documented in `.env.example` and `scripts/`; never copy those local values into
production.
