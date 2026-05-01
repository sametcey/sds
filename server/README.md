# Streakify Auth Server

Production domain:

```text
https://api.streakify.tr
```

## Environment

Copy `production.env.example` to `.env` on the server and fill the secret values.

Required values:

```text
AUTH_PORT=4000
AUTH_PUBLIC_BASE_URL=https://api.streakify.tr
AUTH_DATA_DIR=/data
AUTH_JWT_SECRET=long-random-secret
SMTP_HOST=smtp.resend.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=resend
SMTP_PASS=resend-api-key
SMTP_FROM=Streakify <no-reply@streakify.tr>
```

## Health check

```text
https://api.streakify.tr/health
```
