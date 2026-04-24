# Kryon Dashboard

Web UI for the Kryon Autonomous Security Operations Platform. Built with
Next.js 16, React 19, Tailwind 4, shadcn/ui and TanStack Table.

## Quick start

### With the full stack (Docker)

From the repo root:

```bash
docker compose -f docker/docker-compose.kali.yml up -d dashboard
```

Then open <http://localhost:3000> and log in with one of the demo credentials:

- `admin@kryon.py` / `kryon2026`
- `demo@britimp.com.py` / `demo2026`

### Local development

```bash
cd dashboard
pnpm install
pnpm dev
```

The dashboard starts in **demo mode** with deterministic mock data when
`NEXT_PUBLIC_KRYON_API_URL` is unset — ideal for UI work. Copy `.env.example`
to `.env.local` and point `NEXT_PUBLIC_KRYON_API_URL` at a running FastAPI
backend to switch to live data.

## Architecture

- `src/app/` — Next.js App Router. The `(app)/` route group holds the
  authenticated shell (sidebar + topbar) and the six primary pages.
- `src/components/` — UI building blocks grouped by feature (`findings/`,
  `compliance/`, `overview/`, ...).
- `src/lib/` — data layer:
  - `lib/types.ts` — shared domain types.
  - `lib/api/` — typed FastAPI client with fetch wrapper and adapters.
  - `lib/data/` — facade that tries the real API and falls back to mocks
    on any failure. **Components always import from `data/`, never
    directly from `mocks/` or `api/`.**
  - `lib/mocks/` — deterministic fixtures used in demo mode.
- `src/proxy.ts` — route guard (Next.js 16 rename of `middleware.ts`).

## Environment variables

See [`.env.example`](./.env.example) for the complete list. The dashboard
ships with sane demo defaults so unset variables never break the UI.

| Variable | Purpose |
| --- | --- |
| `NEXT_PUBLIC_KRYON_API_URL` | FastAPI base URL. Empty = demo mode. |
| `NEXT_PUBLIC_KRYON_API_KEY` | Optional `X-API-Key` header value. |

## Production image

```bash
docker build -t kryon-dashboard -f dashboard/Dockerfile dashboard/
docker run --rm -p 3000:3000 \
  -e NEXT_PUBLIC_KRYON_API_URL=http://host.docker.internal:8000 \
  kryon-dashboard
```

The final image is ~180 MB thanks to Next.js `output: "standalone"`.
