# traforato
Prototyping sandboxes optimized for cold start.

## What This Project Is
Traforato is a Go prototype for short-lived sandbox lifecycle management.

It is split into:
1. `broker` (control plane): chooses a worker and redirects requests.
2. `worker` (data plane): owns sandbox state, execution, files, and warm-pool behavior.

If you want internals and schematics, go straight to [ARCHITECTURE.md](./ARCHITECTURE.md).

## Quick Start (Local)
Prerequisites:
1. Go `1.24+`
2. `curl`
3. `jq` (optional, used in examples)

Start broker + worker together:

```bash
go run ./cmd/dev
```

Default local endpoints:
1. Broker: `http://localhost:8080`
2. Worker: `http://localhost:8081`

## First Request Flow
Create a sandbox through the broker (it redirects to the worker):

```bash
SANDBOX_ID=$(
  curl -sS -L -X POST http://localhost:8080/sandboxes \
    -H 'content-type: application/json' \
    -d '{"image":"alpine:3.20","cpu":1}' \
  | jq -r '.sandbox_id'
)

echo "$SANDBOX_ID"
```

Run code in that sandbox:

```bash
curl -sS -L -X POST "http://localhost:8080/sandboxes/$SANDBOX_ID/exec/code" \
  -H 'content-type: application/json' \
  -d '{"runtime":"python","code":"print(\"hello from traforato\")"}'
```

Delete the sandbox:

```bash
curl -sS -L -X DELETE "http://localhost:8080/sandboxes/$SANDBOX_ID"
```

## Running Services Separately
Start broker:

```bash
go run ./cmd/broker
```

Start worker:

```bash
go run ./cmd/worker
```

Start worker with a YAML config:

```bash
go run ./cmd/worker --file ./worker.yaml
```

Minimal `worker.yaml` example:

```yaml
broker-id: broker_local
broker-control-url: http://localhost:8080
worker-id: worker_local
hostname: localhost
hardware-sku: cpu-standard
virtualization: vetu

total-cores: 8
total-memory-mib: 16384
max-live-sandboxes: 6
default-ttl: 30m
registration-heartbeat: 30s
registration-jitter-percent: 20
```

`cmd/dev` also accepts `--file` (or `TRAFORATO_DEV_WORKER_CONFIG`) and applies worker config values in local development.

## Auth Modes
| Mode | Condition | Behavior |
|---|---|---|
| `dev` | `TRAFORATO_JWT_SECRET` is empty | No JWT enforcement (local dev default). |
| `prod` | `TRAFORATO_JWT_SECRET` is set | JWT validation + ownership checks on worker APIs. |

Optional auth env vars:
1. `TRAFORATO_JWT_SECRET`
2. `TRAFORATO_JWT_ISSUER`
3. `TRAFORATO_JWT_AUDIENCE`

## API At A Glance
Main public routes:
1. `POST /sandboxes`
2. `GET /sandboxes/{sandbox_id}`
3. `PATCH /sandboxes/{sandbox_id}/lease`
4. `DELETE /sandboxes/{sandbox_id}`
5. `PUT|GET|DELETE /sandboxes/{sandbox_id}/files?path=...`
6. `GET /sandboxes/{sandbox_id}/files/stat?path=...`
7. `GET /sandboxes/{sandbox_id}/files/list?path=...`
8. `POST /sandboxes/{sandbox_id}/files/mkdir`
9. `POST /sandboxes/{sandbox_id}/exec`
10. `POST /sandboxes/{sandbox_id}/exec/code`
11. `GET /sandboxes/{sandbox_id}/exec/{exec_id}`
12. `GET /sandboxes/{sandbox_id}/exec/{exec_id}/frames`
13. `ANY /sandboxes/{sandbox_id}/proxy/{port}[/{path...}]`
14. `GET /sandboxes/{sandbox_id}/ports/{port}/url?protocol=http|https|ws|wss`

Full endpoint list, routing behavior, and internal control-plane APIs are documented in [ARCHITECTURE.md](./ARCHITECTURE.md).

## Releases
Tagging `vX.Y.Z` triggers release automation:
1. Goreleaser builds `traforato-broker` and `traforato-worker`.
2. Docker Buildx publishes multi-arch images to GHCR (`:vX.Y.Z` and `:latest`).

Dry-run release validation runs on PRs and non-tag pushes to `main`.

## Current Scope
This is a v1 prototype with:
1. In-memory state
2. Single active broker model
