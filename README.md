# traforetto
Prototyping sandboxes optimized for cold start.

## Overview
Traforetto is a Go prototype for routing and lifecycle management of short-lived sandboxes.
It separates control-plane routing from worker data-plane execution, with warm-pool scheduling and built-in telemetry.

Core goals:
1. Fast sandbox placement and redirect routing by `sandbox_id`.
2. Production JWT auth with ownership enforcement, plus explicit dev no-auth mode.
3. Warm pool management keyed by workload tuple `(virtualization, image, cpu)`.
4. Low-cardinality metrics, traces, and structured logs.

## Architecture
```mermaid
flowchart LR
  Client["Client"] --> Controller["Controller"]
  Controller -->|307 redirect| WorkerA["Worker A"]
  Controller -->|307 redirect| WorkerB["Worker B"]
  Controller -->|307 redirect| WorkerN["Worker N"]
  WorkerA --> WarmA["Warm Pool Manager"]
  WorkerA --> StateA["In-Memory Sandbox State"]
  WorkerB --> WarmB["Warm Pool Manager"]
  WorkerB --> StateB["In-Memory Sandbox State"]
  WorkerN --> WarmN["Warm Pool Manager"]
  WorkerN --> StateN["In-Memory Sandbox State"]
```

## Request Routing
```mermaid
sequenceDiagram
  participant C as Client
  participant CT as Controller
  participant W as Worker

  C->>CT: POST /sandboxes
  Note over CT: Prod mode: validate JWT<br/>Dev mode: no JWT checks
  CT-->>C: 307 Location: worker /sandboxes
  C->>W: POST /sandboxes
  Note over W: Enforce auth + ownership in prod
  W-->>C: 201 sandbox metadata

  C->>CT: /sandboxes/{sandbox_id}/...
  Note over CT: Parse sandbox_id and worker hash<br/>No JWT validation on sandbox-scoped routing
  CT-->>C: 307 to owning worker
  C->>W: Follow redirect and execute operation
```

## API Surface (v1)
1. `POST /sandboxes`
2. `GET /sandboxes/{sandbox_id}`
3. `PATCH /sandboxes/{sandbox_id}/lease`
4. `DELETE /sandboxes/{sandbox_id}`
5. `PUT /sandboxes/{sandbox_id}/files`
6. `POST /sandboxes/{sandbox_id}/exec`
7. `GET /sandboxes/{sandbox_id}/exec/{exec_id}`
8. `GET /sandboxes/{sandbox_id}/exec/{exec_id}/frames`
9. `GET /sandboxes/{sandbox_id}/exec/ws` (optional, currently not enabled)

`POST /sandboxes` accepts optional `hardware_sku` to target placement to workers with that SKU.

`sandbox_id` format:
`sbx_<md5(lowercase(worker_hostname))>_<ulid>`

## Auth Modes
| Mode | Condition | Behavior |
|---|---|---|
| `prod` | JWT secret configured | Controller validates non-sandbox entrypoints; worker validates JWT and enforces ownership. |
| `dev` | JWT secret missing | Controller and worker skip JWT checks; startup warning and auth-mode metric emitted. |

Required JWT claims in production: `client_id`, `iss`, `aud`, `exp`, `iat`, `jti`.
Replay protection: in-memory `jti` cache until token expiry.

## Warm Pool and Capacity
```mermaid
flowchart TD
  Demand["Recent demand (60m, exponential decay)"] --> Target["Target warm count per tuple"]
  Target --> Allocate["Allocate capacity (cpu, memory, live sandbox caps)"]
  Allocate --> HitMiss{"Warm instance ready?"}
  HitMiss -->|Yes| Hit["Warm hit"]
  HitMiss -->|No| Miss["Provision and warmup"]
  Miss --> Ready["SSH readiness check then mark ready"]
```

Defaults:
1. `virtualization` defaults to `vetu`.
2. `max_live_sandboxes` defaults to `2` on macOS, `logical_cores_total` on Linux.
3. Memory per sandbox is derived from total memory and requested CPU.

## Telemetry and Logging
Metrics include utilization, latency, reliability, and `service.auth.mode`.
Tracing uses W3C context propagation across controller and worker boundaries.
Structured logs (`slog` JSON) include request/trace/span identifiers and avoid secrets.

Label policy is strict: only low-cardinality labels are allowed, and keys like `sandbox_id`, `exec_id`, and raw `client_id` are rejected.

## Running Services
Start a worker:

```bash
go run ./cmd/worker
```

Or with a YAML config file:

```bash
go run ./cmd/worker --file ./worker.yaml
```

Example `worker.yaml`:

```yaml
worker-id: worker-local
hostname: localhost
hardware-sku: cpu-standard
virtualization: vetu

total-cores: 8
total-memory-mib: 16384
max-live-sandboxes: 6
default-ttl: 30m

log:
  level: info
  file: /var/log/traforetto/worker.log
  rotate-size: 100 MB
  max-rotations: 10

pre-pull:
  images:
    - ghcr.io/cirruslabs/ubuntu-runner-amd64:24.04
    - alpine:3.20
```

YAML parsing is strict (unknown keys fail fast). For overlapping values, the YAML file overrides flag and environment defaults.

Start a controller (defaults to one worker at `http://localhost:8081`):

```bash
go run ./cmd/controller
```

Optional static worker registration fields on controller include `--worker-hardware-sku` (or `TRAFORETTO_CONTROLLER_WORKER_HARDWARE_SKU`).

Start both controller and worker for local development:

```bash
go run ./cmd/dev
```

`cmd/dev` also accepts the same worker config file via `--file` (or `TRAFORETTO_DEV_WORKER_CONFIG`) and applies it to worker runtime settings, logging, hardware SKU registration, and pre-pull images.

By default, all commands run in `dev` no-auth mode (empty `TRAFORETTO_JWT_SECRET`).
Set `TRAFORETTO_JWT_SECRET` (and optionally `TRAFORETTO_JWT_ISSUER`, `TRAFORETTO_JWT_AUDIENCE`) to enable `prod` JWT validation mode.

## Current Scope
This is a v1 prototype with in-memory state and a single active controller model.
