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
  Controller -->|307 redirect| Worker["Worker"]
  Worker --> Warm["Warm Pool Manager"]
  Controller --> Telemetry["Telemetry Recorder"]
  Worker --> Telemetry
  Worker --> State["In-Memory Sandbox State"]
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

## Current Scope
This is a v1 prototype with in-memory state and a single active controller model.
