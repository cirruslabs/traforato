# Traforetto v1 Spec (Auth/Routing Update + Warm Pool + Telemetry)

## Summary
1. Controller redirects by `sandbox_id` immediately, without JWT validation.
2. If global JWT secret is not configured, system runs in development no-auth mode (controller and worker both skip JWT checks).
3. Worker remains source of truth for sandbox ownership/auth in production mode.
4. Warm pool, CPU/image target scheduling, default `vetu`, and OpenTelemetry/slog coverage remain in scope.

## Routing and Redirect Rules
1. `sandbox_id` format: `sbx_<md5(lowercase(worker_hostname))>_<ulid>`.
2. Any request that includes `sandbox_id` (path param first, then query fallback) is treated as sandbox-scoped routing.
3. Controller behavior for sandbox-scoped routes:
   - Parse `sandbox_id`.
   - Resolve worker by hash.
   - Return `307` to worker immediately.
   - Do **not** validate JWT at controller for this request.
4. If `sandbox_id` is malformed: `400`.
5. If worker hash is unknown/stale: `404` (or `503` if worker temporarily unavailable).

## Authentication Modes
### Production mode
1. Enabled when global JWT secret is configured.
2. Controller validates JWT only for non-sandbox-id entrypoints (for example, create/placement endpoints).
3. Worker validates JWT on all data-plane operations.
4. Worker enforces ownership (`sandbox_id -> client_id`) from JWT claim.
5. Required claims: `client_id`, `iss`, `aud`, `exp`, `iat`, `jti`.
6. Replay guard: in-memory `jti` cache until token expiry.

### Development mode
1. Activated when global JWT secret is missing.
2. Controller and worker both skip JWT verification.
3. Ownership checks based on JWT are disabled.
4. Access control in dev mode is by sandbox ID possession only.
5. Dev mode must emit startup warning logs and a metric flag.

## API Surface
1. `POST /sandboxes` (primary create, non-websocket)
   - Body: `image`, `cpu`, `virtualization` (`default: vetu`), `ttl_seconds`.
   - Controller does placement and `307` to worker.
   - Worker returns `201` with `sandbox_id`, `expires_at`, `cpu`, `memory_mib`, `virtualization`.
2. `POST /sandboxes/{sandbox_id}/exec` -> `202` (`exec_id`)
3. `GET /sandboxes/{sandbox_id}/exec/{exec_id}`
4. `GET /sandboxes/{sandbox_id}/exec/{exec_id}/frames?cursor=&wait=`
5. `GET /sandboxes/{sandbox_id}/exec/ws?...` (optional websocket exec)
6. `PUT /sandboxes/{sandbox_id}/files?...`
7. `GET /sandboxes/{sandbox_id}`
8. `PATCH /sandboxes/{sandbox_id}/lease?...`
9. `DELETE /sandboxes/{sandbox_id}`

## Warm Pool and Capacity
1. Warm target key: `(virtualization, image, cpu)`.
2. Memory derivation:
   - `mib_per_cpu = floor(memory_mib_total / logical_cores_total)`.
   - `sandbox.memory_mib = cpu * mib_per_cpu`.
3. Hard caps:
   - CPU, memory, and live sandbox count limits enforced.
4. `max_live_sandboxes` defaults:
   - macOS: `2`
   - Linux: `logical_cores_total`
5. Warm readiness flow:
   - Provision VM -> SSH connect -> run warmup script (must exit `0`) -> close session -> open fresh readiness SSH session -> mark ready.
6. SSH drop:
   - Mark unavailable -> full rewarm cycle -> report newly ready.

## Warm Target Computation
1. Recompute events:
   - Worker register
   - Sandbox delete event
2. Demand model:
   - Last 60 minutes
   - Exponential decay, 20-minute half-life
3. Allocation:
   - Proportional floor/ceil
   - Guarantee 1 warm sandbox for hottest tuple when capacity allows
4. Controller response target fields:
   - `virtualization`, `image`, `cpu`, `target_count`, `warmup_script`, `warmup_timeout_seconds`

## WebSocket Frames
1. Orchard-compatible JSON frames:
   - `stdin`, `stdout`, `stderr`, `exit`, `error`
2. Direction:
   - Client -> worker: `stdin` only
   - Worker -> client: `stdout|stderr|exit|error`
3. Empty `stdin.data` means EOF.

## OpenTelemetry + slog
### Core metrics
1. Utilization:
   - `worker.cpu.total_cores`, `worker.cpu.allocated_cores`
   - `worker.memory.total_mib`, `worker.memory.allocated_mib`
   - `worker.sandboxes.live`, `worker.sandboxes.warm.ready`, `worker.sandboxes.warm.target`, `worker.sandboxes.warm.deficit`
2. Latency:
   - `worker.sandbox.ready.duration_seconds`
   - `worker.sandbox.first_exec.tti_seconds` (fresh sandbox: create request -> exec started)
   - `worker.exec.start.duration_seconds`
   - `worker.exec.duration_seconds`
   - `controller.placement.duration_seconds`
3. Reliability:
   - `controller.no_capacity.total`
   - `worker.warmup.failures.total`
   - `worker.ssh.reconnects.total`
   - `worker.warm.hit.total`, `worker.warm.miss.total`
   - `worker.auth.failures.total`
4. Auth mode metric:
   - `service.auth.mode` gauge (`prod=1/dev=0` or label-based variant)

### Labels
1. Low-cardinality only: `worker_id`, `virtualization`, `cpu`, `start_type`, `result`, `status_code`, `reason`, `image_family`.
2. Never label by `sandbox_id`, `exec_id`, raw `client_id`, full image ref.

### Tracing
1. ParentBased TraceIDRatio `0.10`.
2. Mandatory spans across placement, provisioning, warmup, exec start/run, upload.
3. Propagate W3C trace context controller->worker.

### Logging (`slog`, JSON)
1. Required fields: `request_id`, `trace_id`, `span_id`, `worker_id`, `sandbox_id`, `exec_id`, `auth_mode`.
2. Never log JWT/token/secrets.
3. On startup in dev mode, log explicit warning: auth disabled.

## Test Cases
1. Controller sandbox-id routes redirect without JWT parsing/validation.
2. Non-sandbox-id entrypoints still validate JWT in production mode.
3. Missing JWT secret switches both controller and worker to dev no-auth mode.
4. Dev mode allows operations without JWT; prod mode enforces JWT+ownership.
5. Warmup success/failure gating of readiness.
6. SSH reconnect triggers rewarm and re-report.
7. TTI metric emitted once per fresh sandbox.
8. Metric label lint rejects high-cardinality identifiers.

## Assumptions and Defaults
1. Default virtualization when omitted: `vetu`.
2. Sandbox-scoped controller requests always short-circuit to redirect.
3. JWT-less mode is explicitly development-only and non-production.
4. Controller remains single-active, in-memory for v1.

## Implementation Progress
1. [x] Initialize Go module and project structure.
2. [x] Implement `sandbox_id` parser/constructor (`sbx_<worker_hash>_<ulid>`).
3. [x] Implement auth mode switch (`prod` with JWT secret, `dev` without secret).
4. [x] Implement JWT validation with required claims and in-memory `jti` replay guard.
5. [x] Implement worker API surface and ownership enforcement.
6. [x] Implement controller routing/redirect semantics and placement.
7. [ ] Implement warm pool target computation and readiness lifecycle.
8. [ ] Implement telemetry/tracing/logging fields in handlers.
9. [ ] Add tests for the listed v1 routing/auth/warm/metric scenarios.
