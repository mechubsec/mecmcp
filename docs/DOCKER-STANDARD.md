# Docker documentation standard for mechub MCP servers

**Part of [#6](https://github.com/mechubsec/mecmcp/issues/6).**

## Problem

Both servers ship Docker images, but their documentation has gaps that cause first-run failures:

### 1. Bind-mount ownership — the most common first-run failure

Both servers run as uid **65532** and refuse a group- or world-readable token file. A bind mount carries the host uid straight through, so a `tokens.json` created by your own user fails and the container exits 1:

```
token file /etc/<svc>/tokens.json: Permission denied (os error 13)
```

- **rust-junosmcp** documents the `chown -R 65532:65532` requirement — but eight lines *above* the `docker run` example that needs it, not as a prerequisite of that command.
- **rust-panosmcp** does not mention ownership at all. Its README has zero occurrences of `chown` or `65532`.

**There is a subtler version:** chowning the **files** is not enough. `token add` writes atomically via a temp file in the same directory, so the **directory** must be writable too, or you get a confusing error naming a path you never chose:

```
Permission denied (os error 13) at path "/etc/<svc>/.tokens-KNnZkm.tmp"
```

Both READMEs should show `chown -R` on the directory, immediately adjacent to the command that requires it.

### 2. Undocumented required flags

rust-panosmcp requires `--allowed-origin` even for loopback testing; rust-junosmcp does not. Neither Docker section mentions it, so the documented `docker run` for panos fails verbatim if you try to connect from a browser-based MCP client.

### 3. `--audit-journald` does not work in Docker, and says so badly

There is no journald socket in a container. rust-panosmcp on distroless fails with:

```
No such file or directory
```

which names nothing useful. Neither README mentions that `--audit-journald` is systemd-only.

**In Docker the correct configuration is `--audit-format json` alone**, which emits audit events to stdout for the container runtime to collect. Verified working: an authenticated `tools/call` on junos in Docker produced a complete event with `request_id`, `caller`, `tool`, `action`, and `authorization`.

Worth stating explicitly in both READMEs, because the failure mode otherwise looks like "audit is broken in Docker" — which is not true.

The error itself should also name the cause: "journald socket unavailable — `--audit-journald` requires systemd; use `--audit-format json` in a container".

### 4. `.dockerignore` completeness

rust-junosmcp's `.dockerignore` excludes `target` but not `.claude/`, so agent worktrees under `.claude/worktrees/*/target/` are sent to the build context — tens of gigabytes, enough to make the build impractical. Every repo should exclude `.claude/` and any nested `target/`, and CI should assert the context size stays under a sane bound.

### 5. Unkeyed audit by default (#376 / MEC-978)

Every server's systemd unit runs keyed, redacted audit (`--audit-hmac-key-file` plus `--audit-redact`), and `packaging/lxc/install.sh` generates the key on first install if it is absent. Five of the six container images set neither flag at all, so the same binary run as a container emits unkeyed, unredacted audit by default — same binary, same version, two audit postures depending on how it was deployed.

The fix is `packaging/docker/audit-entrypoint.sh.tmpl` in the `mecmcp` repo: an `ENTRYPOINT` (exec form) that generates the key from `/dev/urandom` on first run if it is not already there, then always `exec`s the real binary with both flags plus `"$@"` — mirroring what the installer already does, so a container gets the same audit posture as an LXC install without an operator having to remember a flag. Put the key under the **state** volume, not config: the canonical compose example below mounts config `:ro`, so a key path under `/etc/<svc>` could never be generated on a fresh container.

`packaging/conformance`'s R7 rule (see that directory's README) statically checks the entrypoint script for exactly this shape — the flag, the generation step, and a final `exec ... "$@"` — once a repo declares `audit_entrypoint` in its `packaging/conformance.toml`. Until it does, R7 warns rather than fails, so this is a WARN in CI until each repo migrates, not yet a merge-blocker.

## Standard

### Docker README section structure

Every README has a **Docker** section documenting the complete first-run workflow. Example structure:

```markdown
## Docker

Prebuilt images are published to `ghcr.io/mechubsec/<reponame>` on every release tag.

### Prerequisites

- Docker 20.10+ or compatible runtime
- Host paths for config and state (see below)

### Prepare host directories

The container runs as uid/gid **65532:65532**. All mounted directories and files must be owned by that uid, and the **directories** must be writable for atomic temp-file operations.

```bash
mkdir -p config state
# Create initial config and token files
printf '%s\n' '{"version":1,"tokens":[]}' > state/tokens.json
cp devices.example.json config/devices.json

# The container process must own its mounts
sudo chown -R 65532:65532 config state
sudo chmod 0700 state           # state dir writable by service only
sudo chmod 0750 config          # config dir readable by service
sudo chmod 0600 state/tokens.json   # enforced by mecmcp-auth
sudo chmod 0640 config/devices.json
```

**Why the directory ownership matters:** `token add` and other management commands write atomically via a temp file in the same directory. If the directory is not writable by uid 65532, you will see:

```
Permission denied (os error 13) at path "/var/lib/<svc>/.tokens-KNnZkm.tmp"
```

### Run

```bash
docker run --rm -i \
  -p 127.0.0.1:30031:30031 \
  -v "$PWD/config:/etc/<binary>:ro" \
  -v "$PWD/state:/var/lib/<binary>" \
  ghcr.io/mechubsec/<reponame>:latest \
  --device-mapping /etc/<binary>/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 30031 \
  --tokens-file /var/lib/<binary>/tokens.json \
  --audit-format json
```

**Note:** `--audit-format json` (not `--audit-journald`) is the correct configuration in Docker. There is no journald socket in a container, so `--audit-journald` fails with `No such file or directory`. JSON format emits audit events to stdout for the container runtime to collect.

**Note:** the image's `ENTRYPOINT` also generates `/var/lib/<binary>/audit-hmac.key` on first run if it is not already in the `state` mount, and always runs the binary with `--audit-hmac-key-file` and `--audit-redact` — see [#376 / MEC-978](#5-unkeyed-audit-by-default-376--mec-978). Nothing above needs to change for this; it happens inside the container using the `state` volume already mounted.

### TLS

For production use with remote clients, add TLS:

```bash
# Generate or obtain a certificate (example using self-signed for testing)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout state/server.key \
  -out state/server.crt \
  -days 365 \
  -subj "/CN=<binary>.example.net"

sudo chown 65532:65532 state/server.key state/server.crt
sudo chmod 0600 state/server.key
sudo chmod 0644 state/server.crt

docker run --rm -i \
  -p 0.0.0.0:30031:30031 \
  -v "$PWD/config:/etc/<binary>:ro" \
  -v "$PWD/state:/var/lib/<binary>" \
  ghcr.io/mechubsec/<reponame>:latest \
  --device-mapping /etc/<binary>/devices.json \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 30031 \
  --tokens-file /var/lib/<binary>/tokens.json \
  --tls-cert /var/lib/<binary>/server.crt \
  --tls-key /var/lib/<binary>/server.key \
  --allowed-host <binary>.example.net \
  --allowed-origin https://client.example.net \
  --audit-format json
```

**`--allowed-origin` is required** for browser-based MCP clients (e.g., Claude Desktop, Zed). Without it, CORS preflight fails and the client cannot connect.

### Compose

`packaging/container/compose.example.yaml`:

```yaml
services:
  <binary>:
    image: ghcr.io/mechubsec/<reponame>:latest
    container_name: <binary>
    user: "65532:65532"
    read_only: true
    ports:
      - "127.0.0.1:30031:30031"
    volumes:
      - ./config:/etc/<binary>:ro
      - ./state:/var/lib/<binary>
    command:
      - --device-mapping
      - /etc/<binary>/devices.json
      - --transport
      - streamable-http
      - --host
      - 0.0.0.0
      - --port
      - "30031"
      - --tokens-file
      - /var/lib/<binary>/tokens.json
      - --audit-format
      - json
    restart: unless-stopped
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
```

**Key elements:**
- `read_only: true` — immutable root filesystem
- Explicit writable mounts only where needed (`/var/lib/<binary>`, `/tmp`)
- `cap_drop: ALL` — no Linux capabilities
- `user: "65532:65532"` — explicit non-root uid/gid

### Health check

**Distroless images have no shell**, so `HEALTHCHECK` cannot use common patterns like `curl` or `wget`. Use a process-alive check instead:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["kill", "-0", "1"]
```

This checks that PID 1 (the server process) is alive. It does not verify that the server is serving requests, but it catches crashes and OOM kills.

For servers that can accept shell-free health checks, an HTTP probe from the host is better:

```bash
# From the host
curl -f http://127.0.0.1:30031/health || exit 1
```

But this cannot be in the Dockerfile for distroless — put it in a monitoring script or orchestrator health check instead.

### Platform notes

**Apple Silicon (M-series) and other arm64 hosts:** Images are published for `linux/amd64` and `linux/arm64`, and Docker pulls the native one. No `--platform` flag is needed. Releases published before multi-arch support are amd64-only and need `--platform linux/amd64`.

### Building locally

```bash
docker build -t <binary>:local .
docker run --rm -i \
  -v "$PWD/config:/etc/<binary>:ro" \
  -v "$PWD/state:/var/lib/<binary>" \
  <binary>:local
```

The Dockerfile is at the repository root.
```

## Dockerfile requirements

Every repo ships a `Dockerfile` that:

1. **Uses distroless runtime** (`gcr.io/distroless/cc-debian13:nonroot`) unless the server spawns processes (see PACKAGING.md §1).

2. **Runs as uid/gid 65532:65532** explicitly:
   ```dockerfile
   USER 65532:65532
   ```

3. **Has no shell-based HEALTHCHECK.** Use `CMD ["kill", "-0", "1"]` or omit the healthcheck (let the orchestrator probe from outside).

4. **Copies only the binary and required runtime files** — no source, no `.git`, no `target/`.

5. **Sets WORKDIR and default CMD**:
   ```dockerfile
   WORKDIR /app
   CMD ["<binary>"]
   ```

6. **Declares standard volumes** (informational; bind mounts override):
   ```dockerfile
   VOLUME ["/etc/<binary>", "/var/lib/<binary>"]
   ```

## `.dockerignore` requirements

Every repo ships a `.dockerignore` that excludes:

```
# Build artifacts
target/
dist/
*.tar.gz
*.sha256

# Development and CI
.git/
.github/
.claude/
.worktrees/
.env
.env.*

# IDE and editor
.vscode/
.idea/
*.swp
*.swo
*~

# Docs and assets (if not needed in image)
docs/
README.md
CHANGELOG.md
LICENSE
*.md

# Test fixtures
tests/
fuzz/
benches/
```

**Why `.claude/` and `.worktrees/` matter:** Agent worktrees under `.claude/worktrees/*/target/` can be tens of GB. Without this exclusion, the Docker build context becomes impractically large.

**CI should assert context size.** Add a check to `.github/workflows/ci.yml`:

```yaml
- name: Check Docker build context size
  run: |
    CONTEXT_SIZE=$(docker build --no-cache --target=builder -q . 2>&1 \
      | grep -oP 'Sending build context.*\K[0-9.]+[KMGT]?B' || echo "0B")
    echo "Docker build context size: $CONTEXT_SIZE"
    # Fail if context is over 100MB (adjust threshold as needed)
    # This catches accidental inclusion of large directories
```

## Error messages for Docker-specific failures

### `--audit-journald` in a container

**Current:**
```
No such file or directory
```

**Should be:**
```
Error: journald socket unavailable

--audit-journald requires systemd and is not supported in Docker containers.
Use --audit-format json instead, which emits audit events to stdout for
the container runtime to collect.
```

### Permission denied on token file

**Current:**
```
token file /etc/<svc>/tokens.json: Permission denied (os error 13)
```

**Should add:**
```
token file /etc/<svc>/tokens.json: Permission denied (os error 13)

In Docker, bind-mounted files inherit the host uid/gid. The container runs as
uid 65532, so the mounted file or directory must be owned by that uid:

  sudo chown -R 65532:65532 /host/path/to/state
  sudo chmod 0700 /host/path/to/state
  sudo chmod 0600 /host/path/to/state/tokens.json
```

### Temp file creation failure

**Current:**
```
Permission denied (os error 13) at path "/etc/<svc>/.tokens-KNnZkm.tmp"
```

**Should add:**
```
Permission denied (os error 13) at path "/etc/<svc>/.tokens-KNnZkm.tmp"

Atomic writes require the parent directory to be writable. In Docker, ensure
the bind-mounted directory is owned by the container's uid (65532):

  sudo chown -R 65532:65532 /host/path/to/state
  sudo chmod 0700 /host/path/to/state
```

## Verification checklist for each repo

- [ ] README has a complete Docker section with all elements above
- [ ] Ownership requirements (`chown -R 65532:65532`) documented adjacent to the `docker run` command that needs them
- [ ] `--audit-format json` (not `--audit-journald`) is the documented audit config
- [ ] Container `ENTRYPOINT` generates the audit HMAC key under the state volume if absent and always passes `--audit-hmac-key-file`/`--audit-redact` (#376 / MEC-978); `packaging/conformance.toml` declares `audit_entrypoint` so R7 checks it
- [ ] `--allowed-origin` documented for browser-based clients (if applicable)
- [ ] `compose.example.yaml` includes `read_only: true`, `cap_drop: ALL`, explicit writable mounts
- [ ] `.dockerignore` excludes `.claude/`, `.worktrees/`, nested `target/`
- [ ] CI asserts Docker build context size under a sane bound
- [ ] HEALTHCHECK is shell-free (or omitted)
- [ ] Error messages for Docker-specific failures include remediation steps

## What each consumer repo must change

### RustJunosMCP

1. **Move ownership docs:** `chown -R 65532:65532` is currently 8 lines above the `docker run` that needs it. Move it immediately before the run command.

2. **Add note on directories:** Clarify that the **directory** must be writable, not just the files, with the temp-file error example.

3. **Document audit in Docker:** Add explicit note that `--audit-format json` is correct, `--audit-journald` fails.

4. **Add `.dockerignore` entries:** `.claude/`, `.worktrees/`

5. **CI context-size check:** Add assertion that build context < 100MB

6. **Health check:** Already correct (`CMD ["kill", "-0", "1"]`)

### rust-panosmcp

1. **Add ownership section:** Currently has zero mentions of `chown` or `65532`. Add complete ownership preparation before first `docker run`.

2. **Document `--allowed-origin`:** Required for browser clients; currently undocumented.

3. **Document audit in Docker:** `--audit-format json`, not `--audit-journald`.

4. **Add compose example:** `packaging/container/compose.example.yaml` with `read_only: true`, `cap_drop: ALL`.

5. **Add `.dockerignore` entries:** `.claude/`, `.worktrees/`

6. **CI context-size check**

7. **Error message improvements:** Add Docker-specific guidance to permission errors

### rustsdcmcp

Check current Docker documentation. If it has the same gaps, apply the same fixes.

### rustproxmoxmcp, rustunifimcp

Adopt the standard from the start. Use this document as the template for the Docker section.

## See also

- [PACKAGING.md](PACKAGING.md) — distroless requirement, process spawning constraints
- [FILESYSTEM-LAYOUT.md](FILESYSTEM-LAYOUT.md) — what lives in `/etc/<svc>` vs `/var/lib/<svc>`
- Issue #31 — specific failures this standard prevents
