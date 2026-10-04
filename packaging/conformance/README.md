# mecmcp package conformance

A shared static check for the mecmcp-family packages. One manifest per repo
describes where the package puts things; the rules below are the same
everywhere, so a defect fixed in one repo cannot quietly return in another.

**This proves nothing about runtime enforcement.** `SystemCallFilter`,
`ProtectSystem=strict` and `SystemCallErrorNumber` are inert until a real
systemd PID 1 on the real guest applies them. A green run here means the package
is shaped correctly, not that the seccomp posture works.

## Using it from another repo

```yaml
  conformance:
    name: Package conformance
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@<pinned-sha>

      - name: Build the binary
        run: cargo build --release --locked

      - name: Stage the package
        run: |
          mkdir -p staging/bin
          cp target/release/<binary> staging/bin/
          cp -r packaging staging/packaging
          cp packaging/conformance.toml staging/

      - name: Build the image          # only needed for R6
        run: docker build -t <image>:conformance .

      - uses: mechubsec/mecmcp/packaging/conformance@<pinned-sha>
        with:
          staging: staging
          manifest: staging/conformance.toml
          image: <image>:conformance    # omit and R6 does not run
          # prebuilt: 'true'            # see R3 clause 3
          # overrides: '--host 0.0.0.0' # the operator arguments R6 replays
```

Or call the scripts directly:

```bash
bash packaging/conformance/verify-package.sh --staging staging \
     --manifest staging/conformance.toml [--prebuilt]
bash packaging/conformance/verify-image.sh --image <tag> \
     --manifest staging/conformance.toml [--override --host --override 0.0.0.0]
```

`FAIL[Rn]` sets the exit code; `WARN[Rn]` never does. All violations are
collected before exiting, so one failure does not hide the rest. Exit 2 means
the manifest or the arguments were wrong and no rule ran.

## The manifest: `packaging/conformance.toml`

Unknown keys are an error, so a typo cannot silently disable a rule.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `binary` | string | yes | Path to the binary **inside** the staging dir. Must be relative. |
| `installer` | string | yes | Path to the install script **inside** the staging dir. Must be relative. |
| `service` | string | yes | systemd service name, without `.service`. |
| `config_dir` | string | yes | Config directory **on the target**. Absolute. |
| `tokens` | string | yes | Token file path **on the target**. Absolute. |
| `build_info` | bool | yes | `true` makes R3 fatal; `false` makes it warn. It never exempts a package from provenance. |
| `units` | list of strings | yes | Unit files **inside** the staging dir. May be empty; the empty case is announced. |
| `must_survive_override` | list of strings | yes | Flags R6 requires to survive an operator override. May be empty; the empty case is announced. |
| `skip_build_env` | `false` or a non-empty string | no | Names the environment variable the packager honours to accept a prebuilt binary. |
| `placeholders` | table of string → string | no | Test values for the `@TOKEN@` placeholders the units carry. |
| `audit_entrypoint` | `false` or a non-empty string | no | Path **inside the staging dir** to the container's audit-key-generating entrypoint script (see `packaging/docker/audit-entrypoint.sh.tmpl`). `false` means this repo's container image has not been migrated yet. |
| `audit_hmac_flag` | `false` or `"--audit-hmac-key-file"` | no | Declares that a **distroless, no-shell** image's `ENTRYPOINT` always passes `--audit-hmac-key-file` to a binary that generates its own key. The only accepted non-`false` value is that exact flag. Mutually exclusive with `audit_entrypoint`, and must also appear in `must_survive_override`. |

Rejected values, each with exit 2:

- `skip_build_env = true` and `skip_build_env = ""`. `true` is truthy, so it
  satisfied the `build_info` ordering guard while naming no variable — and a
  variable that names nothing is what silently disabled R3's third clause.
- `audit_entrypoint = true` and `audit_entrypoint = ""`, for the same reason:
  a bare `true` or empty string would satisfy "the key is present" while
  naming no script for R7 to actually check.
- `audit_hmac_flag = true` and `audit_hmac_flag = ""`, for the same reason.
  Also rejected: any value other than `"--audit-hmac-key-file"` (R7 has
  nothing left to check once the name is right other than R6 proving it
  reaches argv, so an unrecognized name would let R7 pass without verifying
  audit keying at all); setting it together with `audit_entrypoint` (a repo
  picks one migration path, not both); and naming a flag that is not also in
  `must_survive_override` (R7 relies on R6 to prove the flag reaches argv; a
  flag R6 never checks is a flag R7 cannot actually vouch for).
- An absolute `binary`, `installer`, or `units` entry. It would be joined onto
  the staging path anyway and report "not found" for a file that exists.
- Any string containing a newline. The reader emits one value per line and the
  caller assigns each line to a shell variable, so an embedded newline forges a
  second assignment. Placeholder tokens and values additionally reject tabs,
  because they are emitted as `TOKEN<TAB>VALUE`.
- `build_info = true` without `skip_build_env`. See **Provenance ordering**.

A minimal manifest that parses:

```toml
binary     = "bin/svc"
installer  = "packaging/lxc/install.sh"
service    = "svc"
config_dir = "/etc/svc"
tokens     = "/var/lib/svc/tokens.json"
build_info = false
units      = ["packaging/systemd/svc.service"]
must_survive_override = ["--tokens-file"]
```

(`audit_entrypoint` is omitted here since it is optional and defaults to
`false`, i.e. "not migrated yet, R7 warns".)

## The rules

| Rule | Status | What it checks |
|---|---|---|
| R1 | fatal | The installer exists at `installer` and is executable. |
| R2 | fatal | The binary exists at `binary` and is executable. |
| R3 | fatal if `build_info = true`, else warn | Provenance: a `BUILD-INFO` exists, records a `binary_sha256`, that hash matches the shipped binary, and (clause 3) does not name a toolchain that did not compile it. |
| R4 | warn | The installer creates `/etc/systemd/system/<service>.service.d`. Mentions inside comments do not count. |
| R5 | fatal | Every declared unit exists, renders with no `@PLACEHOLDER@` left, and `systemd-analyze verify` reports no defect. |
| R6 | fatal | Every `must_survive_override` flag is still in the container's argv after an operator override. Needs `--image`. |
| R7 | warn if neither `audit_entrypoint` nor `audit_hmac_flag` is set, else fatal | With `audit_entrypoint`: the declared entrypoint script exists, is executable, passes `--audit-hmac-key-file`, generates the key from `/dev/urandom` when absent, and ends in `exec ... "$@"`. With `audit_hmac_flag`: nothing further to check here -- the manifest reader already proved the flag is in `must_survive_override`, so R6 proves it reaches argv; the repo's own tests must cover key generation. |

### What can make a rule not run

A rule that does not run must never look like a rule that passed, so each of
these announces itself.

- **`units = []`** — R5 prints `note: units is empty; R5 has nothing to check`.
- **`must_survive_override = []`** — R6 prints
  `note: must_survive_override is empty; R6 has nothing to check`.
- **No `image` input** — the action prints that R6 did not run and how to
  enable it. If the manifest sets `audit_hmac_flag`, that note is itself a
  `FAIL[R7]`: R7's own verdict for that key is only a placeholder pass
  deferred entirely to R6 (see R7's row above), so skipping R6 while
  `audit_hmac_flag` is set means the fatal rule it names has verified
  nothing. Pass `image: <tag>` to actually verify it.
- **R3 clause 3 without `--prebuilt`** — when `build_info = true` and
  `skip_build_env` names a variable but the caller did not pass `--prebuilt`,
  R3 warns that clause 3 did not run. Pass `--prebuilt` (action input
  `prebuilt: 'true'`) from whichever CI path stages a binary it did not compile.
- **`build_info = false`** — R3 still reports, as a warning rather than a
  failure. There is no value that makes a package legitimately
  provenance-free.
- **`audit_entrypoint = false` and `audit_hmac_flag = false`** — R7 still
  reports, as a warning naming `#376`, rather than silently passing. This is
  the transitional state for a repo that has not migrated either way yet;
  setting either one to a real value promotes the same check to fatal.
- **An earlier rule already failed** — R1-R5 run in one step and R6 in another,
  and a failing step would normally skip everything after it. Both R6 steps
  therefore carry `!cancelled()`, so a package with a non-executable installer
  *and* a security flag stranded in `CMD` reports both in the same run. This is
  not cosmetic: before it was fixed, the implicit `success()` GitHub adds to a
  custom step `if:` skipped R6 **and** the note announcing that R6 had not run,
  so losing argv coverage looked exactly like passing.

### R5 and the uninstalled binary

`systemd-analyze verify` resolves `ExecStart=` against the local filesystem, and
every family unit names the **installed** path (`/usr/local/bin/<binary>`),
which by definition is not there when a package is checked before installation.
That one diagnostic class — `Command <path> is not executable:` — is filtered
out, and the number of suppressed lines is printed for each unit. Nothing else
is filtered: a unit with a genuine directive error still fails R5 even when its
command is also absent, which is what the `r5-bad-directive-uninstalled` fixture
exists to hold in place.

R5's verdict comes from the surviving output rather than from the exit status,
because `systemd-analyze verify` reports some genuine defects (a bad `Restart=`
value, for instance) and still exits 0.

### Provenance ordering

`build_info = true` requires `skip_build_env`. A repo with no supported way to
package a CI-built binary cannot produce an honest `BUILD-INFO`, and demanding
one anyway is what produced the forged file in #355. So the order is: add the
skip-build path, then set `skip_build_env` to its name, then set
`build_info = true`.

### Audit entrypoint rollout (R7)

Every family systemd unit runs keyed, redacted audit (`--audit-hmac-key-file`
plus `--audit-redact`), generating the key on first install if
`packaging/lxc/install.sh` does not find one. Five of six container images
did not do either half of that, so an operator running the same binary as a
container got unkeyed, unredacted audit by default (#376 / MEC-978).

`packaging/docker/audit-entrypoint.sh.tmpl` in this repo is the reference
fix: copy it into the vendor repo, fill in the three placeholders, wire it in
as `ENTRYPOINT` (exec form, so it is not lost the way `rustmistmcp#78`'s CMD
flag was), and declare its staging path as `audit_entrypoint` in that repo's
`packaging/conformance.toml`. R7 then checks the script itself rather than a
running container, because an entrypoint shim's `exec` line is invisible to
`docker inspect` — R6's own commentary calls this out as something it cannot
see. Until a repo does this, `audit_entrypoint = false` keeps R7 at a warning
so the gap stays visible without breaking every image's build in one commit.

**This script-based fix does not apply to a distroless image: there is no
shell to run the wrapper in.** All five vendor repos this rollout targets
ship distroless (`gcr.io/distroless/cc-debian*:nonroot`) runtime stages, so
none of them can ever set `audit_entrypoint` to a real path. Their fix
instead makes the binary itself generate `audit-hmac.key` on first run when
absent (the container-image equivalent of `packaging/lxc/install.sh`'s own
key-generation step) and bakes the flag directly into the Dockerfile's
`ENTRYPOINT` array. Declare that flag as `audit_hmac_flag` (and list it in
`must_survive_override`, since that is what lets R6 actually prove it reaches
the running container's argv) instead of `audit_entrypoint`.

## The tests

Three suites, all run by the `conformance` job in `.github/workflows/ci.yml`:

```bash
bash packaging/conformance/tests/test-read-manifest.sh   # the manifest reader
bash packaging/conformance/tests/run-fixtures.sh         # R1-R5 against fixtures
bash packaging/conformance/tests/test-verify-image.sh    # R6 against real images
```

Each fixture directory under `fixtures/` is a staging tree plus:

- `EXPECT` — the exact rule IDs that must **fail**, one per line. Required; may
  be empty.
- `EXPECT_WARN` — the exact rule IDs that must **warn**. Optional; a fixture
  without one asserts that no warning is emitted at all.
- `FLAGS` — extra arguments for `verify-package.sh`, e.g. `--prebuilt`.

Asserting warnings is what makes the warn-only rules real. Before `EXPECT_WARN`
existed, replacing the whole R4 block with `:` and making `warn()` a no-op both
left the suite green.
