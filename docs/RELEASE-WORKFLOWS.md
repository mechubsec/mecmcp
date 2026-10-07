# Shared release workflows

**Part of [#417](https://github.com/mechubsec/mecmcp/issues/417).**

## Problem

SBOM generation, cosign signing, and SHA-pinning for GitHub Actions steps
were being re-implemented per consumer repo instead of defined once. A grep
across the fleet's `release-image.yml` files at the time this was written
turned up three different pins (or no pin at all) for the same
`docker/build-push-action` release:

```
rustjunosmcp:    docker/build-push-action@v7                                          # unpinned
rustpanosmcp:    docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a     # v7
rustunifimcp:    docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc     # v7
```

and two different SBOM strategies entirely: `cargo-cyclonedx` in one repo,
Docker Buildx's built-in `sbom: true` attestation in another, cosign signing
in one, no signing at all in another. Every repo re-deriving its own answer
to "what SHA does this action pin to" and "do we sign this artifact" is the
Conway's Law failure mode this issue exists to close — see
[RELEASE-ARTIFACTS.md](RELEASE-ARTIFACTS.md) for the equivalent standard on
tarball artifact shape.

## What this repo provides

Two reusable workflows (`workflow_call`), both under
`.github/workflows/` in `mecmcp`:

- **`reusable-release-image.yml`** — SBOM (CycloneDX via `cargo-cyclonedx`,
  plus a buildx-attested SBOM/provenance pair on the image itself), Docker
  Buildx build + push to GHCR (and, opt-in, Docker Hub — MEC-2110), keyless
  cosign signing of the pushed digest on every registry it was pushed to.
  Mirrors rustjunosmcp's `release-image.yml` (MEC-49), which is the
  reference this was extracted from.
- **`reusable-sign-release-tarball.yml`** — keyless cosign `sign-blob` of a
  release asset (tarball) already uploaded to a published GitHub release,
  with the signature bundle uploaded back onto the release. Mirrors
  rustjunosmcp's `release-sign-tarball.yml`.

Both pin every third-party action to a commit SHA. The SHAs used are the
ones already validated in production by rustpanosmcp, rustunifimcp,
rustmistmcp, and rustproxmoxmcp — not newly guessed pins.

Consumer repos keep their own trigger (`on: push: tags:`, `on:
workflow_dispatch`, `on: release: published`) and call the shared job with
`uses: mechubsec/mecmcp/.github/workflows/reusable-release-image.yml@<mecmcp-ref>`.
Pin `<mecmcp-ref>` to a released mecmcp tag, the same way consumer repos
already pin their `mecmcp` crate dependency — a floating `@main` reference
would let an unreviewed mecmcp change silently alter every consumer's
release pipeline.

## How to call it

### Image release

```yaml
name: Release image

on:
  push:
    tags:
      - 'v[0-9]+.[0-9]+.[0-9]+'
  workflow_dispatch:
    inputs:
      version:
        required: true
      ref:
        required: false
        default: ''

jobs:
  release:
    permissions:
      contents: read
      packages: write
      id-token: write
    uses: mechubsec/mecmcp/.github/workflows/reusable-release-image.yml@v0.8.1
    with:
      image: ghcr.io/mechubsec/rust-junosmcp
      dockerhub-image: docker.io/mechubsec/rust-junosmcp
      description: 'Junos/SRX MCP server'
      version: ${{ github.event.inputs.version }}
      ref: ${{ github.event.inputs.ref }}
      smoke-test-command: ./packaging/tests/container-scp-smoke.sh
    secrets: inherit
```

`permissions:` on the calling job is required — a reusable workflow's
effective permissions can only be narrowed by the caller, never widened, so
the caller must grant `packages: write` and `id-token: write` itself.

### Dual-push to Docker Hub (MEC-2110)

`dockerhub-image` is opt-in and empty by default, so adding the pin bump
alone changes nothing. A repo that wants the Docker Hub push too must also:

- Add `dockerhub-image: docker.io/mechubsec/<repo>` (same tags as GHCR:
  `vX.Y.Z`, `X.Y`, `latest`).
- Add `secrets: inherit` to the calling job (or map
  `dockerhub-username`/`dockerhub-token` explicitly) — the org-level
  `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` secrets this depends on are set up
  once, org-wide, not per repo.
- Optionally set `description` for the Docker Hub repo overview, and
  `dockerhub-readme` if the repo's README isn't at the root.

If `dockerhub-image` is set but the Docker Hub secrets are not visible to
the run (a fork with no access to org secrets, or before the org secrets
exist), the job logs a warning and continues with a GHCR-only push instead
of failing. Cosign signing, the buildx SBOM/provenance attestations, and
the image tags are identical on both registries when both are pushed.

### Tarball signing

```yaml
name: Sign release tarball

on:
  release:
    types: [published]

jobs:
  sign:
    permissions:
      contents: write
      id-token: write
    uses: mechubsec/mecmcp/.github/workflows/reusable-sign-release-tarball.yml@v0.8.1
```

## Reference migration: rustjunosmcp

`rustjunosmcp`'s `release-image.yml` and `release-sign-tarball.yml` now call
these two reusable workflows instead of carrying their own copies of the
SBOM/build/sign steps. The behavior is unchanged: same SBOM tool, same
image tags, same keyless cosign signing of the digest, same tarball
signature-bundle upload. Only the step definitions moved.

## Migrating another repo

1. Confirm which pattern the repo currently uses (image release, tarball
   release, or both — `rustpanosmcp`, `rustsdcmcp`, `rustmistmcp`,
   `rustproxmoxmcp` all ship images; consult each repo's own packaging docs
   for whether it also ships a signed tarball).
2. Replace the repo's own SBOM/build-push/sign or sign-blob steps with a
   `uses:` call to the matching reusable workflow above, pinned to a mecmcp
   release tag.
3. If the repo needs multi-arch (`docker/setup-qemu-action`), pass a
   `platforms` input containing a non-`amd64` platform — the reusable
   workflow only runs the QEMU setup step when needed, so single-arch
   callers do not pay for it.
4. If the repo runs a smoke test between Buildx setup and the GHCR push
   (as rustjunosmcp does), pass it via `smoke-test-command`.
5. Run the workflow once via `workflow_dispatch` (image) or against a real
   published release (tarball) before relying on it for a tagged release,
   and confirm the produced image/tarball is signed and the SBOM artifact is
   attached — same as before the migration.
6. Delete the repo's now-unused local copy of the steps.

## See also

- [RELEASE-ARTIFACTS.md](RELEASE-ARTIFACTS.md) — the tarball artifact
  naming, layout, and SBOM standard these workflows help enforce.
- `.github/workflows/security.yml` in this repo — mecmcp's own SBOM
  generation and validation job (MEC-460), which validates the *shape* of
  each workspace crate's SBOM rather than producing a release-image SBOM
  (mecmcp ships as a family of library crates, not a binary or image).
