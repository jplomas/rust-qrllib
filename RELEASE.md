# Releasing rust-qrllib

Versioning and releases are automated with [release-plz](https://release-plz.dev/),
driven by [Conventional Commit](https://www.conventionalcommits.org/) messages.
This document describes how a release is produced and published.

## TL;DR

1. Land Conventional Commits on `main`.
2. release-plz opens a **release PR** (`chore: release vX.Y.Z`) that bumps the
   version and updates `crates/qrllib/CHANGELOG.md`.
3. Review and merge it → the git tag `qrllib-vX.Y.Z` and the GitHub release are
   created automatically, with checksums, SBOMs, attestations, and SLSA provenance.
4. `qrllib` is published to crates.io; `qrllib-wasm` is published to npm as
   `@theqrl/qrllib-wasm` (it is never published to crates.io).

## 1. Conventional commits

We follow Conventional Commits. **They are not enforced by tooling** — please
write them correctly, because release-plz derives both the version bump and the
changelog from the commit history since the last tag.

Format: `<type>[optional scope][!]: <description>`

| Commit | Changelog section | Version effect while on `0.x` |
| --- | --- | --- |
| `fix: …` | Fixed | patch (`0.1.0` → `0.1.1`) |
| `feat: …` | Added | patch (`0.1.0` → `0.1.1`) |
| `feat!: …` or a `BREAKING CHANGE:` footer | Added, marked `[**breaking**]` | minor (`0.1.0` → `0.2.0`) |
| `chore:`, `docs:`, `ci:`, `refactor:`, `test:`, `perf:`, `build:`, `style:` | Other / omitted | none on their own |

After the crate reaches `1.0.0`, normal SemVer applies: `feat` → minor,
breaking → major.

A release PR is only opened when there are **releasing changes to the crate
itself** since the last tag. Commits that don't touch `crates/qrllib/` (e.g.
workflow-only `ci:` changes) won't trigger one. release-plz computes the next
version and shows it in the release PR — **always confirm the version and
changelog there before merging.**

## 2. How a version is bumped (release-plz)

Config: [`release-plz.toml`](release-plz.toml).

- `version_group = "workspace"` — `qrllib` and `qrllib-wasm` share **one version
  and one git tag** (`qrllib-vX.Y.Z`). They are bumped together.
- `release_always = false`, `semver_check = false`, `pr_labels = ["release"]`.

Flow:

1. Conventional commits merge to `main`.
2. The **`release-pr`** job in [`.github/workflows/release.yml`](.github/workflows/release.yml)
   runs release-plz, which opens/updates a PR titled `chore: release vX.Y.Z`
   bumping the version in `Cargo.toml` and updating `crates/qrllib/CHANGELOG.md`.
3. Review the PR (version, changelog), let CI pass, and merge it.
4. On merge, the **`release`** job tags `qrllib-vX.Y.Z` and creates the GitHub
   release. Dependent jobs then attach:
   - `checksums-sha256.txt` / `checksums-sha512.txt` / `source-checksums-sha256.txt`
   - SBOMs (`sbom-spdx.json`, `sbom-cyclonedx.json`)
   - GitHub build-provenance / SBOM attestations
   - SLSA provenance (`provenance.intoto.jsonl`)

**Gating.** Both jobs run only when the repo is `theQRL/rust-qrllib` **and** the
repository variable `RELEASE_ENABLED == 'true'`. Forks can't release. To run on
demand: Actions → **Release** → **Run workflow** (`workflow_dispatch`).

## 3. Publishing to crates.io (`qrllib`)

Controlled by the `publish` flag for the `qrllib` package in `release-plz.toml`:

- **`publish = true`** → the `release` job runs `cargo publish` automatically,
  using the `CARGO_REGISTRY_TOKEN` repository secret (already configured).
- **`publish = false`** (or unset) → release-plz creates the tag/release but does
  **not** publish. Publish manually once the tag exists:

  ```bash
  cargo publish -p qrllib    # from the tagged commit; needs `cargo login` or CARGO_REGISTRY_TOKEN
  ```

The inaugural `0.1.0` was published manually. To switch to automated publishing,
set `publish = true` under the `[[package]] name = "qrllib"` entry (leave
`qrllib-wasm` unpublished).

> crates.io releases are **immutable** — a version can only be yanked, never
> overwritten. Never reuse a version number that is already live.

## 4. Publishing the WASM bindings to npm (`qrllib-wasm`)

`qrllib-wasm` is **never** published to crates.io (`publish = false`). It ships
to npm as [`@theqrl/qrllib-wasm`](https://www.npmjs.com/package/@theqrl/qrllib-wasm)
under the `@theqrl` org, **automatically**, via the `publish-wasm` job in
[`.github/workflows/release.yml`](.github/workflows/release.yml). That job runs on
every release (`releases_created == 'true'`), builds the bindings with wasm-pack,
and publishes via **npm trusted publishing (OIDC)** — no stored token — with build
provenance signed from the OIDC identity (mirroring `js-qrl-cryptography`):

```bash
wasm-pack build crates/qrllib-wasm --target web --scope theqrl --out-dir pkg
cd crates/qrllib-wasm/pkg && npm publish --access public --provenance
```

The version is read from `crates/qrllib-wasm/Cargo.toml`, which release-plz keeps
aligned with `qrllib` (`version_group = "workspace"`), so the npm version always
matches the `qrllib-vX.Y.Z` release.

**One-time setup (no secret to store):**
1. Create a GitHub environment named **`npm-publish`** (Settings → Environments) —
   the `publish-wasm` job runs in it, and trusted publishing is scoped to it.
2. On npmjs.com, open the `@theqrl/qrllib-wasm` package → **Settings → Trusted
   Publisher** (GitHub Actions) and set: repository `theqrl/rust-qrllib`, workflow
   `release.yml`, environment `npm-publish`.

To publish by hand instead, run the two commands above locally after `npm login`
(requires `npm >= 11.5.1`).

## 5. Verifying a release

Verify the SLSA provenance of a release asset:

```bash
slsa-verifier verify-artifact \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theqrl/rust-qrllib \
  <release-asset>
```

## 6. Redoing a release

Only safe **before** the version is published to crates.io (crates.io is
immutable). To re-cut a GitHub tag/release:

1. Delete the release and tag: `gh release delete qrllib-vX.Y.Z --cleanup-tag --yes`
2. Revert the `chore: release vX.Y.Z` commit on `main`.
3. release-plz re-opens the release PR; merge it to re-cut.

If the version is already on crates.io, do **not** re-cut it — land a fix and let
release-plz bump to the next version instead.

## Reference

- [`release-plz.toml`](release-plz.toml) — release configuration
- [`.github/workflows/release.yml`](.github/workflows/release.yml) — the release workflow
- [`crates/qrllib/CHANGELOG.md`](crates/qrllib/CHANGELOG.md) — generated changelog
- [`SECURITY.md`](SECURITY.md) — security policy and vulnerability reporting
