# Releasing

Cutting a release is `git tag -s vX.Y.Z && git push --tags`. Everything after that is
[`.github/workflows/release.yml`](../.github/workflows/release.yml), and everything it builds it
builds with `nix build` — the same command a developer runs and the same one `nix flake check` gates
on. There is deliberately no release-only build path: a release built differently from the thing that
was tested is a release nobody tested.

## What a tag produces

| Artifact | Notes |
|---|---|
| `kmsrs-server-{x86_64,aarch64}-linux` | statically linked against musl; no runtime dependencies |
| `kmsrs-client-{x86_64,aarch64}-linux` | the diagnostic and detection-resistance client |
| `kmsrsos_X.Y.Z_{amd64,arm64}.deb` | with the hardened systemd unit (`PKG-007`, #244) |
| `kmsrsos-X.Y.Z-1.{x86_64,aarch64}.rpm` | the same payload |
| `ghcr.io/schlarpc/kmsrsos:X.Y.Z` | multi-arch; two static binaries and nothing else |
| `kmsrs-server.exe`, `kmsrs-client.exe` | cross-compiled against a pinned MSVC CRT and SDK |
| `kmsrsos-x86_64.iso` | the bootable bare-metal image (`OS-017`, #333); x86_64 only, uncompressed |
| `sbom-*.cdx.json` | CycloneDX, derived from the lockfile |
| `SHA256SUMS`, `.sig`, `.pem` | one keyless cosign signature over the checksum file |

There is no apt or yum repository and no Homebrew tap (decision 26): a repository is ongoing
infrastructure with signing keys that have to be rotated, a downloadable package captures most of the
value, and macOS is not a target.

The ISO is shipped **uncompressed**. It is 5.3 MiB since `OS-030` (#348), and a `.iso.gz` is one more
step between an operator and a running host when the whole procedure is "upload it, attach it, boot
it".

**One signature, over the checksums.** Verifying that file then verifies everything in it, which is a
smaller thing for somebody to get right than eight signatures — and each machine's checksums were
produced on the machine that built those artifacts rather than centrally afterwards. Signing is
keyless, so there is no private key anywhere: the workflow's OIDC token is the identity. That is the
only way to sign from CI without the artifact this project
[claims to have none of](deployment.md#what-is-not-in-the-artifact).

```sh
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/schlarpc/kmsrsos/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

---

## The `latest` snapshot (`PKG-015`, #364)

There is a second channel, and it is deliberately a smaller one. Every push to `main` that passes the
**whole** gate moves a rolling prerelease at the tag `latest`, carrying the bootable ISO, the two
Windows binaries, and a signed checksum file.

```
https://github.com/schlarpc/kmsrsos/releases/download/latest/kmsrsos-x86_64.iso
```

**It is not a release, and the differences are the point.** The tag moves without warning, there is no
version number to put in a bug report, and it carries no SBOM, `.deb`, `.rpm` or container image —
those are things a tag produces. GitHub's "Latest" badge stays on the newest real tag, because the
snapshot release never sets `make_latest`.

It exists for one thing: booting a change before it is tagged. The ISO's entire surface is *does it
boot on your hypervisor*, and `linux-boot` can only answer that for QEMU.

**"All green" means every job.** Actions has no way to say "everything" — `needs` is a list of names —
so `the_latest_pointer_waits_for_every_job` reads the workflow and fails if any job is missing from
that list. A job added later and not added there would leave the pointer moving on a build that job
had failed, silently, and the artifact would look blessed. That is worse than having no pointer.

**It is signed, for the same reason a release is.** An unverifiable bootable image that people
download is worse than one they can check, and keyless signing records the workflow path in the
certificate — so the signature itself says which channel it came from, rather than a promise in the
notes. Verification is the same procedure with one substitution:

```sh
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/schlarpc/kmsrsos/.github/workflows/test.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

Note `test.yml` where a release says `release.yml`. A snapshot signature will not verify against the
release identity and a release signature will not verify against this one, which is the property
worth having.

The artifacts are also uploaded as ordinary workflow artifacts on **every** run, pull requests
included, under `snapshot-x86_64`. Those expire and have no stable URL; they are there so a reviewer
can boot a branch.

**The ISO is bit-reproducible** (`PKG-016`, #366), so the strongest check available is not the
signature but rebuilding it yourself:

```sh
git checkout <the commit the release notes name>
nix build .#linuxIso
sha256sum result   # compare against SHA256SUMS
```

That needs no trust in the machine that built it, which a signature cannot give you — a signature
attests to *who* built an artifact, not to *what it is*. It was not reproducible until #366: two
builds of one revision differed by 74 bytes, every one a timestamp in the volume descriptor or a
directory record, with no content difference at all. `reproducible` now rebuilds it on every run.

---

## Release notes (`PKG-012`, #249)

**The template below is not a formality.** It exists because of a specific, documented failure: the
Py-KMS-Organization fork changed a flag's arity, changed a path's meaning, renamed schema keys and
flipped the default bind address — in one release, with no deprecation and no note — and *three*
downstream forks each rediscovered a different subset of the breakage by running into it.

Nobody deprecated or versioned anything, and nobody was told. So the rule here is that a change a
downstream reader cannot discover by reading a diff gets its own section, and the first of those
sections is the one nothing else in this ecosystem has.

### Protocol-visible changes

**This section is never omitted. If nothing changed, it says so.**

A change is protocol-visible if a client could observe it: a byte on the wire, an HRESULT, a field
value, a timing property, or anything on the anti-fingerprinting checklist (#265). Those are the
changes that break a differential test, invalidate a golden vector, or make a previously
indistinguishable host distinguishable — and they are exactly the ones a version number does not
convey.

Each entry names the issue ID, because that identifier survives even when the issue is closed and
superseded.

### Operator-visible changes

Anything an operator scripted against: a route, a metric name, a log field, a status page, an exit
code, a unit file, a container path. `TEST-016` (#237) snapshots all of it, so a change here has a
failing test behind it and there is no excuse for the note being missing.

### Build-time settings

The four settings `mkKmsrsos` takes (`CFG-003`, #168). A changed default is a changed program for
everybody who did not set it.

### Everything else

Fixes, tests, documentation. Generated from the commit log.

---

## Template

```markdown
## Protocol-visible changes

None. No byte this release puts on the wire differs from vX.Y.Z-1.

<!-- or, when there are some: -->
- **`WIRE-0NN` (#NNN)** — the bind_ack padding is now drawn per response rather
  than per connection. A client comparing two responses on one association sees
  different bytes where it previously saw the same ones.

## Operator-visible changes

None.

<!-- or: -->
- `/metrics` gains `kmsrsos_thing_total`. Nothing was renamed or removed.

## Build-time settings

None changed.

## Everything else

<!-- generated from the commit log -->
```

---

## The checklist

1. `nix flake check` is green on `main`.
2. `docs/decisions.md` records anything decided or declined since the last tag.
3. Every issue closed since the last tag has a comment naming its commit.
4. Bump `version` in the workspace manifest, and in `flake.nix` where the OS packages name it.
5. Write the notes from the template above, **protocol-visible section first**.
6. `git tag -s vX.Y.Z -m 'vX.Y.Z'` and push it.
7. The workflow opens the release as a **draft**. Read what it attached, paste the notes, publish.

Step 7 is a draft rather than a publish on purpose. Everything before it is automated and reproducible;
what a release *says* is the part a person should have looked at.
