# Contributing to kufuli

## Build requirements

- JDK 25+.
- sbt 2.x (pinned in `project/build.properties`).
- Node.js 24+ (for the Scala.js targets).
- A C toolchain for Scala Native: clang and, on Windows, the MSVC toolchain via `vcvarsall.bat`. The
  native backend links aws-lc, provisioned by sbt-snx from `vendor/`.
- Playwright browsers, for the browser test target.
- Git, for the vendored submodules.

## First build

Wycheproof test vectors and the PHC Argon2 reference C source are pinned as git submodules under
`vendor/`. Clone with `--recursive`, or after a plain clone run:

```
git submodule update --init
```

The per-platform aggregators run every module's tests on one target, as CI does:

```
sbt kufuli-jvm/test        # JVM
sbt kufuli-js/test         # Node.js and browser
sbt kufuli-native/test     # Scala Native
```

sbt caches test runs; use `<project>/testOnly *` to force a full re-run.

## Project structure

```
modules/
  core/       Primitives, recipes, key rotation, kufuli.unsafe. Shared source in scala/;
              per-platform KeyRepr and capability aliases in scalajvm/, scalajs-node/,
              scalajs-browser/, and scalanative/.
  jose/       JWT/JWS/JWE/JWK(S), COSE key import.
  password/   Argon2id and the PHC format.
  x509/       Path validation and stapled-OCSP verification.
  tests/      Cross-platform test suites (see below).

project/
  KufuliNative.scala           The aws-lc and libargon2 vendored-build recipes.
  NativePlatformPlugin.scala   Native test-interface eviction, aws-lc/argon2 provisioning, static test linking.
  WebCryptoAxis.scala          The virtual axis distinguishing the browser JS row from Node.
  WycheproofPlugin.scala       Embeds Wycheproof JSON vectors as generated Scala source.

vendor/
  wycheproof/          Wycheproof test vectors (Apache-2.0).
  phc-winner-argon2/   PHC Argon2 reference C source (CC0 1.0 / Apache-2.0).
```

## Test structure

The `tests` module composes capability-gated source sets, so each suite runs only where its
dependencies exist:

- `src/test/scala` runs on all four artifacts: the pure value-layer checks, the structural misuse
  negatives, and the core round-trip flows.
- `src/test/extended` (JVM, Native, Node) adds the Direct-gated record-machine suites and the jose,
  x509, and password suites.
- `src/test/pq` (JVM, Native) adds the ML-KEM hybrid flow.
- `src/test/node` and `src/test/browser` hold the per-artifact capability-boundary checks, proved by
  `summon` for presence and `typeChecks` for absence.

Conventions for new tests:

- Every public operation has at least one test.
- Each algorithm carries an RFC or NIST known-answer vector and, where vectors exist, Wycheproof
  adversarial coverage. When a standard's case is inapplicable (for example, a key below our
  minimum), the exclusion is noted against the standard's reference.
- A suite goes in the widest source set its dependencies allow.

## Vendor submodules

Each submodule is pinned to an exact upstream SHA by the parent commit, so the build is reproducible
with no imperative checkout step. To update one:

```
cd vendor/<name>
git fetch
git checkout <new-sha>
cd ../..
git add vendor/<name>
git commit -m "Bump <name> to <new-sha>"
```

Then record the new SHA in `NOTICE`.

## Code style

Run `sbt format` before committing (`scalafixAll; scalafmtAll; scalafmtSbt; headerCreateAll`); `sbt
check` is the read-only gate CI runs. Both main and test sources compile under the same strict
regime: `-Werror`, `-Yexplicit-nulls`, and the full `-Wunused` set.
