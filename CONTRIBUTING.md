# Contributing to kufuli

## Requirements

- JDK 25 or newer. The build asserts it, because the JVM backend takes ML-KEM from the JDK's own
  JCA provider (JEP 496).
- sbt. The version is pinned in `project/build.properties`.
- Node.js 24.7 or newer for the Scala.js rows. 24.7 is the floor for `crypto.argon2`.
- clang, CMake and make for the Scala Native row. sbt-snx fetches aws-lc and libargon2 from git at
  pinned commits and builds them locally; neither is vendored into the tree.
- On Windows the Native row additionally needs the MSVC toolchain on PATH through `vcvarsall.bat`,
  Ninja, and NASM on x86_64. sbt-snx never passes `-DCMAKE_C_COMPILER`, so the compiler it discovers
  on PATH must itself be the MSVC one.

## First build

The Wycheproof vectors are a git submodule, and the build fails without them:

```
git submodule update --init vendor/wycheproof
```

`vendor/phc-winner-argon2` records the libargon2 commit the Native backend is built against. No
build step reads it, so it does not need initialising to build or test.

## Running the tests

```
sbt suites
```

One command, every suite, every row. Do not reach for `sbt test`: sbt resolves it through
`testQuick`, which skips suites whose inputs have not changed and reports `Total 0` on a working
tree.

Test sources are split by the rows that can run them:

| directory         | rows                       |
| ----------------- | -------------------------- |
| `src/test/scala`  | JVM, Node, Native, browser |
| `src/test/kat`    | JVM, Node, Native          |
| `src/test/misuse` | Native                     |

The browser row is stub-backed, so nothing reaching a provider is added to it. `misuse` is Native
alone because aws-lc is the only backend carrying XChaCha20-Poly1305 and AES-256-GCM-SIV.

## Gates

```
sbt format
```

`format` rewrites and validates in one pass (`scalafixAll; scalafmtAll; scalafmtSbt;
headerCreateAll`). `check` is the read-only form CI runs, and additionally executes the
capture-checking fixtures. Main and test sources compile under the same regime: `-Werror`,
`-Yexplicit-nulls`, `-Wunused:all`.

### The release gate

kufuli publishes NIR and SJSIR, so the optimiser and the linker run in the consumer's build.
`sbt suites` links the way you iterate, which is Scala Native in debug with no LTO and Scala.js
through `fastLinkJS`. The release gate links the strongest way a consumer can:

```
sbt shutdown
KUFULI_RELEASE_GATE=true sbt suites
```

That selects Scala Native `release-full` with thin LTO, and Scala.js `fullLinkJS`. Two things to
know before running it:

- The variable is read when the build loads, so shut the server down first. One already running
  ignores it and reports a pass that means nothing.
- On Linux the gate links with `lld`, because GNU `ld` performs LTO only through `LLVMgold.so`,
  which ships apart from clang and is absent on an ordinary LLVM install.

No release is cut on a verdict from `sbt suites` alone; CI runs the release form on the publish
path.

## Vendor submodules

Each submodule is pinned to an exact upstream SHA by the parent commit. To move one:

```
cd vendor/<name>
git fetch
git checkout <new-sha>
cd ../..
git add vendor/<name>
```

Record the new SHA in `NOTICE` in the same commit.
