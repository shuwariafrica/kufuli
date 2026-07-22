import sbt.*

import scala.sys.process.Process
import scala.sys.process.ProcessLogger

import snx.sbt.SNXImports.*

/** kufuli's native provisioning recipes. sbt-snx is the mechanism (a pkg-config analogue); these
  * are the recipes it carries, shipped so a consumer provisions each Native backend in one line:
  * {{{
  * SNX.libraries += KufuliNative.awsLc      // core
  * SNX.libraries += KufuliNative.argon2     // kufuli-password
  * }}}
  */
object KufuliNative {

  /** The aws-lc release kufuli is verified against. */
  val awsLcTag: String = "v5.2.0"

  private val awsLcRepository: String = "https://github.com/aws/aws-lc.git"

  /** Crypto-only, reproducible. `BUILD_LIBSSL`, `BUILD_TOOL` and `BUILD_TESTING` each default ON;
    * leaving `BUILD_LIBSSL`/`BUILD_TESTING` on would also pull in a C++ toolchain the crypto build
    * does not otherwise need. `DISABLE_PERL=OFF` makes Perl a `find_package(REQUIRED)` hard
    * failure, and `ENABLE_SOURCE_MODIFICATION` defaults ON and writes into the checkout, which a
    * pinned build must not do. sbt-snx supplies `CMAKE_BUILD_TYPE` and forces
    * `BUILD_SHARED_LIBS=OFF` itself.
    */
  private val configureFlags: Seq[String] = Seq(
    "-DBUILD_LIBSSL=OFF",
    "-DBUILD_TOOL=OFF",
    "-DBUILD_TESTING=OFF",
    "-DDISABLE_GO=ON",
    "-DDISABLE_PERL=ON",
    "-DENABLE_SOURCE_MODIFICATION=OFF",
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
  )

  /** aws-lc's CMake Visual Studio generator cannot assemble, so the build is driven by Ninja from
    * an environment where the MSVC toolchain is already on PATH (`vcvarsall.bat`). sbt-snx's CMake
    * backend never passes `-DCMAKE_C_COMPILER`, so an `SNX.clang` override would not reach this
    * build (sbt-snx #19) - the discovered PATH compiler must itself be the MSVC one.
    * `CMAKE_MSVC_RUNTIME_LIBRARY` (honoured through aws-lc's `CMP0091 NEW`) links the CRT
    * statically to match the Scala Native link and libargon2; a mismatched CRT leaves aws-lc's
    * dynamic `__imp_` ucrt symbols unresolved. Plain `MultiThreaded` (release `/MT`) matches the
    * link's `-fms-runtime-lib=static` even for a Debug build. The per-arch assembler handling that
    * lets this apply cleanly is in the cmake selector.
    */
  private val windowsFlags: Seq[String] =
    Seq("-GNinja", "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded")

  /** The link closure a static archive cannot carry itself. */
  private val closure: PartialFunction[NativeRuntime, Flags] = { case Linux(_, _) =>
    Flags.libraries("pthread", "dl")
  }

  /** aws-lc, built from source at a pinned tag and folded into the link.
    *
    * The name is `crypto` deliberately: it is both the rebind key and the `-l` name a System
    * provisioning renders, which is what lets a consumer whose system libcrypto IS aws-lc rebind to
    * `NativeLibrary("crypto")` instead. A consumer who provisions neither links stock libcrypto and
    * fails loudly - kufuli's C shim is written to the BoringSSL-dialect surface, and asserts
    * `OPENSSL_IS_AWSLC` at compile time before that.
    */
  val awsLc: NativeLibrary =
    NativeLibrary(
      "crypto",
      Vendored
        .git(awsLcRepository, awsLcTag)
        .cmake(
          Seq("crypto"),
          {
            // x86_64 assembles with NASM, which ignores CMAKE_MSVC_RUNTIME_LIBRARY. aarch64 assembles
            // with the MSVC assembler, which rejects that setting and cannot be excluded from it
            // (CMAKE_MSVC_RUNTIME_LIBRARY forbids a COMPILE_LANGUAGE generator expression - it is read
            // during compiler-ABI detection), so build the aarch64 crypto pure-C to keep the static CRT
            // off the assembler; the C implementation is functionally identical, only unoptimised.
            case Windows(Arch.X86_64, _) => configureFlags ++ windowsFlags :+ "-DCMAKE_ASM_NASM_COMPILER=nasm"
            case Windows(_, _)           => configureFlags ++ windowsFlags :+ "-DOPENSSL_NO_ASM=ON"
            case _                       => configureFlags
          }
        )
        .options(closure)
    )

  /** The libargon2 release kufuli is verified against (matches the `vendor/phc-winner-argon2`
    * submodule commit).
    */
  val argon2Tag: String = "20190702"

  private val argon2Repository: String = "https://github.com/P-H-C/phc-winner-argon2.git"

  /** Build libargon2 as a static archive with the reference Makefile.
    *
    * `NO_THREADS=1` computes every lane on the calling thread: the Argon2id output depends on the
    * lane count, not on how many OS threads compute them, so the hash is byte-identical while the
    * build gains no pthread dependency (and never spawns a thread on the musl static row).
    * `OPTTARGET=` empties the Makefile's `-march`, so the archive is the compiler's default
    * baseline rather than `-march=native` - reproducible and safe to cross-compile. sbt-snx
    * requires a backend to write its outputs under the context staging directory, so the source is
    * copied there and built out of the cached clone.
    */
  private def buildArgon2(context: BuildContext): Artefacts = {
    val buildDir = context.staging / "build"
    IO.copyDirectory(context.source, buildDir)
    // On MSVC, fold the target and CRT selectors into `CC` (make expands `$(CC)` at every compile;
    // the archive step runs `ar`, so it is untouched; a command-line `CFLAGS=` would instead clobber
    // the reference Makefile's own `CFLAGS +=`). clang - unlike the `cl.exe` aws-lc builds with - does
    // not take its target from the vcvars environment, so a bare invocation defaults to x86_64 and
    // emits objects the aarch64 link cannot resolve (undefined `argon2id_hash_raw`); pin the target to
    // the build arch. The static CRT matches aws-lc and the Scala Native link.
    val cc = context.runtime match {
      case Windows(arch, Msvc) =>
        val triple = arch match {
          case Arch.X86_64  => "x86_64-pc-windows-msvc"
          case Arch.Aarch64 => "aarch64-pc-windows-msvc"
        }
        s"${context.clang.getAbsolutePath} --target=$triple -fms-runtime-lib=static"
      case _ => context.clang.getAbsolutePath
    }
    val command = Seq(
      "make",
      "-C",
      buildDir.getAbsolutePath,
      "libargon2.a",
      s"CC=$cc",
      "NO_THREADS=1",
      "OPTTARGET="
    )
    context.log.info(command.mkString("snx argon2: ", " ", ""))
    val logger = ProcessLogger(line => context.log.info(line), line => context.log.error(line))
    if (Process(command).!(logger) != 0)
      sys.error(s"snx: libargon2 build failed: ${command.mkString(" ")}")
    val includes = Seq(buildDir / "include")
    context.runtime match {
      case Windows(_, Msvc) =>
        // lld-link does not resolve `argon2id_hash_raw` from make's GNU `ar` archive (aws-lc links
        // because CMake emits an MSVC `.lib`; argon2 ships no CMakeLists). Fold the compiled objects in
        // directly - a directly-linked object is always included, so no archive symbol index is read.
        val objects = ((buildDir / "src") ** "*.o").get().filter(_.isFile).sortBy(_.getAbsolutePath)
        if (objects.isEmpty) sys.error(s"snx: libargon2 build produced no objects under ${(buildDir / "src").getAbsolutePath}")
        Artefacts(objects, includes)
      case _ =>
        val archive = buildDir / "libargon2.a"
        if (!archive.isFile) sys.error(s"snx: libargon2 build produced no archive at ${archive.getAbsolutePath}")
        Artefacts(Seq(archive), includes)
    }
  }

  /** libargon2, built from source at a pinned tag and folded into the link.
    *
    * The name is `argon2`, both the rebind key and the `-l` name, so a consumer whose system
    * already provides libargon2 can rebind `NativeLibrary("argon2")` to System instead of vendoring
    * it. The Argon2id primitive is a frozen deterministic spec (RFC 9106), so a vendored provider
    * agrees byte-for-byte with any other conformant one; `kufuli.password`'s PHC codec and policy
    * sit in shared Scala above it.
    */
  val argon2: NativeLibrary =
    NativeLibrary(
      "argon2",
      Vendored
        .git(argon2Repository, argon2Tag)
        // The token is the whole cache key for a `command` build (the build function's contents are not
        // hashed), so it MUST change whenever `buildArgon2` changes, or a stale archive is reused.
        .command("libargon2-static-ref-nothreads-2-winobjs")(buildArgon2)
    )
}
