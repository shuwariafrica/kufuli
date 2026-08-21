import sbt.*
import sbt.Keys.*

import scala.scalanative.build.LTO
import scala.scalanative.build.Mode
import KufuliBuild.{optimisation, Optimisation}

import snx.sbt.SNXImports.*

/** sbt-snx wiring for kufuli's native rows: test-interface eviction scheme and static test
  * binaries.
  */
object NativePlatformPlugin:

  // Set by CI for the musl-static cells; absent or unset for every dynamic build.
  private val staticLink: Boolean = sys.env.get("KUFULI_STATIC_LINK").contains("true")

  /** The scala-native test-interface carries no semver scheme; `always` stops eviction failing the
    * build.
    */
  val schemeSettings: Seq[Setting[?]] = Seq(
    libraryDependencySchemes += "org.scala-native" % "test-interface_native0.5_3" % "always"
  )

  /** Declares that the Native backend needs `crypto` (aws-lc). Exported in the NIR descriptor so a
    * downstream consumer provisions it once with `SNX.libraries += KufuliNative.awsLc`; a consumer
    * whose system libcrypto is aws-lc rebinds the name to System instead.
    */
  val exportCrypto: Seq[Setting[?]] = Seq(SNX.libraries += NativeLibrary("crypto"))

  /** Provisions aws-lc from source for kufuli's own binding tests (scoped to the test link, as a
    * NIR library publishes its C as source rather than exporting a vendored build). One
    * per-platform link fix travels with it: on MSVC the C runtime is linked statically to match
    * aws-lc (built `/MT`) and libargon2, without which aws-lc's dynamic `__imp_` ucrt stdio symbols
    * are unresolved.
    */
  val provisionAwsLc: Seq[Setting[?]] = Seq(
    SNX.libraries += KufuliNative.awsLc % Test,
    Test / SNX.modifiers += Modifier.platform { case runtime @ Windows(_, Msvc) => SNX.staticRuntime(runtime) }
  )

  /** Declares that the Native `kufuli-password` backend needs `argon2` (libargon2). Exported in the
    * NIR descriptor so a downstream consumer provisions it once with
    * `SNX.libraries += KufuliNative.argon2`; a consumer whose system provides libargon2 rebinds the
    * name to System instead.
    */
  val exportArgon2: Seq[Setting[?]] = Seq(SNX.libraries += NativeLibrary("argon2"))

  /** Provisions libargon2 from source for the Native binding tests (test-scoped, as for aws-lc). */
  val provisionArgon2: Seq[Setting[?]] = Seq(SNX.libraries += KufuliNative.argon2 % Test)

  /** Test-binary link settings: only musl can produce a fully static executable, and only when CI
    * asks.
    */
  val testLinkSettings: Seq[Setting[?]] = schemeSettings ++ Seq(
    Test / SNX.modifiers += Modifier.platform {
      case runtime @ Linux(_, Musl) if staticLink => SNX.staticRuntime(runtime)
    },
    Test / SNX.modifiers ++= (if optimisation.value == Optimisation.Full then Seq(releaseOptimisation) else Nil)
  )

  private def releaseOptimisation: Modifier[Native] = Modifier.platform {
    // GNU ld performs LTO only through LLVMgold.so, which is packaged separately from clang and is
    // absent on ordinary LLVM installs; lld links LLVM bitcode natively and ships with the toolchain
    // Scala Native already requires. ld64 and lld-link need no such flag on the other two platforms.
    case Linux(_, _) => native => native.mode(Mode.releaseFull).lto(LTO.thin).linkOptions("-fuse-ld=lld")
    case _           => native => native.mode(Mode.releaseFull).lto(LTO.thin)
  }
end NativePlatformPlugin
