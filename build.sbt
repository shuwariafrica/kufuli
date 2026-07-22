import WycheproofPlugin.autoImport.*

scalaVersion := scala3
organization := "africa.shuwari"
startYear := Some(2026)
homepage := Some(url("https://github.com/shuwariafrica/kufuli"))
semanticdbEnabled := true
versionScheme := Some("semver-spec")
licenses := List("MIT" -> url("https://opensource.org/licenses/MIT"))
scmInfo := Some(
  ScmInfo(
    url("https://github.com/shuwariafrica/kufuli"),
    "scm:git:https://github.com/shuwariafrica/kufuli.git",
    Some("scm:git:git@github.com:shuwariafrica/kufuli.git")
  )
)

// kufuli requires JDK 25 or newer: the JVM backend uses JCA ML-KEM (JEP 496, in-JDK from 24) and
// the ecosystem's LTS floor is 25.
initialize := {
  val _ = initialize.value
  val running = sys.props.getOrElse("java.specification.version", "0")
  val major = running.takeWhile(_.isDigit).toIntOption.getOrElse(0)
  assert(major >= 25, s"kufuli requires JDK 25 or newer (JCA ML-KEM, JEP 496); found $running.")
}

formattingSettings

def scala3 = "3.8.4"
val boilerplate: ModuleID = "africa.shuwari" %% "boilerplate" % "0.10.0"
val boilerplateEffect: ModuleID = "africa.shuwari" %% "boilerplate-effect" % "0.10.0"
val jsoniter: ModuleID = "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-core" % "2.39.1"
val bouncycastle: ModuleID = "org.bouncycastle" % "bcprov-jdk18on" % "1.84"
val munit: ModuleID = "org.scalameta" %% "munit" % "1.3.0"
val `munit-cats-effect`: ModuleID = "org.typelevel" %% "munit-cats-effect" % "2.2.0"

// The JVM row wires the real JCA backend (`scalajvm`); the other three rows share the byte-faithful
// stub backend (`scala-stub`). `kufuli.unsafe` ships only in the synchronous artifacts, so
// `scala-direct` joins every row except the browser (module-level absence there).
val kufuli =
  projectMatrix
    .in(file("modules/core"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Cross-platform cryptographic primitives, recipes, and rotation for Scala 3 on cats-effect")
    .settings(libraryDependencies ++= Seq(boilerplate, boilerplateEffect))
    .jvmPlatform(Seq(scala3), coreDirectDir)
    .jsPlatform(Seq(scala3), jsSettings ++ jsNodeSourceDirs ++ coreStubDir ++ coreDirectDir)
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) => p.settings(jsSettings ++ jsBrowserSettings("kufuli") ++ coreStubDir)
    )
    .snxPlatform(
      Seq(scala3),
      NativePlatformPlugin.schemeSettings ++ coreDirectDir ++ NativePlatformPlugin.exportCrypto ++ NativePlatformPlugin.provisionAwsLc
    )

val `kufuli-jose` =
  projectMatrix
    .in(file("modules/jose"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "JOSE (JWT/JWS/JWE/JWK/COSE) over kufuli")
    .settings(libraryDependencies ++= Seq(boilerplate, boilerplateEffect, jsoniter))
    .jvmPlatform(Seq(scala3), Seq.empty[VirtualAxis], (p: Project) => p.dependsOn(kufuli.jvm(scala3)))
    .jsPlatform(Seq(scala3), Seq.empty[VirtualAxis], (p: Project) => p.settings(jsSettings).dependsOn(kufuli.js(scala3)))
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(NativePlatformPlugin.schemeSettings ++ NativePlatformPlugin.provisionAwsLc).dependsOn(kufuli.native(scala3))
    )

val `kufuli-password` =
  projectMatrix
    .in(file("modules/password"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Argon2id password hashing (PHC codec, policy rehash) over kufuli")
    .settings(libraryDependencies ++= Seq(boilerplate, boilerplateEffect))
    // BouncyCastle stays password-module + JVM-only: the Argon2id provider for the JVM backend.
    .jvmPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(libraryDependencies += bouncycastle).dependsOn(kufuli.jvm(scala3))
    )
    .jsPlatform(Seq(scala3), Seq.empty[VirtualAxis], (p: Project) => p.settings(jsSettings).dependsOn(kufuli.js(scala3)))
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.settings(
          NativePlatformPlugin.schemeSettings ++ NativePlatformPlugin.provisionAwsLc ++
            NativePlatformPlugin.exportArgon2 ++ NativePlatformPlugin.provisionArgon2
        ).dependsOn(kufuli.native(scala3))
    )

val `kufuli-x509` =
  projectMatrix
    .in(file("modules/x509"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "X.509 path validation and stapled-OCSP verification over kufuli")
    .settings(libraryDependencies ++= Seq(boilerplate, boilerplateEffect))
    .jvmPlatform(Seq(scala3), Seq.empty[VirtualAxis], (p: Project) => p.dependsOn(kufuli.jvm(scala3)))
    .jsPlatform(Seq(scala3), Seq.empty[VirtualAxis], (p: Project) => p.settings(jsSettings).dependsOn(kufuli.js(scala3)))
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(NativePlatformPlugin.schemeSettings ++ NativePlatformPlugin.provisionAwsLc).dependsOn(kufuli.native(scala3))
    )

// Capability-gated test source sets: `scala` runs on all four platforms; `extended` (jvm/native/
// node) adds the Direct-gated and jose/x509/password suites; `pq` (jvm/native) adds ML-KEM; `node`
// and `browser` hold the per-artifact capability-boundary checks. The browser row depends on
// kufuli-browser only, so its universal suite is core-scoped by construction.
val `kufuli-tests` =
  projectMatrix
    .in(file("modules/tests"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publish / skip := true)
    .settings(description := "Cross-platform stub-backed test suites for kufuli")
    .settings(
      libraryDependencies += munit % Test,
      libraryDependencies += `munit-cats-effect` % Test,
      libraryDependencies += jsoniter % Test,
      testFrameworks += new TestFramework("munit.Framework")
    )
    .jvmPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.enablePlugins(WycheproofPlugin)
          .settings(wycheproofSettings ++ testDir("extended") ++ testDir("pq") ++ testDir("kat"))
          .dependsOn(kufuli.jvm(scala3), `kufuli-jose`.jvm(scala3), `kufuli-x509`.jvm(scala3), `kufuli-password`.jvm(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.settings(jsSettings ++ testDir("extended") ++ testDir("node"))
          .dependsOn(kufuli.js(scala3), `kufuli-jose`.js(scala3), `kufuli-x509`.js(scala3), `kufuli-password`.js(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) =>
        p.settings(jsSettings ++ testDir("browser"))
          .dependsOn(kufuli.finder(VirtualAxis.js, WebCryptoAxis)(scala3))
    )
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.enablePlugins(WycheproofPlugin)
          .settings(
            wycheproofSettings ++ NativePlatformPlugin.testLinkSettings ++ NativePlatformPlugin.provisionAwsLc ++
              NativePlatformPlugin.provisionArgon2 ++ testDir("extended") ++ testDir("pq") ++ testDir("kat")
          )
          .dependsOn(
            kufuli.native(scala3),
            `kufuli-jose`.native(scala3),
            `kufuli-x509`.native(scala3),
            `kufuli-password`.native(scala3)
          )
    )

val `kufuli-jvm` =
  projectMatrix
    .in(file(".jvm"))
    .jvmPlatform(Seq(scala3))
    .settings(publish / skip := true)
    .aggregate(kufuli, `kufuli-jose`, `kufuli-password`, `kufuli-x509`, `kufuli-tests`)

val `kufuli-js` =
  projectMatrix
    .in(file(".js"))
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.aggregate(
          kufuli.finder(VirtualAxis.js, WebCryptoAxis)(scala3),
          `kufuli-tests`.finder(VirtualAxis.js, WebCryptoAxis)(scala3)
        )
    )
    .defaultAxes(VirtualAxis.js, VirtualAxis.scalaABIVersion(scala3))
    .settings(publish / skip := true)
    .aggregate(kufuli, `kufuli-jose`, `kufuli-password`, `kufuli-x509`, `kufuli-tests`)

val `kufuli-native` =
  projectMatrix
    .in(file(".native"))
    .snxPlatform(Seq(scala3))
    .defaultAxes(VirtualAxis.native, VirtualAxis.scalaABIVersion(scala3))
    .settings(publish / skip := true)
    .aggregate(kufuli, `kufuli-jose`, `kufuli-password`, `kufuli-x509`, `kufuli-tests`)

val `kufuli-root` =
  projectMatrix
    .in(file("."))
    .settings(publish / skip := true)
    .aggregate(`kufuli-jvm`, `kufuli-js`, `kufuli-native`)

def jsSettings: List[Setting[?]] = List(
  scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.ESModule) }
)

def jsNodeSourceDirs: List[Setting[?]] = List(
  Compile / unmanagedSourceDirectories += (Compile / sourceDirectory).value / "scalajs-node",
  Test / unmanagedSourceDirectories += (Test / sourceDirectory).value / "scalajs-node"
)

// Core-only extra source sets: the stub backend (non-JVM rows) and the synchronous `unsafe` floor
// (non-browser rows).
def coreStubDir: List[Setting[?]] =
  List(Compile / unmanagedSourceDirectories += (Compile / sourceDirectory).value / "scala-stub")
def coreDirectDir: List[Setting[?]] =
  List(Compile / unmanagedSourceDirectories += (Compile / sourceDirectory).value / "scala-direct")
def jsBrowserSettings(base: String): List[Setting[?]] = List(
  moduleName := s"$base-browser",
  Compile / unmanagedSourceDirectories += (Compile / sourceDirectory).value / "scalajs-browser",
  Test / unmanagedSourceDirectories += (Test / sourceDirectory).value / "scalajs-browser",
  Compile / unmanagedSourceDirectories := (Compile / unmanagedSourceDirectories).value.distinct,
  Test / unmanagedSourceDirectories := (Test / unmanagedSourceDirectories).value.distinct
)

def testDir(name: String): List[Setting[?]] = List(
  Test / unmanagedSourceDirectories += (Test / sourceDirectory).value / name
)

// p1363 gives raw r||s signatures (kufuli's Signature form); ML-KEM decaps is covered in RealBackendSuite.
def wycheproofSettings: List[Setting[?]] = List(
  wycheproofTargetPackage := "kufuli.tests.wycheproof",
  wycheproofVectorFiles := Seq(
    "aes_gcm_test.json",
    "chacha20_poly1305_test.json",
    "ecdsa_secp256r1_sha256_p1363_test.json",
    "ed25519_test.json"
  )
)

def baseCompilerOptions = List(
  "-language:experimental.macros",
  "-language:higherKinds",
  "-language:implicitConversions",
  "-language:strictEquality",
  "-Xkind-projector",
  "-Xmax-inlines:64",
  "-unchecked",
  "-deprecation",
  "-feature",
  "-explain",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wunused:implicits",
  "-Wunused:explicits",
  "-Wunused:imports",
  "-Wunused:locals",
  "-Wunused:params",
  "-Wunused:privates",
  "-Yrequire-targetName",
  "-Ycheck-reentrant",
  "-Ycheck-mods"
)

def compilerOptions = baseCompilerOptions ++ List(
  "-Yexplicit-nulls",
  "-Wsafe-init",
  "-Xcheck-macros",
  "-Werror"
)

def compilerSettings = List(
  Compile / compile / scalacOptions ++= compilerOptions,
  Test / compile / scalacOptions ++= compilerOptions,
  Compile / doc / scalacOptions := Nil,
  Test / doc / scalacOptions := Nil
)

def formattingSettings = List(
  scalafmtDetailedError := true,
  scalafmtPrintDiff := true
)

def fileHeaderSettings: List[Setting[?]] =
  List(
    headerLicense := {
      val developmentTimeline = {
        import java.time.Year
        val start = startYear.value.get
        val current: Int = Year.now.getValue
        if (start == current) s"$current" else s"$start, $current"
      }
      Some(HeaderLicense.MIT(developmentTimeline, "Ali Rashid."))
    },
    headerEmptyLine := false
  )

def publishSettings: List[Setting[?]] = List(
  packageOptions += Package.ManifestAttributes(
    "Build-Jdk" -> System.getProperty("java.version"),
    "Specification-Title" -> name.value,
    "Specification-Version" -> Keys.version.value,
    "Implementation-Title" -> name.value
  ),
  publishTo := {
    if (isSnapshot.value) Some("central-snapshots".at("https://central.sonatype.com/repository/maven-snapshots/"))
    else localStaging.value
  },
  pomIncludeRepository := (_ => false),
  publishMavenStyle := true,
  developers := List(
    Developer(
      "arashi01",
      "Ali Rashid",
      "https://github.com/arashi01",
      url("https://github.com/arashi01")
    )
  )
)

addCommandAlias("format", "scalafixAll; scalafmtAll; scalafmtSbt; headerCreateAll")
addCommandAlias("check", "scalafixAll --check; scalafmtCheckAll; scalafmtSbtCheck; headerCheckAll")

lazy val showConfigurations = taskKey[Unit]("Shows all configurations")

lazy val inAnyProjectAndConfiguration = ScopeFilter(inAnyProject, inAnyConfiguration)

showConfigurations := Def.uncached {
  val configs = configuration.all(inAnyProjectAndConfiguration).value.toSet

  configs.filter(_.isPublic).foreach { c =>
    println(s"${c.name} - ${c.description}")
  }
} // No .value here!
