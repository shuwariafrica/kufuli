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

initialize := {
  val _ = initialize.value
  val running = sys.props.getOrElse("java.specification.version", "0")
  val major = running.takeWhile(_.isDigit).toIntOption.getOrElse(0)
  assert(major >= 25, s"kufuli requires JDK 25 or newer (JCA ML-KEM, JEP 496); found $running.")
}

formattingSettings

def scala3 = "3.8.4"
val boilerplate: ModuleID = "africa.shuwari" %% "boilerplate" % "0.13.0"
val boilerplateEffect: ModuleID = "africa.shuwari" %% "boilerplate-effect" % "0.13.0"
val jsoniter: ModuleID = "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-core" % "2.40.1"
val bouncycastle: ModuleID = "org.bouncycastle" % "bcprov-jdk18on" % "1.85.2"
val munit: ModuleID = "org.scalameta" %% "munit" % "1.3.4"
val `munit-cats-effect`: ModuleID = "org.typelevel" %% "munit-cats-effect" % "2.2.0"

def stubPublishGuard: List[Setting[?]] = List(publish / skip := true)

val kufuli =
  projectMatrix
    .in(file("modules/core"))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Cross-platform cryptographic primitives, recipes, and rotation for Scala 3 on cats-effect")
    .settings(libraryDependencies ++= Seq(boilerplate, boilerplateEffect))
    .jvmPlatform(Seq(scala3), coreDirectDir)
    .jsPlatform(Seq(scala3), jsSettings ++ jsNodeSourceDirs ++ coreDirectDir)
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) => p.settings(jsSettings ++ jsBrowserSettings("kufuli") ++ coreStubDir ++ stubPublishGuard)
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
    .jvmPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(libraryDependencies += bouncycastle).dependsOn(kufuli.jvm(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(jsSettings ++ jsNodeSourceDirs).dependsOn(kufuli.js(scala3))
    )
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
      testFrameworks += new TestFramework("munit.Framework"),
      // sbt 2.x resolves `test` through testQuick, which skips suites whose prior run succeeded with
      // unchanged inputs - so a warm state store reports `Total 0` on a fully working suite.
      Test / test := (Test / testOnly).toTask(" *").value
    )
    .jvmPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.enablePlugins(WycheproofPlugin)
          .settings(wycheproofSettings ++ corpusSettings ++ testDir("kat"))
          .dependsOn(kufuli.jvm(scala3), `kufuli-jose`.jvm(scala3), `kufuli-x509`.jvm(scala3), `kufuli-password`.jvm(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.enablePlugins(WycheproofPlugin)
          .settings(jsSettings ++ wycheproofSettings ++ corpusSettings ++ testDir("kat"))
          .dependsOn(kufuli.js(scala3), `kufuli-jose`.js(scala3), `kufuli-x509`.js(scala3), `kufuli-password`.js(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) =>
        p.settings(jsSettings)
          .dependsOn(kufuli.finder(VirtualAxis.js, WebCryptoAxis)(scala3))
    )
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.enablePlugins(WycheproofPlugin)
          .settings(
            wycheproofSettings ++ corpusSettings ++ NativePlatformPlugin.testLinkSettings ++ NativePlatformPlugin.provisionAwsLc ++
              NativePlatformPlugin.provisionArgon2 ++ testDir("kat")
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

def jsSettings: List[Setting[?]] = List(
  scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.ESModule) }
)

def jsNodeSourceDirs: List[Setting[?]] = List(
  Compile / unmanagedSourceDirectories += (Compile / sourceDirectory).value / "scalajs-node",
  Test / unmanagedSourceDirectories += (Test / sourceDirectory).value / "scalajs-node"
)

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

// The vendored x509-limbo and NIST PKITS slices become string constants, because JS and Native have
// no test resources to read at run time. Each vendored file is well under a class file's per-entry
// constant-pool limit, so no chunking is involved.
val corpusGenerate = taskKey[Seq[File]]("Embeds the vendored X.509 conformance corpora as Scala string constants.")

def corpusSettings: List[Setting[?]] = List(
  Test / corpusGenerate := Def.uncached {
    val out = (Test / sourceManaged).value / "corpora"
    val root = (LocalRootProject / baseDirectory).value / "modules" / "tests" / "corpora"

    def read(dir: File, suffix: String): List[(String, String)] =
      IO.listFiles(dir)
        .filter(_.getName.endsWith(suffix))
        .sortBy(_.getName)
        .toList
        .map(f => (f.getName.stripSuffix(suffix), IO.read(f, IO.utf8)))

    def entries(pairs: List[(String, String)]): String =
      pairs.map { case (name, body) => "    (\"" + name + "\", \"\"\"" + body + "\"\"\")" }.mkString(",\n")

    val limbo = read(root / "x509-limbo" / "cases", ".json")
    val certs = read(root / "nist-pkits" / "certs", ".pem")
    val cases = IO.read(root / "nist-pkits" / "cases.json", IO.utf8)
    val source = new StringBuilder
    source.append("package kufuli.tests.corpora\n\n")
    source.append("/** Generated from modules/tests/corpora. Do not edit. */\n")
    source.append("object Vectors:\n")
    source.append("  val limboNameConstraints: List[(String, String)] = List(\n")
    source.append(entries(limbo)).append("\n  )\n")
    source.append("  val pkitsCertificates: List[(String, String)] = List(\n")
    source.append(entries(certs)).append("\n  )\n")
    source.append("  val pkitsCases: String = \"\"\"").append(cases).append("\"\"\"\n")
    val rendered = source.result()

    IO.createDirectory(out)
    val file = out / "Vectors.scala"
    if (!file.exists() || IO.read(file, IO.utf8) != rendered) IO.write(file, rendered, IO.utf8)
    Seq(file)
  },
  Test / sourceGenerators += (Test / corpusGenerate).taskValue
)

def wycheproofSettings: List[Setting[?]] = List(
  wycheproofTargetPackage := "kufuli.tests.wycheproof",
  wycheproofVectorFiles := Seq(
    "aes_gcm_test.json",
    "aes_kwp_test.json",
    "chacha20_poly1305_test.json",
    "ecdsa_secp256r1_sha256_p1363_test.json",
    "ed25519_test.json",
    "mlkem_768_test.json",
    "mlkem_1024_test.json"
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
  "-Wunused:all",
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
