addSbtPlugin("africa.shuwari" % "sbt-snx" % "0.4.5")
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.22.0")

addSbtPlugin("africa.shuwari" % "sbt-version" % "0.10.0")

addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.6.2")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix" % "0.14.7")
addSbtPlugin("com.github.sbt" % "sbt-header" % "5.11.0")

addSbtPlugin("com.github.sbt" % "sbt-pgp" % "2.3.1")

// A source dependency on a fork until scala-js-env-playwright supports sbt 2.x upstream. Dormant
// until the browser row runs its own suite under a real WebCrypto environment (PLAN K-3'); pinned to
// a commit rather than the branch because sbt compiles this as meta-build code in every job,
// including publish.
lazy val root = (project in file(".")).dependsOn(playwrightEnv)
lazy val playwrightEnv =
  RootProject(uri("https://github.com/arashi01/scala-js-env-playwright.git#e5072604316edecbb16edd09042a2e3b2156d528"))
