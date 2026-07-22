addSbtPlugin("africa.shuwari" % "sbt-snx" % "0.4.0")
addSbtPlugin("org.scala-js" % "sbt-scalajs" % "1.22.0")

addSbtPlugin("africa.shuwari" % "sbt-version" % "0.8.0")

addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.6.1")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix" % "0.14.7")
addSbtPlugin("com.github.sbt" % "sbt-header" % "5.11.0")

addSbtPlugin("com.github.sbt" % "sbt-pgp" % "2.3.1")

// TODO: remove once scala-js-env-playwright supports sbt 2.x upstream.
lazy val root = (project in file(".")).dependsOn(playwrightEnv)
lazy val playwrightEnv =
  RootProject(uri("https://github.com/arashi01/scala-js-env-playwright.git#sbt-2"))
