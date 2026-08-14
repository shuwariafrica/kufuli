import sbt.*
import sbt.Keys.*

import xsbti.FileConverter

/** Build-internal verification for the capture-checked carrier sources: the escape fixture and the
  * formatter-exclusion divergence check, both wired into the `check` alias by `build.sbt`.
  */
object KufuliBuild extends AutoPlugin {

  // Capture-checking negatives cannot be suite rows: `typeChecks` compiles its snippet in a nested
  // scope, where the language import is rejected and the body is never capture-checked.
  val checkCaptureEscapes =
    taskKey[Unit]("Compile each capture-checking escape in isolation and assert its exact diagnostic.")

  // scalafix withholds by content and scalafmt by path, so a newly capture-checked file can be
  // withheld from one and not the other, breaking `format`.
  val checkCaptureCheckedExclusions =
    taskKey[Unit]("Verify .scalafmt.conf's exclusion list matches the capture-checked sources on disk.")

  /** True for a source carrying the capture-checking language import - the predicate the
    * per-project scalafix withholding and the exclusion divergence check share.
    */
  def captureChecked(source: File): Boolean =
    source.getName.endsWith(".scala") &&
      IO.readLines(source).exists(line => line.trim.matches("""import (scala\.)?language\.experimental\.captureChecking"""))

  // Uncached deliberately: both tasks discover their inputs rather than declare them, so a cached
  // success would outlive the divergence they exist to catch.
  val fixtureSettings: Seq[Def.Setting[?]] = List(
    LocalRootProject / checkCaptureCheckedExclusions := Def.uncached {
      val root = (LocalRootProject / baseDirectory).value
      val declared = IO
        .readLines(root / ".scalafmt.conf")
        .dropWhile(line => !line.startsWith("project.excludeFilters"))
        .takeWhile(line => !line.startsWith("]"))
        .flatMap(line => """"([^"]+)"""".r.findFirstMatchIn(line).map(_.group(1)))
        .toSet
      val present = ((root / "modules") ** "*.scala")
        .get()
        .filter(captureChecked)
        .map(file => root.toPath.relativize(file.toPath).toString.replace('\\', '/'))
        .toSet
      if (declared != present)
        sys.error(
          s"""|.scalafmt.conf's capture-checking exclusions are out of step with the sources:
              |  declared but not capture-checked: ${(declared -- present).toList.sorted.mkString(", ")}
              |  capture-checked but not declared: ${(present -- declared).toList.sorted.mkString(", ")}""".stripMargin
        )
    },
    LocalRootProject / checkCaptureEscapes := Def.uncached {
      implicit val converter: FileConverter = fileConverter.value

      val classpath = (LocalProject("kufuli") / Compile / fullClasspath).value.files
        .map(_.toAbsolutePath.toString)
        .mkString(java.io.File.pathSeparator)
      val loader = (LocalProject("kufuli") / scalaInstance).value.loaderCompilerOnly
      val work = (LocalRootProject / target).value / "capture-escapes"
      IO.delete(work)
      IO.createDirectory(work)

      val failures = escapes.zipWithIndex.flatMap { case ((label, body, expected), index) =>
        val source = work / s"escape$index.scala"
        val dest = work / s"escape$index-out"
        IO.write(source, escapeSource(body))
        IO.createDirectory(dest)
        assertEscape(label, expected, compileEscape(loader, classpath, dest, source))
      }
      if (failures.nonEmpty) sys.error(s"Capture-checking escape fixture failed:\n${failures.mkString("\n")}")
    }
  )

  // (label, source body, expected diagnostic fragment - empty means it must compile cleanly)
  private def escapes = List(
    ("shared-secret view returned", "def f(z: SharedSecret): UEff[Slice] = z.use(v => v)", "outlives its scope"),
    ("shared-secret view in a container", "def f(z: SharedSecret): UEff[List[Slice]] = z.use(v => List(v))", "outlives its scope"),
    ("re-sliced shared-secret view returned", "def f(z: SharedSecret): UEff[Slice] = z.use(v => v.take(2))", "outlives its scope"),
    ("prk view returned", "def f(p: PRK): UEff[Slice] = p.use(v => v)", "outlives its scope"),
    ("effect borrow returning the view", "def f(z: SharedSecret): UEff[Slice] = z.useEff(v => Eff.succeed(v))", "is boxed but"),
    ("effect borrow returning the view through IO", "def f(z: SharedSecret): UEff[Slice] = z.useEff(v => IO.pure(v))", "outlives its scope"),
    ("POSITIVE: a copy outlives the borrow", "def f(z: SharedSecret): UEff[List[Byte]] = z.use(v => v.toArray.toList)", "")
  )

  private def escapeSource(body: String) =
    s"""package kufuli.escape
       |import scala.language.experimental.captureChecking
       |import boilerplate.Slice
       |import boilerplate.effect.Eff
       |import boilerplate.effect.UEff
       |import cats.effect.IO
       |import kufuli.*
       |object CaptureEscape:
       |  $body
       |""".stripMargin

  // Diagnostics come back through the compiler's own SimpleReporter, not by capturing stdout: the
  // compiler loader has its own `scala.Console`, so redirection from here captures nothing.
  private def compileEscape(loader: ClassLoader, classpath: String, dest: File, source: File): String = {
    val module = loader.loadClass("dotty.tools.dotc.Main$").getField("MODULE$").get(null)
    val reporterClass = loader.loadClass("dotty.tools.dotc.interfaces.SimpleReporter")
    val callbackClass = loader.loadClass("dotty.tools.dotc.interfaces.CompilerCallback")
    val diagnosticClass = loader.loadClass("dotty.tools.dotc.interfaces.Diagnostic")
    val messageMethod = diagnosticClass.getMethod("message")
    val collected = new java.util.ArrayList[String]()
    val handler = new java.lang.reflect.InvocationHandler {
      def invoke(proxy: Object, method: java.lang.reflect.Method, args: Array[Object]): Object = {
        if (method.getName == "report") collected.add(String.valueOf(messageMethod.invoke(args(0))))
        null
      }
    }
    val reporter = java.lang.reflect.Proxy.newProxyInstance(loader, Array(reporterClass), handler)
    val process = module.getClass.getMethod("process", classOf[Array[String]], reporterClass, callbackClass)
    val args = Array("-classpath", classpath, "-d", dest.getAbsolutePath, source.getAbsolutePath)
    val _ = process.invoke(module, args, reporter, null)
    collected.toArray.mkString("\n")
  }

  private def assertEscape(label: String, expected: String, output: String): Option[String] =
    if (expected.isEmpty)
      if (output.trim.isEmpty) None else Some(s"  - $label: expected a clean compile, got:\n${output.take(600)}")
    else if (output.trim.isEmpty) Some(s"  - $label: expected the diagnostic to contain '$expected', but the compiler reported nothing")
    else if (output.contains(expected)) None
    else Some(s"  - $label: expected the diagnostic to contain '$expected', got:\n${output.take(600)}")
}
