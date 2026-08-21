import sbt.*
import sbt.Keys.*

/** Embeds Wycheproof JSON test vector files as string constants in generated Scala source, enabling
  * cross-platform (JVM, JS, Native) test vector consumption.
  *
  * Enable on a project, then configure:
  * {{{
  * .enablePlugins(WycheproofPlugin)
  * .settings(
  *   wycheproofTargetPackage := "my.package.wycheproof",
  *   wycheproofVectorFiles := Seq("hmac_sha256_test.json", ...)
  * )
  * }}}
  *
  * Vectors are read from the `vendor/wycheproof` git submodule. Contributors must initialise it
  * once with `git submodule update --init vendor/wycheproof` (or clone with `--recursive`). For
  * each listed `.json` file, generates a Scala object containing the raw JSON as a string constant.
  * Suites parse this at runtime via jsoniter-scala `readFromString`.
  */
object WycheproofPlugin extends AutoPlugin:

  object autoImport:
    val wycheproofVectorFiles = settingKey[Seq[String]](
      "List of JSON filenames to embed from the Wycheproof testvectors_v1/ directory."
    )
    val wycheproofTargetPackage = settingKey[String](
      "Scala package for generated vector objects."
    )
    val wycheproofGenerate = taskKey[Seq[File]](
      "Generates Scala source files embedding Wycheproof JSON vectors."
    )

  import autoImport.*

  override def trigger = noTrigger

  override def requires = plugins.JvmPlugin

  override def projectSettings: Seq[Setting[?]] = Seq(
    wycheproofVectorFiles := Seq.empty,
    wycheproofTargetPackage := "wycheproof"
  ) ++ ProjectExtra.inConfig(Test)(
    Seq(
      wycheproofGenerate := Def.uncached {
        val files = wycheproofVectorFiles.value
        val targetPkg = wycheproofTargetPackage.value
        val outDir = sourceManaged.value / "wycheproof"
        val log = streams.value.log
        val cacheDir = streams.value.cacheDirectory / "wycheproof"
        val rootDir = (LocalRootProject / baseDirectory).value
        val vectorDir = rootDir / "vendor" / "wycheproof" / "testvectors_v1"

        if files.isEmpty then Seq.empty[File]
        else
          if !vectorDir.isDirectory then
            sys.error(
              s"Wycheproof submodule not initialised at $vectorDir. Run: git submodule update --init vendor/wycheproof"
            )

          IO.createDirectory(outDir)
          files.map { filename =>
            val jsonFile = vectorDir / filename
            if !jsonFile.exists() then sys.error(s"Wycheproof vector file not found: $jsonFile")

            val objectName = filenameToObjectName(filename)
            val outFile = outDir / s"$objectName.scala"
            val tempFile = cacheDir / s"$objectName.scala"

            // Generate to temp, then copy only if content changed (avoids needless recompilation)
            IO.createDirectory(cacheDir)
            val content = IO.read(jsonFile)
            val scalaSource = renderSource(targetPkg, objectName, filename, content)
            IO.write(tempFile, scalaSource, IO.utf8)

            val changed = !outFile.exists() || !IO.readBytes(outFile).sameElements(IO.readBytes(tempFile))
            if changed then
              log.info(s"WycheproofPlugin: generating $objectName from $filename")
              IO.copyFile(tempFile, outFile, preserveLastModified = true)
            outFile
          }
        end if
      },
      sourceGenerators += wycheproofGenerate.taskValue
    )
  )

  // A class file's constant pool caps a UTF8 entry at 65535 bytes, so a large vector is split into
  // chunks concatenated at runtime; 60000 leaves a conservative margin.
  private val MaxChunkBytes = 60000

  private def renderSource(pkg: String, objectName: String, filename: String, jsonContent: String): String =
    val escaped = escapeTripleQuote(jsonContent)
    if escaped.getBytes("UTF-8").length <= MaxChunkBytes then s"""|package $pkg
                                                                  |
                                                                  |/** Generated from `$filename`. Do not edit. */
                                                                  |object $objectName:
                                                                  |  val json: String = ${"\"\"\""}$escaped${"\"\"\""}
                                                                  |""".stripMargin
    else
      val chunks = splitByByteLimit(escaped, MaxChunkBytes)
      val sb = new StringBuilder
      sb.append(s"package $pkg\n\n")
      sb.append(s"/** Generated from `$filename`. Do not edit. */\n")
      sb.append(s"object $objectName:\n")
      sb.append(s"  val json: String =\n")
      sb.append(s"    val sb = new StringBuilder(${jsonContent.length})\n")
      chunks.zipWithIndex.foreach { case (chunk, _) =>
        sb.append(s"""    sb.append(${"\"\"\""}$chunk${"\"\"\""})\n""")
      }
      sb.append(s"    sb.result()\n")
      sb.result()
    end if
  end renderSource

  // hmac_sha256_test.json -> HmacSha256TestJson
  private def filenameToObjectName(filename: String): String =
    val base = filename.stripSuffix(".json")
    base
      .split("[_\\-]")
      .map(segment => segment.take(1).toUpperCase + segment.drop(1))
      .mkString + "Json"

  private def escapeTripleQuote(s: String): String =
    s.replace("\"\"\"", "\\\"\\\"\\\"")

  private def splitByByteLimit(s: String, maxBytes: Int): Seq[String] =
    val result = Vector.newBuilder[String]
    val current = new StringBuilder
    var currentBytes = 0
    var i = 0
    while i < s.length do
      val c = s.charAt(i)
      val charBytes = if c <= 0x7f then 1 else if c <= 0x7ff then 2 else 3
      if currentBytes + charBytes > maxBytes && current.nonEmpty then
        result += current.result()
        current.clear()
        currentBytes = 0
      current.append(c)
      currentBytes += charBytes
      i += 1
    if current.nonEmpty then result += current.result()
    result.result()
  end splitByByteLimit
end WycheproofPlugin
