import sbt.VirtualAxis

/** Virtual axis distinguishing the Web Crypto (browser) JS row from default Node.js. Use
  * [[VirtualAxis.WeakAxis]] so a browser row may depend on an axis-less upstream row. `suffixOrder`
  * is 90 - after the `js` platform axis (80) and before the Scala-version axis (100).
  */
case object WebCryptoAxis extends VirtualAxis.WeakAxis {
  override val idSuffix: String = "-browser"
  override val directorySuffix: String = "browser"
  override val suffixOrder: Int = 90
}
