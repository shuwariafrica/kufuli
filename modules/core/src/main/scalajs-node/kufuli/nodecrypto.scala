/*
 * Copyright (c) 2026 Ali Rashid.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
// Typed facades over `node:crypto` via its default export (the CommonJS module object). `u8`/`ba`
// are the sole byte-copy points; they honour the `byteOffset` a pooled node `Buffer` view may carry.
package kufuli

import scala.scalajs.js
import scala.scalajs.js.annotation.JSImport
import scala.scalajs.js.typedarray.Int8Array
import scala.scalajs.js.typedarray.Uint8Array
import scala.scalajs.js.typedarray.byteArray2Int8Array
import scala.scalajs.js.typedarray.int8Array2ByteArray

private[kufuli] object nodecrypto:

  @js.native
  @JSImport("node:crypto", JSImport.Default)
  private[kufuli] object crypto extends js.Object:
    def randomFillSync(buffer: Uint8Array): Uint8Array = js.native
    def createHash(algorithm: String): NodeHash = js.native
    def createHmac(algorithm: String, key: Uint8Array): NodeHmac = js.native
    def createCipheriv(algorithm: String, key: Uint8Array, iv: Uint8Array): NodeCipher = js.native
    def createDecipheriv(algorithm: String, key: Uint8Array, iv: Uint8Array): NodeCipher = js.native
    def createCipheriv(algorithm: String, key: Uint8Array, iv: Uint8Array, options: js.Any): NodeCipher = js.native
    def createDecipheriv(algorithm: String, key: Uint8Array, iv: Uint8Array, options: js.Any): NodeCipher = js.native
    def createPublicKey(key: js.Any): KeyObject = js.native
    def createPrivateKey(key: js.Any): KeyObject = js.native
    def generateKeyPair(`type`: String, options: js.Any, callback: js.Function3[js.Error | Null, KeyObject, KeyObject, Unit]): Unit =
      js.native
    def sign(algorithm: js.UndefOr[String], data: Uint8Array, key: js.Any): Uint8Array = js.native
    def verify(algorithm: js.UndefOr[String], data: Uint8Array, key: js.Any, signature: Uint8Array): Boolean = js.native
    def diffieHellman(options: js.Any): Uint8Array = js.native
    def publicEncrypt(key: js.Any, buffer: Uint8Array): Uint8Array = js.native
    def privateDecrypt(key: js.Any, buffer: Uint8Array): Uint8Array = js.native
    def pbkdf2(
      password: Uint8Array,
      salt: Uint8Array,
      iterations: Int,
      keylen: Int,
      digest: String,
      callback: js.Function2[js.Error | Null, Uint8Array, Unit]): Unit = js.native
    def encapsulate(publicKey: KeyObject): Encapsulation = js.native
    def decapsulate(privateKey: KeyObject, ciphertext: Uint8Array): Uint8Array = js.native
    val constants: Constants = js.native
  end crypto

  @js.native
  private[kufuli] trait NodeHash extends js.Object:
    def update(data: Uint8Array): NodeHash = js.native
    def copy(): NodeHash = js.native
    def digest(): Uint8Array = js.native

  @js.native
  private[kufuli] trait NodeHmac extends js.Object:
    def update(data: Uint8Array): NodeHmac = js.native
    def digest(): Uint8Array = js.native

  @js.native
  private[kufuli] trait NodeCipher extends js.Object:
    def update(data: Uint8Array): Uint8Array = js.native
    def `final`(): Uint8Array = js.native
    def setAAD(aad: Uint8Array): Unit = js.native
    def setAutoPadding(pad: Boolean): Unit = js.native
    def getAuthTag(): Uint8Array = js.native
    def setAuthTag(tag: Uint8Array): Unit = js.native

  @js.native
  private[kufuli] trait KeyObject extends js.Object:
    def `export`(options: js.Any): Uint8Array = js.native
    val asymmetricKeyType: js.UndefOr[String] = js.native
    val asymmetricKeyDetails: js.UndefOr[KeyDetails] = js.native

  @js.native
  private[kufuli] trait KeyDetails extends js.Object:
    val namedCurve: js.UndefOr[String] = js.native

  @js.native
  private trait NodeError extends js.Object:
    val code: js.UndefOr[String] = js.native

  @js.native
  private[kufuli] trait Encapsulation extends js.Object:
    val sharedKey: Uint8Array = js.native
    val ciphertext: Uint8Array = js.native

  @js.native
  private[kufuli] trait Constants extends js.Object:
    val RSA_PKCS1_PSS_PADDING: Int = js.native
    val RSA_PKCS1_OAEP_PADDING: Int = js.native
    val RSA_PSS_SALTLEN_DIGEST: Int = js.native

  private[kufuli] def u8(a: Array[Byte]): Uint8Array =
    val i8 = byteArray2Int8Array(a)
    new Uint8Array(i8.buffer, i8.byteOffset, i8.length)

  private[kufuli] def ba(u: Uint8Array): Array[Byte] =
    int8Array2ByteArray(new Int8Array(u.buffer, u.byteOffset, u.length))

  private[kufuli] def zero(u: Uint8Array): Unit = (0 until u.length).foreach(i => u(i) = 0.toShort)

  /** The `code` node attaches to a thrown error, which is how its failure taxonomy is read. */
  private[kufuli] def errorCode(e: js.JavaScriptException): Option[String] = e.exception match
    case o: js.Object => dynamic(o).code.toOption
    case _            => None

  // A property JS attaches at runtime has no statically-typed accessor; the cast is the read.
  private def dynamic(o: js.Object): NodeError = o.asInstanceOf[NodeError] // scalafix:ok DisableSyntax.asInstanceOf
end nodecrypto
