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
package kufuli.unsafe

import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec

import boilerplate.Slice

private[unsafe] def aesBlockEncrypt(key: Array[Byte], src: Slice, dst: Slice): Unit =
  val cipher = Cipher.getInstance("AES/ECB/NoPadding")
  cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
  val _ = Slice.of(cipher.doFinal(src.take(16).toArray)).copyInto(dst)

private[unsafe] def chacha20Keystream(key: Array[Byte], dst: Slice, nonce: Slice, counter: Int): Unit =
  // A fresh instance each call: JCA rejects re-initialising its ChaCha20 engine with a repeated key+nonce.
  val cipher = Cipher.getInstance("ChaCha20")
  cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20ParameterSpec(nonce.toArray, counter))
  val _ = Slice.of(cipher.doFinal(new Array[Byte](dst.length))).copyInto(dst)
