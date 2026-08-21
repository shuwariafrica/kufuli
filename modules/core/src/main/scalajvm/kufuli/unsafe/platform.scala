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

private[unsafe] def aesBlockEngine(key: Array[Byte]): AesBlockEngine =
  new AesBlockEngine:
    private val kb = key.clone
    private val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kb, "AES"))
    // ECB with no padding leaves the engine in its post-init state after each `doFinal`, so one
    // instance serves the connection: the provider lookup and key schedule do not repeat per packet.
    def encrypt(src: Slice, dst: Slice): Unit =
      val _ = cipher.doFinal(src.unsafeArray, src.unsafeOffset, 16, dst.unsafeArray, dst.unsafeOffset)
    def release(): Unit = Slice.of(kb).wipe()

private[unsafe] def chacha20Engine(key: Array[Byte]): ChaCha20Engine =
  new ChaCha20Engine:
    private val kb = key.clone
    private val jk = new SecretKeySpec(kb, "ChaCha20")
    // A fresh instance each call, unlike the AES engine above: JCA refuses to re-initialise its
    // ChaCha20 engine with the key, nonce and counter it was last given, and a keystream is a pure
    // function of those - a receiver unmasking a header its sender masked recomputes exactly that.
    // The provider lookup therefore stays per call here; header protection under the AES suites,
    // which is the default, does not pay it.
    def keystream(dst: Slice, nonce: Slice, counter: Int): Unit =
      val cipher = Cipher.getInstance("ChaCha20")
      cipher.init(Cipher.ENCRYPT_MODE, jk, new ChaCha20ParameterSpec(nonce.toArray, counter))
      val zeros = new Array[Byte](dst.length)
      val _ = cipher.doFinal(zeros, 0, zeros.length, dst.unsafeArray, dst.unsafeOffset)
    def release(): Unit = Slice.of(kb).wipe()
