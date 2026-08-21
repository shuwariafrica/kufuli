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

import boilerplate.Slice

import kufuli.nodecrypto.ba
import kufuli.nodecrypto.crypto
import kufuli.nodecrypto.u8
import kufuli.nodecrypto.zero

private[unsafe] def aesBlockEngine(key: Array[Byte]): AesBlockEngine =
  new AesBlockEngine:
    // node builds its cipher state per `createCipheriv`, so there is no context to hold across
    // packets; the key buffer is what the handle owns, and it is zeroed at release.
    private val kb = u8(key)
    private val zeroIv = u8(new Array[Byte](16))
    private val name = s"aes-${key.length * 8}-cbc" // node's ECB needs a null IV, which lint forbids
    def encrypt(src: Slice, dst: Slice): Unit =
      val cipher = crypto.createCipheriv(name, kb, zeroIv)
      val _ = cipher.setAutoPadding(false)
      val out = ba(cipher.update(u8(src.take(16).toArray))) ++ ba(cipher.`final`())
      val _ = Slice.of(out).copyInto(dst)
    def release(): Unit = zero(kb)

private[unsafe] def chacha20Engine(key: Array[Byte]): ChaCha20Engine =
  new ChaCha20Engine:
    private val kb = u8(key)
    def keystream(dst: Slice, nonce: Slice, counter: Int): Unit =
      // node's `chacha20` IV is a 32-bit little-endian counter followed by the 96-bit nonce (RFC 8439).
      val iv = new Array[Byte](16)
      iv(0) = counter.toByte
      iv(1) = (counter >>> 8).toByte
      iv(2) = (counter >>> 16).toByte
      iv(3) = (counter >>> 24).toByte
      val _ = nonce.copyInto(Slice.of(iv).drop(4))
      val cipher = crypto.createCipheriv("chacha20", kb, u8(iv))
      val out = ba(cipher.update(u8(new Array[Byte](dst.length)))) ++ ba(cipher.`final`())
      val _ = Slice.of(out).copyInto(dst)
    def release(): Unit = zero(kb)
