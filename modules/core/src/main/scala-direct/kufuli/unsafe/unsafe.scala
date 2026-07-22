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
// The expert floor: raw primitives with no misuse-resistance - every invariant is the caller's.
// Absent from the browser artifact.
package kufuli.unsafe

import boilerplate.Slice
import cats.effect.IO
import cats.effect.Resource

/** Raw AES-ECB single block (the QUIC AES header-protection primitive). Exactly 16 bytes. */
trait AesBlock:
  def encrypt(src: Slice, dst: Slice): Unit
object AesBlock:
  def of(key: Array[Byte]): Resource[IO, AesBlock] =
    require(key.length == 16 || key.length == 24 || key.length == 32, "AES key must be 16/24/32 bytes")
    Resource.pure(
      new AesBlock:
        def encrypt(src: Slice, dst: Slice): Unit =
          require(src.length == 16 && dst.length >= 16, "AES block is 16 bytes")
          aesBlockEncrypt(key, src, dst)
    )

/** Raw ChaCha20 keystream (the QUIC ChaCha header-protection primitive). */
trait ChaCha20Stream:
  def keystream(dst: Slice, nonce: Slice, counter: Int): Unit
object ChaCha20:
  def of(key: Array[Byte]): Resource[IO, ChaCha20Stream] =
    require(key.length == 32, "ChaCha20 key must be 32 bytes")
    Resource.pure(
      new ChaCha20Stream:
        def keystream(dst: Slice, nonce: Slice, counter: Int): Unit =
          require(nonce.length == 12, "ChaCha20 nonce must be 12 bytes")
          chacha20Keystream(key, dst, nonce, counter)
    )

/** QUIC header protection: the 5-byte mask from a 16-byte ciphertext sample (RFC 9001 section 5.4).
  * Applying the mask (first-byte/packet-number bit surgery) is protocol logic and stays downstream;
  * so do QUIC version constants.
  */
trait HeaderProtection:
  def mask(sample: Slice, out: Slice): Unit // writes 5 bytes at out's start
object HeaderProtection:
  def aes(hpKey: Array[Byte]): Resource[IO, HeaderProtection] =
    AesBlock
      .of(hpKey)
      .map(block =>
        new HeaderProtection:
          def mask(sample: Slice, out: Slice): Unit =
            require(sample.length >= 16 && out.length >= 5, "sample 16 bytes; mask 5 bytes")
            val full = Slice.of(new Array[Byte](16))
            block.encrypt(sample.take(16), full)
            val _ = full.take(5).copyInto(out)
      )
  def chacha(hpKey: Array[Byte]): Resource[IO, HeaderProtection] =
    ChaCha20
      .of(hpKey)
      .map(stream =>
        new HeaderProtection:
          def mask(sample: Slice, out: Slice): Unit =
            require(sample.length >= 16 && out.length >= 5, "sample 16 bytes; mask 5 bytes")
            // RFC 9001 section 5.4.4.
            val counter =
              (sample(0) & 0xff) | ((sample(1) & 0xff) << 8) | ((sample(2) & 0xff) << 16) | ((sample(3) & 0xff) << 24)
            stream.keystream(out.take(5), sample.slice(4, 16), counter)
      )
end HeaderProtection
