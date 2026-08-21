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
import boilerplate.effect.EffResource
import cats.effect.IO
import cats.effect.Resource

// The per-key engines the platform seams supply. Header protection runs ONCE PER PACKET on the loop
// thread, so the key schedule and any provider lookup belong in the resource rather than in the
// call: on JDK 25 a fresh `Cipher.getInstance` per packet cost 3040 ns against 24 ns for a prepared
// instance. Each engine owns a copy of the key and erases it at release, so the caller's array is
// the caller's to wipe as soon as the resource is allocated.
private[unsafe] trait AesBlockEngine:
  def encrypt(src: Slice, dst: Slice): Unit
  def release(): Unit

private[unsafe] trait ChaCha20Engine:
  def keystream(dst: Slice, nonce: Slice, counter: Int): Unit
  def release(): Unit

/** Raw AES-ECB single block (the QUIC AES header-protection primitive). Exactly 16 bytes. */
trait AesBlock:
  def encrypt(src: Slice, dst: Slice): Unit
object AesBlock:
  def of(key: Array[Byte]): EffResource[Nothing, AesBlock] =
    require(key.length == 16 || key.length == 24 || key.length == 32, "AES key must be 16/24/32 bytes")
    Resource
      .make(IO(aesBlockEngine(key)))(e => IO(e.release()))
      .map(e =>
        new AesBlock:
          def encrypt(src: Slice, dst: Slice): Unit =
            require(src.length == 16 && dst.length >= 16, "AES block is 16 bytes")
            e.encrypt(src, dst)
      )

/** Raw ChaCha20 keystream (the QUIC ChaCha header-protection primitive). */
trait ChaCha20Stream:
  def keystream(dst: Slice, nonce: Slice, counter: Int): Unit
object ChaCha20:
  def of(key: Array[Byte]): EffResource[Nothing, ChaCha20Stream] =
    require(key.length == 32, "ChaCha20 key must be 32 bytes")
    Resource
      .make(IO(chacha20Engine(key)))(e => IO(e.release()))
      .map(e =>
        new ChaCha20Stream:
          def keystream(dst: Slice, nonce: Slice, counter: Int): Unit =
            require(nonce.length == 12, "ChaCha20 nonce must be 12 bytes")
            e.keystream(dst, nonce, counter)
      )

/** QUIC header protection: the 5-byte mask from a 16-byte ciphertext sample (RFC 9001 section 5.4).
  * Applying the mask (first-byte/packet-number bit surgery) is protocol logic and stays downstream;
  * so do QUIC version constants.
  *
  * A handle is SINGLE-FIBRE, like the record [[kufuli.Cipher]] and for the same reason: it holds
  * one engine and one scratch block, which interleaved calls corrupt. Acquire one per connection.
  */
trait HeaderProtection:
  def mask(sample: Slice, out: Slice): Unit // writes 5 bytes at out's start
object HeaderProtection:
  def aes(hpKey: Array[Byte]): EffResource[Nothing, HeaderProtection] =
    AesBlock
      .of(hpKey)
      .map(block =>
        new HeaderProtection:
          // One block per handle rather than one per packet: the AES output is 16 bytes and the mask
          // is the first five, so the scratch cannot be the caller's own five-byte buffer.
          private val full = Slice.of(new Array[Byte](16))
          def mask(sample: Slice, out: Slice): Unit =
            require(sample.length >= 16 && out.length >= 5, "sample 16 bytes; mask 5 bytes")
            block.encrypt(sample.take(16), full)
            val _ = full.take(5).copyInto(out)
      )
  def chacha(hpKey: Array[Byte]): EffResource[Nothing, HeaderProtection] =
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
