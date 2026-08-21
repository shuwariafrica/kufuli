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
package kufuli.tests

import boilerplate.Slice
import boilerplate.effect.*
import cats.effect.IO

import kufuli.*
import kufuli.tests.support.*

class BudgetSuite extends munit.CatsEffectSuite:

  private def nonce(b: Byte): Slice = Slice.of(Array[Byte](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b))

  test("AeadLimits: key.cipher applies the algorithm's per-algorithm default budget") {
    for
      gcm <- AesGcm256.generate.absolve
      gb <- gcm.cipher.use(c => IO.pure(c.budget)).absolve
      _ <- check(gb == AeadBudget(1L << 32, 1L << 50, 1L << 36), "aes-gcm 96-bit-nonce default (SP 800-38D)")
      cha <- ChaCha20Poly1305.generate.absolve
      cb <- cha.cipher.use(c => IO.pure(c.budget)).absolve
      _ <- check(cb == AeadBudget(1L << 62, 1L << 62, 1L << 36), "chacha20 confidentiality default (RFC 9001)")
    yield ()
  }

  test("Cipher budget: encrypt spends invocations+bytes; decrypt spends only failures; exhaustion is typed") {
    val aad = Slice.of("aad".getBytes)
    val src = Slice.of("hello".getBytes)
    for
      key <- AesGcm256.generate.absolve
      enc <- key
               .cipher(AeadLimits(encryptions = 2, bytes = 1L << 20, decryptFailures = 2))
               .use { c =>
                 IO {
                   val dst = Slice.of(new Array[Byte](64))
                   val a = c.encrypt(dst, src, aad, nonce(1)).isRight
                   val b = c.encrypt(dst, src, aad, nonce(2)).isRight
                   val after = c.budget
                   val third = c.encrypt(dst, src, aad, nonce(3))
                   (a, b, after, third)
                 }
               }
               .absolve
      _ <- check(enc._1 && enc._2, "two encrypts within budget")
      _ <- check(enc._3.encryptions == 0 && enc._3.bytes == (1L << 20) - 10, "invocations and bytes both charged")
      _ <- check(enc._4 match
                   case Left(BudgetExhausted) => true;
                   case _                     => false
                 ,
                 "third encrypt -> BudgetExhausted"
           )
      dec <- key
               .cipher(AeadLimits(2, 1L << 20, 2))
               .use { c =>
                 IO {
                   val dst = Slice.of(new Array[Byte](64))
                   val forged = Slice.of(new Array[Byte](21)) // 5-byte ciphertext + 16-byte tag
                   val f1 = c.decrypt(dst, forged, aad, nonce(1)).isLeft
                   val f2 = c.decrypt(dst, forged, aad, nonce(2)).isLeft
                   val after = c.budget
                   val f3 = c.decrypt(dst, forged, aad, nonce(3))
                   (f1, f2, after, f3)
                 }
               }
               .absolve
      _ <- check(dec._1 && dec._2, "two forged opens fail")
      _ <- check(dec._3.encryptions == 2 && dec._3.decryptFailures == 0, "only the forgery budget was charged")
      _ <- check(dec._4 match
                   case Left(BudgetExhausted) => true;
                   case _                     => false
                 ,
                 "third decrypt -> BudgetExhausted"
           )
    yield ()
    end for
  }

  test("a forged record leaves no unauthenticated plaintext in the caller's buffer") {
    // The engines decrypt before they authenticate, and a `Left` carries no length to tell a caller
    // the buffer was touched at all - so a consumer reusing one record buffer would otherwise find
    // attacker-chosen plaintext there after every forgery. The three backends reach the guarantee
    // differently (the JVM erases, aws-lc erases by its own contract, node never copies out), so
    // what is asserted is the guarantee itself: every octet is still either the caller's own fill
    // or an erasure, and none of them is this record's plaintext.
    val aad = Slice.of("aad".getBytes)
    val fill = 1.toByte
    // A full TLS-sized record, with every octet outside {0, fill} so a leak cannot pass as either.
    val plaintext = Slice.of(Array.tabulate[Byte](1300)(i => (100 + (i % 100)).toByte))
    for
      key <- AesGcm256.generate.absolve
      seen <- key.cipher.use { c =>
                IO {
                  val dst = Slice.of(Array.fill[Byte](1400)(fill))
                  val n = c.encrypt(dst, plaintext, aad, nonce(1)).toOption.get
                  val forged = Slice.of(dst.take(n).toArray)
                  forged(0) = (forged(0) ^ 0xff).toByte
                  val out = Slice.of(Array.fill[Byte](1400)(fill))
                  val verdict = c.decrypt(out, forged, aad, nonce(2))
                  (verdict = verdict.isLeft, residue = out.take(plaintext.length).toArray)
                }
              }.absolve
      _ <- check(seen.verdict, "a forged record is rejected")
      _ <- check(
             seen.residue.forall(b => b == 0.toByte || b == fill),
             s"and no plaintext reaches the buffer, got ${seen.residue.count(b => b != 0.toByte && b != fill)} foreign octets"
           )
    yield ()
    end for
  }

end BudgetSuite
