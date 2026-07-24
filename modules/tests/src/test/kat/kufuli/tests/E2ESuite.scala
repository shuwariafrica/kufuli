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
import cats.syntax.all.*

import kufuli.*
import kufuli.tests.support.*
import kufuli.unsafe.HeaderProtection

class E2ESuite extends munit.CatsEffectSuite:

  private def seal(cipher: Cipher[AesGcm256], iv: Array[Byte], seq: Long, plaintext: Array[Byte]): Array[Byte] =
    val nonce = Slice.of(new Array[Byte](12))
    Nonce.xorInto(Slice.of(iv), seq, nonce)
    val dst = Slice.of(new Array[Byte](plaintext.length + 16))
    val n = cipher.encrypt(dst, Slice.of(plaintext), Slice.empty, nonce).getOrElse(0)
    dst.take(n).toArray

  private def open(cipher: Cipher[AesGcm256], iv: Array[Byte], seq: Long, wire: Array[Byte]): Option[Array[Byte]] =
    val nonce = Slice.of(new Array[Byte](12))
    Nonce.xorInto(Slice.of(iv), seq, nonce)
    val dst = Slice.of(new Array[Byte](wire.length))
    cipher.decrypt(dst, Slice.of(wire), Slice.empty, nonce).toOption.map(n => dst.take(n).toArray)

  private def derive(secret: Slice, label: String): IO[SecretKey[AesGcm256]] =
    HKDF.expandLabelKey(Sha256, Prk.unsafe(secret.toArray), label, Slice.empty, AesGcm256).absolve

  test("TLS/QUIC-shaped E2E: hybrid agree -> extract -> expandLabel -> records both ways -> HP mask -> key update") {
    for
      xc <- X25519.generate.absolve
      xs <- X25519.generate.absolve
      kem <- MlKem768.generate.absolve
      xShared <- xc.privateKey.agree(xs.publicKey).absolve
      enc <- kem.publicKey.encapsulate.absolve
      kShared <- kem.privateKey.decapsulate(enc.ciphertext).absolve
      xa <- xShared.use(_.toArray).absolve
      kaSend <- enc.secret.use(_.toArray).absolve
      kaRecv <- kShared.use(_.toArray).absolve
      _ <- check(kaSend.sameElements(kaRecv), "KEM shared secret agrees across the wire")
      prk <- HKDF.extract(Sha256, Slice.of(new Array[Byte](32)), Slice.of(xa ++ kaSend)).absolve
      cSecret <- HKDF.expandLabel(Sha256, prk, "c ap traffic", Slice.empty, 32).absolve
      sSecret <- HKDF.expandLabel(Sha256, prk, "s ap traffic", Slice.empty, 32).absolve
      cIv <- HKDF.expandLabel(Sha256, prk, "c iv", Slice.empty, 12).absolve
      sIv <- HKDF.expandLabel(Sha256, prk, "s iv", Slice.empty, 12).absolve
      hpKey <- HKDF.expandLabel(Sha256, prk, "c hp", Slice.empty, 16).absolve
      cKey <- derive(cSecret, "key")
      sKey <- derive(sSecret, "key")
      records <- (cKey.cipher, cKey.cipher, sKey.cipher, sKey.cipher).tupled.use { (cWrite, cRead, sWrite, sRead) =>
                   IO {
                     val c0 = seal(cWrite, cIv.toArray, 0L, "client-hello-0".getBytes)
                     val c1 = seal(cWrite, cIv.toArray, 1L, "client-hello-1".getBytes)
                     val s0 = seal(sWrite, sIv.toArray, 0L, "server-hello-0".getBytes)
                     val forged = c0.updated(c0.length - 1, (c0(c0.length - 1) ^ 0x01).toByte)
                     (
                       open(cRead, cIv.toArray, 0L, c0),
                       open(cRead, cIv.toArray, 1L, c1),
                       open(sRead, sIv.toArray, 0L, s0),
                       open(cRead, cIv.toArray, 0L, forged),
                       c0
                     )
                   }
                 }
      (r0, r1, rs0, rForged, sample) = records
      _ <- check(r0.exists(p => new String(p) == "client-hello-0"), "c->s record 0 round-trips")
      _ <- check(r1.exists(p => new String(p) == "client-hello-1"), "c->s record 1 round-trips (seq nonce)")
      _ <- check(rs0.exists(p => new String(p) == "server-hello-0"), "s->c record 0 round-trips")
      _ <- check(rForged.isEmpty, "a tampered record is rejected")
      mask <- HeaderProtection
                .aes(hpKey.toArray)
                .use(hp =>
                  IO {
                    val m = new Array[Byte](5)
                    hp.mask(Slice.of(sample ++ new Array[Byte](16)), Slice.of(m))
                    m
                  }
                )
      _ <- check(mask.exists(_ != 0), "a QUIC header-protection mask was produced")
      cNextSecret <- HKDF.expandLabel(Sha256, Prk.unsafe(cSecret.toArray), "traffic upd", Slice.empty, 32).absolve
      cKeyGen1 <- derive(cNextSecret, "key")
      rekeyed <- (cKey.cipher, cKeyGen1.cipher).tupled.use { (before, after) =>
                   IO(seal(before, cIv.toArray, 0L, "same".getBytes).sameElements(seal(after, cIv.toArray, 0L, "same".getBytes)))
                 }
      _ <- check(!rekeyed, "a proactive key update rekeys the direction")
    yield ()
  }
end E2ESuite
