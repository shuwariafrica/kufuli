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

class RealVectorSuite extends munit.CatsEffectSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"$x%02x").mkString
  private def hb(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  test("SHA-256(\"abc\") == the FIPS 180-4 digest") {
    Sha256.digest(Slice.of("abc".getBytes)).absolve.flatMap { d =>
      check(d.hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256")
    }
  }

  test("SHA-512(\"abc\") == the FIPS 180-4 digest") {
    Sha512.digest(Slice.of("abc".getBytes)).absolve.flatMap { d =>
      check(
        d.hex == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "sha512"
      )
    }
  }

  test("HKDF-SHA256 (RFC 5869 A.1): PRK and OKM - also anchors HMAC-SHA256") {
    for
      prk <- HKDF.extract(Sha256, Slice.of(hb("000102030405060708090a0b0c")), Slice.of(Array.fill(22)(0x0b.toByte))).absolve
      prkHex <- prk.use(s => hex(s.toArray)).absolve
      _ <- check(prkHex == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "PRK")
      okm <- HKDF.expand(Sha256, prk, Slice.of(hb("f0f1f2f3f4f5f6f7f8f9")), 42).absolve
      _ <- check(
             hex(okm.toArray) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
             "OKM"
           )
    yield ()
  }

  test("PBKDF2-HMAC-SHA256 (RFC 7914 s11): password/salt/4096/32") {
    PBKDF2.derive(Sha256, Slice.of("password".getBytes), Slice.of("salt".getBytes), 4096, 32).absolve.flatMap { dk =>
      check(hex(dk.toArray) == "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", "pbkdf2")
    }
  }

  test("AES-KW (RFC 3394 s4.1): a 128-bit KEK wraps a 128-bit key to the published output") {
    val kek = SecretKey.of(AesKw128)(hb("000102030405060708090a0b0c0d0e0f")).toOption.get
    val target = SecretKey.of(AesGcm128)(hb("00112233445566778899aabbccddeeff")).toOption.get
    kek.wrap(target).absolve.flatMap { wrapped =>
      check(hex(wrapped.toArray) == "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", "aes-kw rfc3394 4.1")
    }
  }

  test("Ed25519 (RFC 8032 s7.1 TEST 1): the published key verifies the published signature") {
    val pub = hb("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    val sig = hb(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    for
      key <- expectRight("import ed pub")(PublicKey.fromRaw(Ed25519)(Slice.of(pub)))
      good = Signature.fromRaw(Ed25519)(sig).toOption.get
      ok <- key.verify(Slice.empty, good).either
      _ <- check(ok == Right(()), "ed25519 rfc8032 verify")
      bad = Signature.fromRaw(Ed25519)(sig.updated(0, (sig(0) ^ 1).toByte)).toOption.get
      rej <- key.verify(Slice.empty, bad).either
      _ <- check(rej.isLeft, "tampered ed25519 rejected")
    yield ()
  }
end RealVectorSuite
