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

import kufuli.*

// Backend-independent value-layer checks over the shared code, so identical on every artifact
// including the browser.
class PureChecksSuite extends munit.FunSuite:

  test("nonce derivation (RFC 8446 s5.3): self-inverse; sequence lands big-endian in the low bytes") {
    val iv = Array.tabulate[Byte](12)(i => (0x10 + i).toByte)
    val n1 = new Array[Byte](12)
    Nonce.xorInto(Slice.of(iv), 1L, Slice.of(n1))
    val flip = iv.clone; flip(11) = (flip(11) ^ 0x01).toByte
    assert(Slice.of(n1).contentEquals(Slice.of(flip)), "seq 1 flips only the low byte")
    val n2 = new Array[Byte](12)
    Nonce.xorInto(Slice.of(iv), 0x0102030405060708L, Slice.of(n2))
    val expected = Array.tabulate[Byte](12)(i => if i < 4 then (0x10 + i).toByte else ((0x10 + i) ^ (i - 3)).toByte)
    assert(Slice.of(n2).contentEquals(Slice.of(expected)), "sequence lands big-endian")
    val n3 = new Array[Byte](12)
    Nonce.xorInto(Slice.of(n2), 0x0102030405060708L, Slice.of(n3))
    assert(Slice.of(n3).contentEquals(Slice.of(iv)), "xor self-inverse")
  }

  test("Base64Url (RFC 4648 s5, unpadded): vectors both directions, strict rejection") {
    val vectors =
      List("" -> "", "f" -> "Zg", "fo" -> "Zm8", "foo" -> "Zm9v", "foob" -> "Zm9vYg", "fooba" -> "Zm9vYmE", "foobar" -> "Zm9vYmFy")
    vectors.foreach { (plain, encoded) =>
      assertEquals(Base64Url.encode(plain.getBytes("US-ASCII")), encoded)
      assert(Base64Url.decode(encoded).exists(_.sameElements(plain.getBytes("US-ASCII"))))
    }
    assertEquals(Base64Url.encode(Array[Byte](-5, -16, 63)), "-_A_")
    assert(Base64Url.decode("Zg==").isLeft, "padded input rejected")
    assert(Base64Url.decode("a").isLeft, "length 4k+1 rejected")
    assert(Base64Url.decode("Zm+v").isLeft && Base64Url.decode("Zm/v").isLeft, "standard alphabet rejected")
    assert(Base64Url.decode("Zm9%").isLeft, "non-alphabet byte rejected")
  }

  test("PEM (RFC 7468): encode->decode round-trip, fullchain decodeAll, negatives") {
    val der = Array.tabulate[Byte](70)(i => (i * 7).toByte)
    val text = PEM.encode(PEM.Block("PUBLIC KEY", IArray.from(der)))
    assert(PEM.decode(text).exists(b => b.label == "PUBLIC KEY" && b.der.length == 70), "PEM round-trip")
    val two = text + "\n" + PEM.encode(PEM.Block("CERTIFICATE", IArray[Byte](1, 2, 3)))
    assert(PEM.decodeAll(two).exists(bs => bs.length == 2 && bs(1).label == "CERTIFICATE"), "decodeAll")
    assert(PEM.decode("-----BEGIN X-----\nAAAA").isLeft, "missing END rejected")
    assert(PEM.decode("-----BEGIN X-----\n!!!!\n-----END X-----").isLeft, "corrupt body rejected")
  }

  test("HkdfLabel (RFC 8446 s7.1) byte-exact layout") {
    val label = HKDF.hkdfLabel("key", Slice.empty, 16)
    val expected = Array[Byte](0x00, 0x10, 0x09) ++ "tls13 key".getBytes("US-ASCII") ++ Array[Byte](0x00)
    assert(label.contentEquals(Slice.of(expected)), "HkdfLabel byte layout")
  }

  test("key import validation carries diagnostics; parse-time everywhere") {
    val aesDiag = SecretKey.of(AesGcm256)(new Array[Byte](31)) match
      case Left(InvalidKey.WrongLength(32, 31)) => true
      case _                                    => false
    assert(aesDiag, "AES-256 length diagnostic")
    assert(SecretKey.of(HmacSha256)(new Array[Byte](16)).isLeft, "HMAC key below hash length rejected")
    assert(SecretKey.of(HmacSha256)(new Array[Byte](48)).isRight, "HMAC accepts longer keys")
    assert(Digest.of(new Array[Byte](15)).isLeft, "digest length validated")
    assert(SealedBox.of(AesGcm256)(new Array[Byte](5)).isLeft, "truncated box rejected")
    assert(SealedBox.of(AesGcm256)(Array.fill[Byte](64)(9)).isLeft, "unknown box version rejected")
    assert(Signature.fromRaw(Ed25519)(new Array[Byte](63)).isLeft, "ed25519 signature is 64 bytes")
    assert(Signature.fromRaw(P256)(new Array[Byte](64)).isRight, "P-256 raw r||s is 64 bytes")
    assertEquals(Signature.fromRaw(HmacSha256)(new Array[Byte](31)), Left(Malformed))
    assertEquals(KemCiphertext.of(MlKem768)(new Array[Byte](10)), Left(Malformed))
  }

  test("programmer-error domains are defects (require), not error values") {
    val _ = intercept[IllegalArgumentException](Rsa.bits(1024))
    val _ = intercept[IllegalArgumentException](AeadLimits(0, 1, 1))
  }

  test("ECDSA DER<->raw codec: round-trip, minimal integers, strict rejection") {
    // r||s where both halves have the high bit set (forces a 0x00 sign byte in DER)
    val raw = Array.tabulate[Byte](64)(i => if i == 0 || i == 32 then 0x80.toByte else (i + 1).toByte)
    val sig = Signature.fromRaw(P256)(raw).toOption.get
    val der = Array.from(sig.der.iterator)
    assertEquals(der(0), 0x30.toByte, "SEQUENCE tag")
    val back = Signature.fromDer(P256)(der).toOption.get
    assert(Array.from(back.bytes.iterator).sameElements(raw), "der -> raw round-trips")
    assert(Signature.fromDer(P256)(Array[Byte](0x30, 0x00)).isLeft, "empty integers rejected")
    assert(Signature.fromDer(P256)(Array.emptyByteArray).isLeft, "empty der rejected")
  }
end PureChecksSuite
