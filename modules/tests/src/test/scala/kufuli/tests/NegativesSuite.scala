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

import scala.compiletime.testing.typeChecks

import kufuli.*

// The opaque tags are abstract here, so these compile-time rejections hold on every unit
// independent of instance presence.
class NegativesSuite extends munit.FunSuite:
  def aeadKey: SecretKey[AesGcm256] = ???
  def aeadKey128: SecretKey[AesGcm128] = ???
  def hmacKey: SecretKey[HmacSha256] = ???
  def macRing: Keyring[HmacSha256] = ???
  def xPriv: PrivateKey[X25519] = ???
  def edPriv: PrivateKey[Ed25519] = ???
  def edPub: PublicKey[Ed25519] = ???
  def p256Priv: PrivateKey[P256] = ???
  def p384Pub: PublicKey[P384] = ???
  def ecPub: PublicKey[P256] = ???
  def rsaPriv: PrivateKey[Rsa] = ???
  def box128: SealedBox[AesGcm128] = ???
  def p256Sig: Signature[P256] = ???
  def macTag: Signature[HmacSha256] = ???
  def kemPriv: PrivateKey[MlKem768] = ???
  def kemPub: PublicKey[MlKem768] = ???

  test("19 structural misuse patterns rejected at compile time") {
    assert(!typeChecks("aeadKey.sign(boilerplate.Slice.empty)"), "an AEAD key must not sign")
    assert(
      !typeChecks("aeadKey.encrypt(boilerplate.Slice.empty, boilerplate.Slice.empty, boilerplate.Slice.empty, boilerplate.Slice.empty)"),
      "record encrypt lives on the Cipher handle, never on the key"
    )
    assert(!typeChecks("hmacKey.seal(boilerplate.Slice.empty)"), "an HMAC key must not seal")
    assert(!typeChecks("macRing.seal(boilerplate.Slice.empty)"), "a MAC keyring must not seal")
    assert(!typeChecks("xPriv.sign(boilerplate.Slice.empty)"), "X25519 must not sign")
    assert(!typeChecks("edPriv.agree(edPub)"), "an Ed25519 key cannot agree")
    assert(!typeChecks("xPriv.agree(edPub)"), "X25519/Ed25519 are unrelated types")
    assert(!typeChecks("p256Priv.agree(p384Pub)"), "curve mismatch must not typecheck")
    assert(!typeChecks("ecPub.sign(boilerplate.Slice.empty)"), "a public key must not sign")
    assert(!typeChecks("p256Priv.sign(boilerplate.Slice.empty, Sha1)"), "Sha1 is outside Sha2")
    assert(!typeChecks("rsaPriv.sign(boilerplate.Slice.empty)"), "RSA signing requires an explicit padding scheme")
    assert(!typeChecks("aeadKey.open(box128)"), "a box sealed under another algorithm must not open")
    assert(!typeChecks("val k: SecretKey[AesGcm256] = aeadKey128"), "algorithm tags are invariant")
    assert(!typeChecks("edPub.verify(boilerplate.Slice.empty, p256Sig)"), "signature tags thread the family")
    assert(!typeChecks("edPub.verify(boilerplate.Slice.empty, macTag)"), "a MAC tag is not an Ed25519 signature")
    assert(!typeChecks("kemPriv.sign(boilerplate.Slice.empty)"), "a KEM key must not sign")
    assert(!typeChecks("kemPriv.agree(kemPub)"), "KEM is encapsulation, not agreement")
    assert(!typeChecks("ecPub.encapsulate"), "encapsulation exists only for KEM algorithms")
    assert(!typeChecks("aeadKey.raw"), "symmetric keys have no raw export")
  }
end NegativesSuite
