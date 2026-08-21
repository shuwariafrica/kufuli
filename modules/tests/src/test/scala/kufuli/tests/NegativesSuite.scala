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
  def rsaPriv: PrivateKey[RSA] = ???
  def box128: SealedBox[AesGcm128] = ???
  def p256Sig: Signature[P256] = ???
  def macTag: Signature[HmacSha256] = ???
  def kemPriv: PrivateKey[MlKem768] = ???
  def kemPub: PublicKey[MlKem768] = ???

  // Every negative below rejects for a REASON, and a rename would make it reject for another one.
  // These are the paired positives: each names the same member on the type that is entitled to it,
  // so a suite that still passes after `sign`, `seal`, `agree`, `open`, `verify`, `encapsulate` or
  // `raw` moved or vanished is a suite this test fails first.
  test("the operations the negatives are about all exist on the types entitled to them") {
    assert(typeChecks("edPriv.sign(boilerplate.Slice.empty)"), "a signing key signs")
    assert(typeChecks("hmacKey.sign(boilerplate.Slice.empty)"), "and so does a MAC key")
    assert(typeChecks("rsaPriv.sign(boilerplate.Slice.empty, RsaPss(Sha256))"), "RSA signs under a named padding")
    assert(typeChecks("p256Priv.sign(boilerplate.Slice.empty, Sha384)"), "and an EC key under an explicit Sha2")
    assert(typeChecks("aeadKey.seal(boilerplate.Slice.empty)"), "an AEAD key seals")
    assert(typeChecks("def r: Keyring[AesGcm256] = ???; r.seal(boilerplate.Slice.empty)"), "and so does an AEAD keyring")
    assert(
      typeChecks("def c: Cipher[AesGcm256] = ???; c.encrypt(boilerplate.Slice.empty, boilerplate.Slice.empty, boilerplate.Slice.empty, boilerplate.Slice.empty)"),
      "record encrypt exists on the Cipher handle"
    )
    assert(typeChecks("xPriv.agree(??? : PublicKey[X25519])"), "X25519 agrees with its own family")
    assert(typeChecks("p256Priv.agree(ecPub)"), "and a P-256 key with a P-256 peer")
    assert(typeChecks("def b: SealedBox[AesGcm256] = ???; aeadKey.open(b)"), "a box of the key's own algorithm opens")
    assert(typeChecks("def s: Signature[Ed25519] = ???; edPub.verify(boilerplate.Slice.empty, s)"), "a public key verifies its own family")
    // `ecPub.encapsulate` has no universal positive twin: the browser artifact provides no KEM
    // instance at all, so `kemPub.encapsulate` would not compile there. The KAT tier pairs it on
    // the rows that do provide one.
    assert(typeChecks("edPub.raw"), "an asymmetric public key exports raw")
    assert(typeChecks("def k: SecretKey[AesGcm256] = aeadKey"), "and a key of matching tag assigns")
  }

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
    assert(!typeChecks("edPriv.raw"), "nor does a private key: export is the typed, backend-decided path")
  }

  test("equality is available exactly where value semantics are real") {
    assert(typeChecks("AeadLimits(1, 1, 1) == AeadLimits(1, 1, 1)"), "limits compare by their integers")
    assert(!typeChecks("def d: Digest = ???; d == d"), "a digest does not, because the array behind it would compare by reference")
    assert(!typeChecks("aeadKey == aeadKey"), "nor does a carrier, whose comparison has no meaning any consumer asked for")
    assert(
      !typeChecks("def b: PEM.Block = ???; b == b"),
      "nor a PEM block, whose DER field would compare by reference and make a decode round-trip unequal to itself"
    )
  }

  test("the key-material types name only what they can hold, and parsing names the encoding") {
    assert(!typeChecks("def k: SecretKey[Ed25519] = ???"), "no constructor makes an asymmetric-tagged secret key nameable")
    assert(!typeChecks("def r: Keyring[Ed25519] = ???"), "a keyring holds symmetric keys alone")
    assert(typeChecks("def k: SecretKey[HmacSha256] = ???"), "a symmetric tag is nameable")
    assert(!typeChecks("RSA.fromPkcs8(boilerplate.Slice.empty)"), "parsing lives on the carrier, beside its siblings")
    assert(typeChecks("PrivateKey.parse(RSA)(PKCS8(boilerplate.Slice.empty))"), "RSA private-key import is where every other family's is")
  }
end NegativesSuite
