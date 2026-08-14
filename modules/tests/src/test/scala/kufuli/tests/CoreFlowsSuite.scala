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

import boilerplate.Slice
import boilerplate.effect.*

import kufuli.*
import kufuli.tests.support.*

// Runs on every artifact, browser included, so it exercises only the ops common to all four
// backends.
class CoreFlowsSuite extends munit.CatsEffectSuite:

  test("AES-GCM-256 seal/open with authenticated header; re-heading refuses") {
    for
      key <- AesGcm256.generate.absolve
      box <- key.seal(Slice.of("secret".getBytes), Slice.of("ctx".getBytes)).absolve
      pt <- expectRight("open")(key.open(box, Slice.of("ctx".getBytes)))
      _ <- check(new String(pt.toArray) == "secret", "round-trip")
      bad <- key.open(box, Slice.of("other".getBytes)).either
      _ <- check(bad.isLeft, "wrong aad -> AuthFailed")
      stored = box.bytes
      reparsed = SealedBox.of(AesGcm256)(Array.from(stored.iterator))
      _ <- check(reparsed.isRight, "persistence round-trip")
    yield ()
  }

  test("Keyring AEAD rotation: id-routed v2, duplicate-id rejection, unknown-id-as-forgery") {
    for
      k1 <- AesGcm256.generate.absolve
      k2 <- AesGcm256.generate.absolve
      ring1 = Keyring.of(KeyId.of(1) -> k1).toOption.get
      ring2 = ring1.rotated(KeyId.of(2) -> k2).toOption.get
      _ <- check(ring1.rotated(KeyId.of(1) -> k2).isLeft, "duplicate id rejected")
      box <- ring2.seal(Slice.of("payload".getBytes)).absolve
      opened <- expectRight("ring open")(ring2.open(box))
      _ <- check(new String(opened.toArray) == "payload", "ring seal/open")
    yield ()
  }

  test("MAC keyring rotation (session/CSRF): CT trial across held keys") {
    for
      k1 <- HmacSha256.generate.absolve
      k2 <- HmacSha256.generate.absolve
      ring = Keyring.of(KeyId.of(1) -> k1).toOption.get.rotated(KeyId.of(2) -> k2).toOption.get
      tag <- ring.sign(Slice.of("cookie".getBytes)).absolve
      ok <- ring.verify(Slice.of("cookie".getBytes), tag).either
      _ <- check(ok == Right(()), "tag verifies under the ring")
      bad <- ring.verify(Slice.of("forged".getBytes), tag).either
      _ <- check(bad.isLeft, "forged data rejected")
    yield ()
  }

  test("Ed25519 sign/verify with scheme-mismatch rejection") {
    for
      kp <- Ed25519.generate.absolve
      sig <- kp.privateKey.sign(Slice.of("msg".getBytes)).absolve
      ok <- kp.publicKey.verify(Slice.of("msg".getBytes), sig).either
      _ <- check(ok == Right(()), "verify")
      bad <- kp.publicKey.verify(Slice.of("MSG".getBytes), sig).either
      _ <- check(bad.isLeft, "tampered data rejected")
    yield ()
  }

  test("ECDSA P-256 sign/verify (curve-paired hash)") {
    for
      kp <- P256.generate.absolve
      sig <- kp.privateKey.sign(Slice.of("data".getBytes)).absolve
      ok <- kp.publicKey.verify(Slice.of("data".getBytes), sig).either
      _ <- check(ok == Right(()), "verify")
    yield ()
  }

  test("X25519 agreement is total and symmetric; secret hygiene (use-wipes)") {
    for
      a <- X25519.generate.absolve
      b <- X25519.generate.absolve
      za <- a.privateKey.agree(b.publicKey).absolve
      zb <- b.privateKey.agree(a.publicKey).absolve
      ha <- za.use(s => s.toArray.toSeq).absolve
      hb <- zb.use(s => s.toArray.toSeq).absolve
      _ <- check(ha == hb, "agreement matches both directions")
      _ <- za.destroy.absolve
      _ <- zb.destroy.absolve
    yield ()
  }

  test("HKDF derive a key from a shared secret; the PRK is destroyed") {
    for
      a <- X25519.generate.absolve
      b <- X25519.generate.absolve
      z <- a.privateKey.agree(b.publicKey).absolve
      key <- z.deriveKey(Sha256, Slice.empty, Slice.of("app".getBytes), AesGcm256).absolve
      box <- key.seal(Slice.of("derived".getBytes)).absolve
      pt <- expectRight("open derived")(key.open(box))
      _ <- check(new String(pt.toArray) == "derived", "derived-key round-trip")
    yield ()
  }

  test("AES-KW wrap/unwrap; the UnwrapFailed | InvalidKey union channel is sound") {
    for
      kek <- AesKw256.generate.absolve
      target <- AesGcm256.generate.absolve
      wrapped <- expectRight("wrap")(kek.wrap(target))
      unwrapped <- kek.unwrap(wrapped, AesGcm256).either
      _ <- check(unwrapped.isRight, "unwrap to the named algorithm")
    yield ()
  }

  test("hashing: one-shot digest snapshots") {
    for
      d <- Sha256.digest(Slice.of("transcript".getBytes)).absolve
      _ <- check(d.bytes.length == 32, "SHA-256 is 32 bytes")
    yield ()
  }
  test("a generated public key exports on every backend, and its private half never leaves as bytes") {
    for
      ed <- Ed25519.generate.absolve
      raw <- ed.publicKey.raw.either
      _ <- check(raw.exists(_.length == 32), s"a generated Ed25519 public key exports its raw form, got $raw")
      spki <- ed.publicKey.spki.either
      _ <- check(spki.isRight, s"and its SubjectPublicKeyInfo, got $spki")
      p <- P256.generate.absolve
      sec1 <- p.publicKey.sec1.either
      _ <- check(sec1.exists(_.length == 65), s"a generated P-256 public key exports its point, got $sec1")
      // The private half has no byte accessor at all: export is the typed, backend-decided path.
      _ <- check(!typeChecks("def k: PrivateKey[Ed25519] = ???; k.raw"), "a private key has no raw export")
      _ <- check(!typeChecks("def k: SecretKey[AesGcm256] = ???; k.raw"), "a secret key has no raw export")
    yield ()
    end for
  }

  test("a secret key copies the caller's buffer rather than adopting it") {
    val bytes = Array.fill[Byte](32)(7)
    val key = SecretKey.of(AesGcm256)(bytes)
    assert(key.isRight, "32 bytes is an AES-256 key")
    assert(bytes.forall(_ == 7.toByte), "the caller's buffer is untouched, and stays the caller's to wipe")
  }

  test("a shared secret borrows under guard and refuses a borrow after destruction") {
    for
      first <- X25519.generate.absolve
      second <- X25519.generate.absolve
      secret <- first.privateKey.agree(second.publicKey).absolve
      seen <- secret.use(_.length).absolve
      _ <- check(seen == 32, s"the borrow sees the live bytes, got $seen")
      held <- secret.useEff(s => Eff.succeed(s.length)).absolve
      _ <- check(held == 32, s"the effect borrow holds the guard across the returned effect, got $held")
      _ <- secret.destroy.absolve
      after <- secret.use(_.length).absolve.attempt
      _ <- check(after.left.exists { case _: IllegalStateException => true; case _ => false }, s"a borrow after destroy raises, got $after")
      again <- secret.destroy.absolve.attempt
      _ <- check(again.isRight, "destruction is idempotent")
    yield ()
    end for
  }
  test("a borrow across an effect releases its guard whether the effect succeeds or fails") {
    for
      first <- X25519.generate.absolve
      second <- X25519.generate.absolve
      secret <- first.privateKey.agree(second.publicKey).absolve
      // The channel is ascribed: inferred, it collapses to Nothing and the row proves nothing about
      // a typed failure crossing the borrow.
      failed <- secret.useEff[Malformed, Int](_ => Eff.fail(Malformed)).either
      _ <- check(failed == Left(Malformed), s"the typed failure propagates out of the borrow, got $failed")
      // Had the guard survived the failure, this borrow would raise rather than read.
      after <- secret.use(_.length).absolve
      _ <- check(after == 32, s"and the guard was released, so the secret borrows again, got $after")
      _ <- secret.destroy.absolve
    yield ()
    end for
  }

  private val prepared = Slice.of("prepared".getBytes)

  test("a prepared MAC handle signs and verifies what the one-shot ops do") {
    for
      mk <- HmacSha256.generate.absolve
      tag <- mk.signer.use(s => s.sign(prepared)).absolve
      ok <- mk.verifier.use(v => v.verify(prepared, tag).either).absolve
      _ <- check(ok == Right(()), s"a prepared MAC verifier accepts a prepared tag, got $ok")
      oneShot <- mk.verify(prepared, tag).either
      _ <- check(oneShot == Right(()), s"and the one-shot verify accepts it too, got $oneShot")
      forged <- mk.verifier.use(v => v.verify(Slice.of("other".getBytes), tag).either).absolve
      _ <- check(forged.isLeft, s"a prepared verifier still rejects a tag over other data, got $forged")
    yield ()
  }

  test("a prepared Ed25519 handle signs and verifies what the one-shot ops do") {
    for
      ed <- Ed25519.generate.absolve
      sig <- ed.privateKey.signer.use(s => s.sign(prepared)).absolve
      ok <- ed.publicKey.verifier.use(v => v.verify(prepared, sig).either).absolve
      _ <- check(ok == Right(()), s"a prepared Ed25519 pair round-trips, got $ok")
      oneShot <- ed.publicKey.verify(prepared, sig).either
      _ <- check(oneShot == Right(()), s"and the one-shot verify accepts the prepared signature, got $oneShot")
    yield ()
  }

  test("a prepared P-256 handle signs and verifies what the one-shot ops do") {
    for
      ec <- P256.generate.absolve
      sig <- ec.privateKey.signer.use(s => s.sign(prepared)).absolve
      ok <- ec.publicKey.verifier.use(v => v.verify(prepared, sig).either).absolve
      _ <- check(ok == Right(()), s"a prepared P-256 pair round-trips, got $ok")
      crossed <- ec.publicKey.verifier.use(v => v.verify(Slice.of("other".getBytes), sig).either).absolve
      _ <- check(crossed.isLeft, s"and rejects a signature over other data, got $crossed")
    yield ()
  }

  test("a private key exports exactly when the backend holds it as bytes, and names the refusal when it does not") {
    for
      ed <- Ed25519.generate.absolve
      exportable = ed.privateKey.exportable
      result <- ed.privateKey.pkcs8.either
      _ <- check(result.isRight == exportable, s"export and the backend's own custody agree, got $result for exportable=$exportable")
      _ <- check(exportable || result == Left(KeyNotExportable), s"a handle-backed key names the refusal, got $result")
      // An IMPORTED key is the caller's bytes whatever the backend generates into, so it always
      // exports - which is what keeps a round trip expressible on every artifact.
      imported <- ed.publicKey.spki.either
      _ <- check(imported.isRight, s"a public key always exports, got $imported")
    yield ()
    end for
  }

  test("an RSA SubjectPublicKeyInfo round-trips the exponent a DER INTEGER carries without padding") {
    // 65537 is 02 03 01 00 01: its top bit is clear, so DER adds no leading zero and a reader that
    // skips the first content octet unconditionally reads the exponent as 1.
    def tlv(tag: Int, c: Array[Byte]): Array[Byte] =
      val h =
        if c.length < 0x80 then Array[Byte](tag.toByte, c.length.toByte)
        else if c.length < 0x100 then Array[Byte](tag.toByte, 0x81.toByte, c.length.toByte)
        else Array[Byte](tag.toByte, 0x82.toByte, (c.length >> 8).toByte, c.length.toByte)
      h ++ c
    def seq(parts: Array[Byte]*): Array[Byte] = tlv(0x30, parts.foldLeft(Array.emptyByteArray)(_ ++ _))
    val modulus = Array.fill[Byte](256)(0xff.toByte)
    val exponent = Array[Byte](1, 0, 1)
    val rsaOid = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x01)
    val spki = seq(
      seq(tlv(0x06, rsaOid), tlv(0x05, Array.emptyByteArray)),
      tlv(0x03, Array[Byte](0) ++ seq(tlv(0x02, Array[Byte](0) ++ modulus), tlv(0x02, exponent)))
    )
    for
      key <- expectRight("rsa spki")(PublicKey.fromSpki(RSA)(Slice.of(spki)))
      components <- expectRight("components")(key.components)
      _ <- check(Array.from(components.exponent.iterator).sameElements(exponent),
                 s"the exponent survives, got ${components.exponent.length} octets"
           )
      _ <- check(Array.from(components.modulus.iterator).sameElements(modulus),
                 s"and so does the modulus, got ${components.modulus.length} octets"
           )
    yield ()
  }

  test("the error arms a caller routes on: unwrappable length, duplicate id, unknown key algorithm") {
    // A DSA SubjectPublicKeyInfo: well formed, and outside every family kufuli implements.
    val dsaSpki =
      Array[Byte](0x30, 0x1b, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x01, 0x03, 0x0e, 0x00) ++ Array
        .fill[Byte](13)(1)
    for
      kek <- AesKw256.generate.absolve
      // HMAC keys are variable length, so a 33-byte one is the reachable way to hand plain AES-KW a
      // length RFC 3394 cannot wrap; a KWP algorithm takes it.
      odd <- Eff.from(SecretKey.of(HmacSha256)(new Array[Byte](33))).absolve
      refused <- kek.wrap(odd).either
      _ <- check(refused == Left(NotWrappable), s"a length that is not a multiple of 8 -> NotWrappable, got $refused")
      even <- AesGcm256.generate.absolve
      accepted <- kek.wrap(even).either
      _ <- check(accepted.isRight, s"and the same key-encryption key wraps a length RFC 3394 admits, got ${accepted.isRight}")
      k1 <- AesGcm256.generate.absolve
      k2 <- AesGcm256.generate.absolve
      _ <- check(Keyring.of(KeyId.of(1) -> k1, KeyId.of(1) -> k2) == Left(DuplicateKeyId), "a ring cannot be built with a repeated id")
      unknown <- PublicKey.fromSpki(Slice.of(dsaSpki)).either
      _ <- check(unknown == Left(InvalidKey.Unsupported), s"an SPKI naming no family kufuli implements -> Unsupported, got $unknown")
    yield ()
    end for
  }
end CoreFlowsSuite
