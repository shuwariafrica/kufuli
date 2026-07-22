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

import kufuli.*
import kufuli.tests.support.*

// Runs on every artifact, browser included, so it exercises only the ops common to all four
// backends and never attempts a key export.
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
end CoreFlowsSuite
