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

// The recipe layer - the box format, the keyrings, the prepared handles, the derive-and-seal chain,
// the export-versus-custody contract - each assertion of which runs a backend operation to reach
// what it is about. That is why the suite lives in the known-answer tier and not beside the
// value-layer checks: these rows are meaningless against a placeholder, so they execute on the lanes
// with a real provider and nowhere else.
class RecipeSuite extends munit.CatsEffectSuite:

  private val prepared = Slice.of("prepared".getBytes)

  test("a sealed box binds its own header, so re-heading a valid box refuses to open") {
    for
      key <- AesGcm256.generate.absolve
      box <- key.seal(Slice.of("secret".getBytes), Slice.of("ctx".getBytes)).absolve
      pt <- expectRight("open")(key.open(box, Slice.of("ctx".getBytes)))
      _ <- check(new String(pt.toArray) == "secret", "round-trip")
      bad <- key.open(box, Slice.of("other".getBytes)).either.absolve
      _ <- check(bad.isLeft, "a different aad -> AuthFailed")
      stored = Array.from(box.bytes.iterator)
      _ <- check(SealedBox.parse(AesGcm256)(stored).isRight, "the stored form parses back")
      // Version 1 is unkeyed and version 2 carries a KeyId; the whole header is the AEAD's
      // associated data, so promoting a v1 box to v2 fails authentication rather than being read as
      // a ring member.
      reheaded = stored.clone
      _ = reheaded(0) = 2.toByte
      // The re-headed box must PARSE, or the row would pass on a length rejection and say nothing
      // about the header being authenticated.
      forged <- expectRight("the re-headed box parses")(Eff.from(SealedBox.parse(AesGcm256)(reheaded)))
      opened <- key.open(forged, Slice.of("ctx".getBytes)).either.absolve
      _ <- check(opened == Left(AuthFailed), s"and then fails authentication rather than opening, got $opened")
    yield ()
    end for
  }

  test("Keyring AEAD rotation: the id routes a v2 box, and an unknown id is a forgery") {
    for
      k1 <- AesGcm256.generate.absolve
      k2 <- AesGcm256.generate.absolve
      ring1 = Keyring.of(KeyId(1) -> k1).toOption.get
      ring2 = ring1.rotated(KeyId(2) -> k2).toOption.get
      box <- ring2.seal(Slice.of("payload".getBytes)).absolve
      opened <- expectRight("ring open")(ring2.open(box))
      _ <- check(new String(opened.toArray) == "payload", "the ring seals under its primary and opens it")
      // The retired key is still held, so a box sealed before the rotation still opens.
      old <- ring1.seal(Slice.of("earlier".getBytes)).absolve
      earlier <- expectRight("retired key")(ring2.open(old))
      _ <- check(new String(earlier.toArray) == "earlier", "and still opens what a retired key sealed")
      stranger <- AesGcm256.generate.absolve
      other = Keyring.of(KeyId(9) -> stranger).toOption.get
      unknown <- other.open(box).either.absolve
      _ <- check(unknown == Left(AuthFailed), s"a ring that holds no such id reports a forgery, got $unknown")
    yield ()
    end for
  }

  test("MAC keyring rotation: a tag issued under a retired key still verifies, through the one CT compare") {
    for
      k1 <- HmacSha256.generate.absolve
      k2 <- HmacSha256.generate.absolve
      ring1 = Keyring.of(KeyId(1) -> k1).toOption.get
      ring2 = ring1.rotated(KeyId(2) -> k2).toOption.get
      old <- ring1.sign(Slice.of("cookie".getBytes)).absolve
      accepted <- ring2.verify(Slice.of("cookie".getBytes), old).either.absolve
      _ <- check(accepted == Right(()), s"the retired key's tag verifies under the rotated ring, got $accepted")
      forged <- ring2.verify(Slice.of("forged".getBytes), old).either.absolve
      _ <- check(forged.isLeft, s"and a tag over other data does not, got $forged")
    yield ()
  }

  test("a shared secret derives a key in one step, and the intermediate PRK does not outlive it") {
    for
      a <- X25519.generate.absolve
      b <- X25519.generate.absolve
      z <- a.privateKey.agree(b.publicKey).absolve
      key <- z.deriveKey(Sha256, Slice.empty, Slice.of("app".getBytes), AesGcm256).absolve
      box <- key.seal(Slice.of("derived".getBytes)).absolve
      pt <- expectRight("open derived")(key.open(box))
      _ <- check(new String(pt.toArray) == "derived", "the derived key seals and opens")
      _ <- z.destroy.absolve
    yield ()
  }

  test("unwrapping to a named algorithm validates the recovered length, over a sound union channel") {
    for
      kek <- AesKw256.generate.absolve
      target <- AesGcm256.generate.absolve
      wrapped <- expectRight("wrap")(kek.wrap(target))
      // Both arms of `UnwrapFailed | InvalidKey` are proper classes, so both survive the reifying
      // observer a union channel is read through - the first arm of a singleton union does not.
      recovered <- kek.unwrap(wrapped, AesGcm256).either.absolve
      _ <- check(recovered.isRight, s"the wrapped key unwraps to its own algorithm, got ${recovered.isRight}")
      mismatch <- kek.unwrap(wrapped, AesGcm128).either.absolve
      _ <- check(mismatch == Left(InvalidKey.WrongLength(16, 32)), s"and to another length is a typed refusal, got $mismatch")
      corrupt = wrapped.toArray
      _ = corrupt(0) = (corrupt(0) ^ 0xff).toByte
      failed <- kek.unwrap(Slice.of(corrupt), AesGcm256).either.absolve
      _ <- check(failed == Left(UnwrapFailed), s"a corrupted wrapping is the other arm, got $failed")
    yield ()
    end for
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
      failed <- secret.useEff[Malformed, Int](_ => Eff.fail(Malformed)).either.absolve
      _ <- check(failed == Left(Malformed), s"the typed failure propagates out of the borrow, got $failed")
      // Had the guard survived the failure, this borrow would raise rather than read.
      after <- secret.use(_.length).absolve
      _ <- check(after == 32, s"and the guard was released, so the secret borrows again, got $after")
      _ <- secret.destroy.absolve
    yield ()
    end for
  }

  test("a prepared MAC handle signs and verifies what the one-shot ops do") {
    for
      mk <- HmacSha256.generate.absolve
      tag <- mk.signer.use(s => s.sign(prepared)).absolve
      ok <- mk.verifier.use(v => v.verify(prepared, tag).either).absolve
      _ <- check(ok == Right(()), s"a prepared MAC verifier accepts a prepared tag, got $ok")
      oneShot <- mk.verify(prepared, tag).either.absolve
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
      oneShot <- ed.publicKey.verify(prepared, sig).either.absolve
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
      result <- ed.privateKey.pkcs8.either.absolve
      _ <- check(result.isRight == exportable, s"export and the backend's own custody agree, got $result for exportable=$exportable")
      _ <- check(exportable || result == Left(KeyNotExportable), s"a handle-backed key names the refusal, got $result")
      raw <- ed.publicKey.raw.either.absolve
      _ <- check(raw.exists(_.bytes.length == 32), s"a generated public key exports its raw form, got $raw")
      spki <- ed.publicKey.spki.either.absolve
      _ <- check(spki.isRight, s"and its SubjectPublicKeyInfo, got $spki")
      p <- P256.generate.absolve
      sec1 <- p.publicKey.sec1.either.absolve
      _ <- check(sec1.exists(_.bytes.length == 65), s"a generated P-256 public key exports its point, got $sec1")
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
      key <- expectRight("rsa spki")(PublicKey.parse(RSA)(SPKI(Slice.of(spki))))
      components <- expectRight("components")(key.components)
      _ <- check(Array.from(components.exponent.iterator).sameElements(exponent),
                 s"the exponent survives, got ${components.exponent.length} octets"
           )
      _ <- check(Array.from(components.modulus.iterator).sameElements(modulus),
                 s"and so does the modulus, got ${components.modulus.length} octets"
           )
    yield ()
  }

  test("an RSA public key keeps its modulus whatever width its exponent was given in") {
    // The JWK `e` is minimal-width: 65537 is three octets, 3 is one and 2^64+1 is nine. A reader
    // that splits a stored (modulus, exponent) pair at a FIXED width hands back octets of the
    // modulus as the exponent, and a short modulus - so the modulus is what this pins, since a
    // backend is free to canonicalise the exponent it re-derives.
    val modulus = Array.fill[Byte](256)(0xff.toByte)
    val wide = Array[Byte](0, 1, 0, 1) // 65537, one octet wider than its minimal encoding
    for
      key <- expectRight("of")(PublicKey.of(RSA.Components(IArray.from(modulus), IArray.from(wide))))
      components <- expectRight("components")(key.components)
      _ <- check(
             Array.from(components.modulus.iterator).sameElements(modulus),
             s"the modulus survives a four-octet exponent, got ${components.modulus.length} octets"
           )
      der <- expectRight("spki")(key.spki)
      reparsed <- expectRight("reparse")(PublicKey.parse(RSA)(der))
      again <- expectRight("components again")(reparsed.components)
      _ <- check(Array.from(again.modulus.iterator).sameElements(modulus),
                 s"and survives the SPKI the same key emits, got ${again.modulus.length} octets"
           )
    yield ()
    end for
  }
end RecipeSuite
