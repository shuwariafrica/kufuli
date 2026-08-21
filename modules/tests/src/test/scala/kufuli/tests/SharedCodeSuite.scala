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

// Effectful behaviour computed ENTIRELY in shared source: the custody split, the error arms a door
// decides above every backend, and the borrow discipline. No row here INVOKES a provider - the keys
// come from the pure import door, every refusal is reached before the seam is called, and the one
// backend-shaped step passes a double at that seam - so all four lanes run the same real logic and
// none of them certifies a provider.
class SharedCodeSuite extends munit.CatsEffectSuite:

  private def aesKey: SecretKey[AesGcm256] = SecretKey.of(AesGcm256)(Array.tabulate[Byte](32)(i => (i + 1).toByte)).toOption.get
  private def kekKey: SecretKey[AesKw256] = SecretKey.of(AesKw256)(Array.tabulate[Byte](32)(i => (i + 3).toByte)).toOption.get

  test("a secret key copies the caller's buffer rather than adopting it") {
    val bytes = Array.fill[Byte](32)(7)
    val key = SecretKey.of(AesGcm256)(bytes)
    assert(key.isRight, "32 bytes is an AES-256 key")
    assert(bytes.forall(_ == 7.toByte), "the caller's buffer is untouched, and stays the caller's to wipe")
  }

  test("the error arms a caller routes on are decided above every backend") {
    // A DSA SubjectPublicKeyInfo: well formed, and outside every family kufuli implements.
    val dsaSpki =
      Array[Byte](0x30, 0x1b, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x01, 0x03, 0x0e, 0x00) ++ Array
        .fill[Byte](13)(1)
    for
      // HMAC keys are variable length, so a 33-byte one is the reachable way to hand plain AES-KW a
      // length RFC 3394 cannot wrap. The refusal is the spec's own rule, applied before the provider
      // is called at all.
      odd <- Eff.from(SecretKey.of(HmacSha256)(new Array[Byte](33))).absolve
      refused <- kekKey.wrap(odd).either.absolve
      _ <- check(refused == Left(NotWrappable), s"a length that is not a multiple of 8 -> NotWrappable, got $refused")
      _ <- check(Keyring.of(KeyId(1) -> aesKey, KeyId(1) -> aesKey) == Left(DuplicateKeyId), "a ring cannot be built with a repeated id")
      unknown <- PublicKey.parse(SPKI(Slice.of(dsaSpki))).either.absolve
      _ <- check(unknown == Left(InvalidKey.Unsupported), s"an SPKI naming no family kufuli implements -> Unsupported, got $unknown")
    yield ()
    end for
  }

  test("an RSA modulus outside the shared range is declined, in one arm, before any provider") {
    // Above the ceiling no engine kufuli ships can verify with the key: two refuse it at import and
    // OpenSSL imports it and then returns false from every operation, which would report a key
    // nothing can use as a valid key and its every signature as a forgery. Deciding it here is what
    // makes the verdict the same on all four lanes.
    val huge = Array.fill[Byte](2049)(0xff.toByte) // 16392 bits
    val small = Array.fill[Byte](128)(0xff.toByte) // 1024 bits
    for
      over <- PublicKey.of(RSA.Components(IArray.from(huge), IArray[Byte](1, 0, 1))).either.absolve
      _ <- check(over == Left(InvalidKey.Unsupported), s"a modulus above the ceiling -> Unsupported, got $over")
      under <- PublicKey.of(RSA.Components(IArray.from(small), IArray[Byte](1, 0, 1))).either.absolve
      _ <- check(under == Left(InvalidKey.Unsupported), s"and one below the floor is the same arm, got $under")
    yield ()
  }

  test("a wrapped key is borrowed under the read guard for the whole operation, not only its construction") {
    // `Secret.use` guards the CALL alone. A backend whose `wrap` merely BUILDS an effect would,
    // under that guard, hand the borrowed view on to a runtime the guard had already released - and
    // a `destroy` landing in that window would erase the bytes mid-wrap, wrapping zeros with no
    // error at all. The double destroys the key from INSIDE the operation, which is the same
    // interleaving a concurrent destroy produces against a real asynchronous backend: a guard that
    // spans the operation makes it raise, a guard that spans the call lets it through.
    val target = aesKey
    val racing = new Wrap[AesKw256]:
      private[kufuli] def wrap(k: SecretKey[AesKw256], t: Slice): UEff[Slice] =
        target.destroy.map(_ => Slice.of(t.toArray))
      private[kufuli] def unwrap(k: SecretKey[AesKw256], w: Slice): Eff[UnwrapFailed, Slice] =
        Eff.suspend(Slice.of(w.toArray))
    for
      outcome <- kekKey.wrap(target)(using racing, AesKw256).absolve.attempt
      _ <- check(
             outcome.left.exists { case _: IllegalStateException => true; case _ => false },
             s"a destroy inside the operation window raises rather than wrapping zeros, got $outcome"
           )
    yield ()
  }
end SharedCodeSuite
