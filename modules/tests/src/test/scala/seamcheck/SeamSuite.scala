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
// Deliberately outside `kufuli.*`: `private[kufuli]` grants package access, so the same assertions
// made from `kufuli.tests` would compile whether or not the backend primitives are sealed and would
// prove nothing. Each negative is paired with the summon that reaches the same instance, so a
// failure means the primitive became callable rather than the instance becoming unresolvable.
package seamcheck

import scala.compiletime.testing.typeChecks

import kufuli.*

class SeamSuite extends munit.FunSuite:

  test("backend primitives are unreachable from outside kufuli, while the safe surface is not") {
    assert(typeChecks("summon[Random]"), "the Random instance resolves")
    assert(!typeChecks("summon[Random].bytes(32)"), "Random.bytes is sealed")
    assert(typeChecks("Random.bytes(32)"), "the companion wrapper is the public path")

    assert(typeChecks("summon[Aead[AesGcm256]]"), "the Aead instance resolves")
    assert(!typeChecks("summon[Aead[AesGcm256]].seal(???, ???, ???, ???)"), "Aead.seal is sealed")
    assert(!typeChecks("summon[Aead[AesGcm256]].open(???, ???, ???, ???)"), "Aead.open is sealed")
    assert(typeChecks("AesGcm256.generate"), "generation goes through the spec object")

    assert(typeChecks("summon[Mac[HmacSha256]]"), "the Mac instance resolves")
    assert(!typeChecks("summon[Mac[HmacSha256]].sign(???, ???)"), "Mac.sign is sealed")
    assert(!typeChecks("summon[Mac[HmacSha256]].prepared(???)"), "the default Mac.prepared is sealed with it")

    assert(typeChecks("summon[Signer[Ed25519]]") && typeChecks("summon[Verifier[Ed25519]]"), "the signing instances resolve")
    assert(!typeChecks("summon[Signer[Ed25519]].sign(???, ???, EdDsa)"), "Signer.sign is sealed")
    assert(!typeChecks("summon[Verifier[Ed25519]].verify(???, ???, ???, EdDsa)"), "Verifier.verify is sealed")

    assert(typeChecks("summon[Agreement[X25519]]"), "the Agreement instance resolves")
    assert(!typeChecks("summon[Agreement[X25519]].agree(???, ???)"), "Agreement.agree is sealed")

    assert(!typeChecks("summon[Kem[MlKem768]].encapsulate(???)"), "Kem.encapsulate is sealed")
    assert(!typeChecks("summon[Kem[MlKem768]].decapsulate(???, ???)"), "Kem.decapsulate is sealed")

    assert(typeChecks("summon[Wrap[AesKw256]]"), "the Wrap instance resolves")
    assert(!typeChecks("summon[Wrap[AesKw256]].wrap(???, ???)"), "the RFC 3394 length rule is unbypassable")
    assert(!typeChecks("summon[Wrap[AesKw256]].unwrap(???, ???)"), "Wrap.unwrap is sealed")

    assert(typeChecks("summon[Kdf]"), "the Kdf instance resolves")
    assert(!typeChecks("summon[Kdf].expand(Sha256, ???, ???, 100000)"), "the HKDF counter bound is unbypassable")
    assert(!typeChecks("summon[Kdf].extract(Sha256, ???, ???)"), "Kdf.extract is sealed")
    assert(!typeChecks("summon[Kdf].pbkdf2(Sha256, ???, ???, 1, 32)"), "Kdf.pbkdf2 is sealed")
    assert(typeChecks("HKDF.expand(Sha256, ???, ???, 32)"), "HKDF is the public path")

    assert(typeChecks("summon[Hash[Sha256]]"), "the Hash instance resolves")
    assert(!typeChecks("summon[Hash[Sha256]].digest(???)"), "Hash.digest is sealed")
    assert(!typeChecks("summon[Hashing[Sha256]].hasher"), "Hashing.hasher is sealed")
    assert(typeChecks("Sha256.digest(???)"), "the spec object is the public path")

    assert(typeChecks("summon[Oaep]"), "the Oaep instance resolves")
    assert(!typeChecks("summon[Oaep].encrypt(???, ???, RsaOaep(Sha256))"), "Oaep.encrypt is sealed")
    assert(!typeChecks("summon[Oaep].decrypt(???, ???, RsaOaep(Sha256))"), "Oaep.decrypt is sealed")

    assert(!typeChecks("summon[Ciphering[AesGcm256]].engine(???)"), "an unbudgeted record engine is unobtainable")

    assert(typeChecks("summon[EdKeys]") && typeChecks("summon[XKeys]"), "the key-lifecycle instances resolve")
    assert(!typeChecks("summon[XKeys].fromRaw(???)"), "the X25519 blocklist is unbypassable")
    assert(!typeChecks("summon[XKeys].fromSpki(???)"), "the SPKI blocklist path is unbypassable")
    assert(!typeChecks("summon[EdKeys].generate"), "EdKeys.generate is sealed")
    assert(!typeChecks("summon[EdKeys].fromPkcs8(???)"), "EdKeys.fromPkcs8 is sealed")
    assert(!typeChecks("summon[EdKeys].raw(???)"), "EdKeys.raw is sealed")
    assert(!typeChecks("summon[EcKeys[P256]].fromSec1(???)"), "EcKeys.fromSec1 is sealed")
    assert(!typeChecks("summon[RsaKeys].fromComponents(???, ???)"), "RsaKeys.fromComponents is sealed")
    assert(!typeChecks("summon[KemKeys[MlKem768]].fromSeed(???)"), "the seed import has no public surface")
    assert(typeChecks("Ed25519.generate"), "generation goes through the algorithm object")
    assert(typeChecks("PublicKey.fromRaw(X25519)(???)"), "the blocklisted import is the public path")
    assert(typeChecks("PublicKey.fromSpki(X25519)(???)"), "the typed SPKI import is the public path")

    assert(typeChecks("(??? : Signature.Signer[Ed25519]).sign(???)"), "a prepared signer stays callable")
    assert(typeChecks("(??? : Hasher).digest"), "a hasher handle stays callable")
    assert(typeChecks("(??? : Cipher[AesGcm256]).budget"), "a record cipher handle stays callable")
  }
end SeamSuite
