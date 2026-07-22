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
// Deterministic, input-sensitive stub backend for node and browser: round-trips are real byte
// equalities and tamper checks real rejections, over the same op seam as a real backend.
package kufuli

import java.util.concurrent.atomic.AtomicLong

import scala.collection.mutable.ArrayBuffer

import boilerplate.Slice
import boilerplate.effect.EffIO
import cats.effect.IO
import cats.effect.Resource

private[kufuli] object stubs:

  private def splitmix(z0: Long): Long =
    val z = z0 + 0x9e3779b97f4a7c15L
    val a = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L
    val b = (a ^ (a >>> 27)) * 0x94d049bb133111ebL
    b ^ (b >>> 31)

  // Deterministic `len` bytes sensitive to every input byte.
  private[kufuli] def mix(len: Int)(parts: Slice*): Array[Byte] =
    val seed = parts.foldLeft(0xcbf29ce484222325L) { (h, s) =>
      (0 until s.length).foldLeft(h)((h2, i) => (h2 ^ (s(i) & 0xff)) * 0x100000001b3L)
    }
    Array.tabulate(len)(i => (splitmix(seed + i) & 0xff).toByte)

  private def xorBytes(a: Slice, b: Slice): Array[Byte] =
    Array.tabulate(math.min(a.length, b.length))(i => (a(i) ^ b(i)).toByte)

  private def schemeTag(s: Scheme[?]): Array[Byte] = s match
    case _: EdDsa.type => Array(1)
    case Ecdsa(h)      => Array(2, h.length.toByte)
    case RsaPss(h)     => Array(3, h.length.toByte)
    case RsaPkcs1(h)   => Array(4, h.length.toByte)

  private val seq = new AtomicLong(0)
  private def longBytes(l: Long): Array[Byte] = Array.tabulate(8)(i => (l >>> (56 - 8 * i)).toByte)

  // Deterministic-but-distinct bytes per call (no ambient randomness).
  private def fresh(tag: String)(len: Int): Array[Byte] =
    mix(len)(Slice.of(tag.getBytes), Slice.of(longBytes(seq.incrementAndGet())))

  // Ciphertext = plaintext ++ tag where the tag mixes key, nonce, aad, and payload - so
  // round-trips are real byte equalities and ANY input difference (tampered ciphertext, wrong
  // key/nonce/aad - including the authenticated box header) fails authentication.
  private def sealBytes[A <: AeadAlgorithm](spec: AeadSpec[A])(key: SecretKey[A], nonce: Array[Byte], aad: Slice, pt: Slice): Array[Byte] =
    val tag = key.read(k => mix(spec.tagLength)(k, Slice.of(nonce), aad, pt))
    val out = new Array[Byte](pt.length + spec.tagLength)
    val _ = pt.copyInto(Slice.of(out))
    val _ = Slice.of(tag).copyInto(Slice.of(out).drop(pt.length))
    out
  private def openBytes[A <: AeadAlgorithm](spec: AeadSpec[A])(
    key: SecretKey[A],
    nonce: Array[Byte],
    aad: Slice,
    ct: Slice
  ): Either[AuthFailed, Slice] =
    if ct.length < spec.tagLength then Left(AuthFailed)
    else
      val payload = ct.take(ct.length - spec.tagLength)
      val expected = key.read(k => mix(spec.tagLength)(k, Slice.of(nonce), aad, payload))
      if Slice.of(expected).constantTimeEquals(ct.drop(payload.length)) then Right(payload) else Left(AuthFailed)

  private[kufuli] def aead[A <: AeadAlgorithm](spec: AeadSpec[A]): Aead[A] = new:
    def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice) =
      EffIO.suspend(Slice.of(sealBytes(spec)(key, nonce.repr, aad, plaintext)))
    def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice) =
      EffIO.delay(openBytes(spec)(key, nonce.repr, aad, ciphertext))

  final private class StubEngine[A <: AeadAlgorithm](key: SecretKey[A], spec: AeadSpec[A]) extends Cipher.Engine[A]:
    def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
      val tag = key.read(k => mix(spec.tagLength)(k, nonce, aad, src))
      val _ = src.copyInto(dst)
      val _ = Slice.of(tag).copyInto(dst.drop(src.length))
      src.length + spec.tagLength
    def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      val payload = src.take(src.length - spec.tagLength)
      val expected = key.read(k => mix(spec.tagLength)(k, nonce, aad, payload))
      if !Slice.of(expected).constantTimeEquals(src.drop(payload.length)) then Left(AuthFailed)
      else
        val _ = payload.copyInto(dst)
        Right(payload.length)
  end StubEngine

  private[kufuli] def ciphering[A <: AeadAlgorithm](spec: AeadSpec[A]): Ciphering[A] = new:
    def engine(key: SecretKey[A]) = Resource.eval(IO(new StubEngine(key, spec)))

  private[kufuli] def mac[H <: MacAlgorithm](spec: MacSpec[H]): Mac[H] = new:
    def sign(key: SecretKey[H], data: Slice) =
      EffIO.suspend(Signature.unsafe(key.read(k => mix(spec.outLength)(k, data))))

  private[kufuli] def signerOf[A <: SignatureAlgorithm](len: Int): Signer[A] = new:
    def sign(key: PrivateKey[A], data: Slice, scheme: Scheme[A]) =
      EffIO.suspend(Signature.unsafe[A](key.read(k => mix(len)(k, data, Slice.of(schemeTag(scheme))))))
  private[kufuli] def verifierOf[A <: SignatureAlgorithm](len: Int): Verifier[A] = new:
    def verify(key: PublicKey[A], data: Slice, sig: Signature[A], scheme: Scheme[A]) =
      EffIO.defer {
        val expected = mix(len)(Slice.of(keyBytes(key.repr)), data, Slice.of(schemeTag(scheme)))
        EffIO.raiseUnless(Slice.of(expected).constantTimeEquals(Slice.of(sig.repr)))(SignatureRejected)
      }

  // Stub keypairs carry pub == priv bytes so verify/agree/decapsulate can recompute.
  private[kufuli] def agreement[A <: AgreementAlgorithm]: Agreement[A] = new:
    def agree(priv: PrivateKey[A], pub: PublicKey[A]) =
      EffIO.suspend(SharedSecret.unsafe(priv.read(p => xorBytes(p, Slice.of(keyBytes(pub.repr))))))

  private[kufuli] def kem[K <: KemAlgorithm](spec: KemSpec[K]): Kem[K] = new:
    def encapsulate(pub: PublicKey[K]) = EffIO.suspend {
      val p = Slice.of(keyBytes(pub.repr))
      val z = mix(32)(p, Slice.of(Array(101.toByte)))
      val mask = mix(32)(p, Slice.of(Array(102.toByte)))
      val ct = new Array[Byte](spec.ciphertextLength)
      val _ = Slice.of(xorBytes(Slice.of(z), Slice.of(mask))).copyInto(Slice.of(ct))
      Encapsulated(SharedSecret.unsafe(z), KemCiphertext.unsafe(ct))
    }
    def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]) = EffIO.suspend {
      priv.read { p =>
        val mask = mix(32)(p, Slice.of(Array(102.toByte)))
        // FIPS 203 implicit rejection: any ciphertext yields a secret; a forged one a different one.
        SharedSecret.unsafe(xorBytes(Slice.of(ct.repr).take(32), Slice.of(mask)))
      }
    }

  private[kufuli] def wrapOf[W <: WrapAlgorithm]: Wrap[W] = new:
    def wrap(kek: SecretKey[W], target: Slice) =
      EffIO.suspend {
        kek.read { k =>
          val body = xorBytes(target, Slice.of(mix(target.length)(k)))
          val hdr = mix(8)(k, Slice.of(body))
          val out = new Array[Byte](8 + body.length)
          val _ = Slice.of(hdr).copyInto(Slice.of(out))
          val _ = Slice.of(body).copyInto(Slice.of(out).drop(8))
          Slice.of(out)
        }
      }
    def unwrap(kek: SecretKey[W], wrapped: Slice) =
      EffIO.defer {
        kek.read { k =>
          if wrapped.length < 8 then EffIO.fail(UnwrapFailed)
          else
            val body = wrapped.drop(8)
            val expected = mix(8)(k, body)
            if !Slice.of(expected).constantTimeEquals(wrapped.take(8)) then EffIO.fail(UnwrapFailed)
            else EffIO.succeed(Slice.of(xorBytes(body, Slice.of(mix(body.length)(k)))))
        }
      }

  private[kufuli] def kdf: Kdf = new:
    def extract(hash: Sha2, salt: Slice, ikm: Slice) =
      EffIO.suspend(Prk.unsafe(mix(hash.length)(salt, ikm)))
    def expand(hash: Sha2, prk: Prk, info: Slice, length: Int) =
      EffIO.suspend(prk.read(p => Slice.of(mix(length)(p, info))))
    def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int) =
      EffIO.suspend(Slice.of(mix(length)(password, salt, Slice.of(Array(iterations.toByte)))))

  private[kufuli] def hash[D <: HashAlgorithm](spec: HashSpec[D]): Hash[D] = new:
    def digest(data: Slice) = EffIO.suspend(Digest.unsafe(mix(spec.length)(data)))
  private[kufuli] def hashing[D <: HashAlgorithm](spec: HashSpec[D]): Hashing[D] = new:
    def hasher = Resource.eval(IO {
      new Hasher:
        private val acc = ArrayBuffer.empty[Byte]
        def update(data: Slice): Unit = acc.appendAll(data.toArray)
        def digest: Digest = Digest.unsafe(mix(spec.length)(Slice.of(acc.toArray)))
    })

  private[kufuli] def oaep: Oaep = new:
    def encrypt(key: PublicKey[Rsa], plaintext: Slice, scheme: RsaOaep) = EffIO.suspend {
      val hdr = mix(16)(Slice.of(keyBytes(key.repr)), Slice.of(Array(scheme.hash.length.toByte)))
      val out = new Array[Byte](16 + plaintext.length)
      val _ = Slice.of(hdr).copyInto(Slice.of(out))
      val _ = plaintext.copyInto(Slice.of(out).drop(16))
      Slice.of(out)
    }
    def decrypt(key: PrivateKey[Rsa], ciphertext: Slice, scheme: RsaOaep) = EffIO.defer {
      key.read { k =>
        val hdr = mix(16)(k, Slice.of(Array(scheme.hash.length.toByte)))
        if ciphertext.length >= 16 && Slice.of(hdr).constantTimeEquals(ciphertext.take(16))
        then EffIO.succeed(ciphertext.drop(16))
        else EffIO.fail(AuthFailed)
      }
    }

  private[kufuli] def random: Random = new:
    def bytes(n: Int) = EffIO.suspend(Slice.of(fresh("random")(n)))
    def fill(dst: Slice) = EffIO.suspend {
      val _ = Slice.of(fresh("fill")(dst.length)).copyInto(dst)
    }

  // Key lifecycle stubs: pub == priv bytes; imports validate byte-faithfully; exports emit
  // REAL encodings (RFC 8410 templates for Ed/X, Der-built SPKI/PKCS#8 for EC/RSA) so the shared
  // peek round-trips executed blobs. Validation conventions: a 0xFF-led point is "off-curve"; an
  // all-zero X25519 point is a weak point. `handleBacked = true` models WebCrypto: GENERATED keys
  // carry a sentinel and refuse export (KeyNotExportable); IMPORTED keys always export.

  private val sentinel = Array[Byte]('H', 'N', 'D', 'L')
  private def sentinelled(b: Array[Byte]): Array[Byte] = sentinel ++ b.drop(4)
  private def isSentinel(b: Slice): Boolean =
    b.length >= 4 && b.take(4).contentEquals(Slice.of(sentinel))
  private def exportable[A](key: Slice, handleBacked: Boolean)(value: => A): EffIO[KeyNotExportable, A] =
    if handleBacked && isSentinel(key) then EffIO.fail(KeyNotExportable) else EffIO.succeed(value)

  final private[kufuli] class StubEdKeys(handleBacked: Boolean) extends EdKeys:
    def generate = EffIO.suspend {
      val body = fresh("ed")(32)
      body(0) = (body(0) & 0x7f).toByte // never collide with the stub off-curve marker
      val b = if handleBacked then sentinelled(body) else body
      KeyPair(PublicKey.unsafe(keyRepr(b.clone)), PrivateKey.unsafe(b))
    }
    def fromRaw(bytes: Slice) = EffIO.delay {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes(0) == -1 then Left(InvalidKey.NotOnCurve)
      else Right(PublicKey.unsafe[Ed25519](keyRepr(bytes.toArray)))
    }
    def fromSpki(der: Slice) = EffIO.from(Der.payload(der, Der.edSpkiPrefix, 32)).flatMap(fromRaw)
    def fromPkcs8(der: Slice) =
      EffIO.delay(Der.payload(der, Der.edPkcs8Prefix, 32).map(s => PrivateKey.unsafe[Ed25519](s.toArray)))
    def raw(key: PublicKey[Ed25519]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(b))
    def spki(key: PublicKey[Ed25519]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(Der.edSpkiPrefix ++ b))
    def pkcs8(key: PrivateKey[Ed25519]) =
      EffIO.defer(key.read(s => exportable(s, handleBacked)(IArray.from(Der.edPkcs8Prefix ++ s.toArray))))
  end StubEdKeys

  final private[kufuli] class StubXKeys(handleBacked: Boolean) extends XKeys:
    def generate = EffIO.suspend {
      val b = if handleBacked then sentinelled(fresh("x")(32)) else fresh("x")(32)
      KeyPair(PublicKey.unsafe(keyRepr(b.clone)), PrivateKey.unsafe(b))
    }
    def fromRaw(bytes: Slice) = EffIO.delay {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes.toArray.forall(_ == 0) then Left(InvalidKey.WeakPoint)
      else Right(PublicKey.unsafe[X25519](keyRepr(bytes.toArray)))
    }
    def fromSpki(der: Slice) = EffIO.from(Der.payload(der, Der.xSpkiPrefix, 32)).flatMap(fromRaw)
    def fromPkcs8(der: Slice) =
      EffIO.delay(Der.payload(der, Der.xPkcs8Prefix, 32).map(s => PrivateKey.unsafe[X25519](s.toArray)))
    def raw(key: PublicKey[X25519]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(b))
    def spki(key: PublicKey[X25519]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(Der.xSpkiPrefix ++ b))
    def pkcs8(key: PrivateKey[X25519]) =
      EffIO.defer(key.read(s => exportable(s, handleBacked)(IArray.from(Der.xPkcs8Prefix ++ s.toArray))))
  end StubXKeys

  final private[kufuli] class StubEcKeys[C <: EcCurve](
    spec: EcSpec[C],
    spkiPrefix: Array[Byte],
    curveOid: Array[Byte],
    handleBacked: Boolean
  ) extends EcKeys[C]:
    private val pointLength = 1 + 2 * spec.fieldLength
    def generate = EffIO.suspend {
      val body = Array[Byte](4) ++ fresh("ec")(2 * spec.fieldLength)
      body(1) = (body(1) & 0x7f).toByte // never collide with the stub off-curve marker
      val b = if handleBacked then sentinelled(body) else body
      KeyPair(PublicKey.unsafe(keyRepr(b.clone)), PrivateKey.unsafe(b))
    }
    def fromSec1(point: Slice) = EffIO.delay {
      if point.length != pointLength then Left(InvalidKey.WrongLength(pointLength, point.length))
      else if point(0) != 4.toByte then Left(InvalidKey.Malformed)
      else if point(1) == -1 then Left(InvalidKey.NotOnCurve)
      else Right(PublicKey.unsafe[C](keyRepr(point.toArray)))
    }
    def fromSpki(der: Slice) = EffIO.from(Der.payload(der, spkiPrefix, pointLength)).flatMap(fromSec1)
    def fromPkcs8(der: Slice) = EffIO.delay {
      val expected = Der.sequence(
        Der.integer(Array.emptyByteArray),
        Der.sequence(Der.objectId(Der.oidEcPublic), Der.objectId(curveOid)),
        Der.octetString(new Array[Byte](pointLength))
      )
      if der.length != expected.length then Left(InvalidKey.Malformed)
      else Right(PrivateKey.unsafe[C](der.drop(der.length - pointLength).toArray))
    }
    def sec1(key: PublicKey[C]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(b))
    def spki(key: PublicKey[C]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(IArray.from(spkiPrefix ++ b))
    def pkcs8(key: PrivateKey[C]) =
      EffIO.defer(
        key.read(s =>
          exportable(s, handleBacked)(
            IArray.from(
              Der.sequence(
                Der.integer(Array.emptyByteArray),
                Der.sequence(Der.objectId(Der.oidEcPublic), Der.objectId(curveOid)),
                Der.octetString(s.toArray)
              )
            )
          )
        )
      )
  end StubEcKeys

  final private[kufuli] class StubRsaKeys(handleBacked: Boolean) extends RsaKeys:
    // stub key layout: repr = modulus ++ exponent(3 bytes, 0x010001)
    private val e = Array[Byte](1, 0, 1)
    def generate(size: Rsa.Size) = EffIO.suspend {
      val body = fresh("rsa")(size.bits / 8) ++ e
      val b = if handleBacked then sentinelled(body) else body
      KeyPair(PublicKey.unsafe(keyRepr(b.clone)), PrivateKey.unsafe(b))
    }
    def fromComponents(modulus: Slice, exponent: Slice) = EffIO.delay {
      if modulus.isEmpty || exponent.isEmpty then Left(InvalidKey.Malformed)
      else Right(PublicKey.unsafe[Rsa](keyRepr(modulus.toArray ++ exponent.toArray)))
    }
    def fromSpki(der: Slice) = EffIO.delay {
      // real parse via the bounded reader: SEQ { SEQ { oid, NULL }, BIT STRING { SEQ { INT n, INT e } } }
      for
        outer <- Der.read(der, 0, 0x30)
        algId <- Der.read(der, outer.contentOff, 0x30)
        bits <- Der.read(der, algId.next, 0x03)
        inner <- Der.read(der, bits.contentOff + 1, 0x30)
        n <- Der.read(der, inner.contentOff, 0x02)
        ex <- Der.read(der, n.next, 0x02)
      yield PublicKey.unsafe[Rsa](
        keyRepr(
          der.slice(n.contentOff + 1, n.next).toArray ++ der.slice(ex.contentOff + 1, ex.next).toArray
        )
      )
    }
    def fromPkcs8(der: Slice) = EffIO.delay {
      for
        outer <- Der.read(der, 0, 0x30)
        v <- Der.read(der, outer.contentOff, 0x02)
        algId <- Der.read(der, v.next, 0x30)
        octets <- Der.read(der, algId.next, 0x04)
      yield PrivateKey.unsafe[Rsa](der.slice(octets.contentOff, octets.next).toArray)
    }
    def components(key: PublicKey[Rsa]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(Rsa.Components(IArray.from(b.take(b.length - 3)), IArray.from(b.drop(b.length - 3))))
    def spki(key: PublicKey[Rsa]) =
      val b = keyBytes(key.repr)
      exportable(Slice.of(b), handleBacked)(
        IArray.from(
          Der.sequence(
            Der.sequence(Der.objectId(Der.oidRsa), Der.nullValue),
            Der.bitString(Der.sequence(Der.integer(b.take(b.length - 3)), Der.integer(b.drop(b.length - 3))))
          )
        )
      )
    def pkcs8(key: PrivateKey[Rsa]) =
      EffIO.defer(
        key.read(s =>
          exportable(s, handleBacked)(
            IArray.from(
              Der.sequence(
                Der.integer(Array.emptyByteArray),
                Der.sequence(Der.objectId(Der.oidRsa), Der.nullValue),
                Der.octetString(s.toArray)
              )
            )
          )
        )
      )
  end StubRsaKeys

  final private[kufuli] class StubKemKeys[K <: KemAlgorithm](spec: KemSpec[K]) extends KemKeys[K]:
    def generate = EffIO.suspend {
      val b = fresh("kem")(spec.publicKeyLength)
      KeyPair(PublicKey.unsafe(keyRepr(b.clone)), PrivateKey.unsafe(b))
    }
    def fromRaw(bytes: Slice) = EffIO.delay {
      if bytes.length != spec.publicKeyLength then Left(InvalidKey.WrongLength(spec.publicKeyLength, bytes.length))
      else Right(PublicKey.unsafe[K](keyRepr(bytes.toArray)))
    }
    def raw(key: PublicKey[K]) = EffIO.succeed(IArray.from(keyBytes(key.repr)))

  // Composable instance bundles: each per-unit platform trait extends exactly its backend's set.

  private[kufuli] trait AeadUniversal:
    given Aead[AesGcm128] = aead(AesGcm128)
    given Aead[AesGcm192] = aead(AesGcm192)
    given Aead[AesGcm256] = aead(AesGcm256)
    given Aead[A128CbcHs256] = aead(A128CbcHs256)
    given Aead[A256CbcHs512] = aead(A256CbcHs512)
  private[kufuli] trait AeadChaCha:
    given Aead[ChaCha20Poly1305] = aead(ChaCha20Poly1305)
  private[kufuli] trait AeadMisuseResistant:
    given Aead[XChaCha20Poly1305] = aead(XChaCha20Poly1305)
    given Aead[AesGcmSiv256] = aead(AesGcmSiv256)

  private[kufuli] trait CipheringUniversal:
    given Ciphering[AesGcm128] = ciphering(AesGcm128)
    given Ciphering[AesGcm192] = ciphering(AesGcm192)
    given Ciphering[AesGcm256] = ciphering(AesGcm256)
  private[kufuli] trait CipheringChaCha:
    given Ciphering[ChaCha20Poly1305] = ciphering(ChaCha20Poly1305)
  private[kufuli] trait CipheringMisuseResistant:
    given Ciphering[XChaCha20Poly1305] = ciphering(XChaCha20Poly1305)
    given Ciphering[AesGcmSiv256] = ciphering(AesGcmSiv256)

  private[kufuli] trait MacAll:
    given Mac[HmacSha256] = mac(HmacSha256)
    given Mac[HmacSha384] = mac(HmacSha384)
    given Mac[HmacSha512] = mac(HmacSha512)

  private[kufuli] trait SignersAll:
    given Signer[Ed25519] = signerOf(64)
    given Signer[P256] = signerOf(64)
    given Signer[P384] = signerOf(96)
    given Signer[P521] = signerOf(132)
    given Signer[Rsa] = signerOf(256)
  private[kufuli] trait VerifiersAll:
    given Verifier[Ed25519] = verifierOf(64)
    given Verifier[P256] = verifierOf(64)
    given Verifier[P384] = verifierOf(96)
    given Verifier[P521] = verifierOf(132)
    given Verifier[Rsa] = verifierOf(256)

  private[kufuli] trait AgreementAll:
    given Agreement[X25519] = agreement
    given Agreement[P256] = agreement
    given Agreement[P384] = agreement
    given Agreement[P521] = agreement

  private[kufuli] trait KemAll:
    given Kem[MlKem768] = kem(MlKem768)
    given Kem[MlKem1024] = kem(MlKem1024)
  private[kufuli] trait KemKeysAll:
    given KemKeys[MlKem768] = StubKemKeys(MlKem768)
    given KemKeys[MlKem1024] = StubKemKeys(MlKem1024)

  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapOf
    given Wrap[AesKw256] = wrapOf
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapOf
    given Wrap[AesKwp256] = wrapOf

  private[kufuli] trait KdfDefault:
    given Kdf = kdf

  private[kufuli] trait HashAll:
    given Hash[Sha1] = hash(Sha1)
    given Hash[Sha256] = hash(Sha256)
    given Hash[Sha384] = hash(Sha384)
    given Hash[Sha512] = hash(Sha512)
  private[kufuli] trait HashingSync:
    given Hashing[Sha256] = hashing(Sha256)
    given Hashing[Sha384] = hashing(Sha384)
    given Hashing[Sha512] = hashing(Sha512)

  private[kufuli] trait OaepDefault:
    given Oaep = oaep

  private[kufuli] trait RandomDefault:
    given Random = random

  private[kufuli] trait EdKeysBytes:
    given EdKeys = StubEdKeys(handleBacked = false)
  private[kufuli] trait EdKeysHandles:
    given EdKeys = StubEdKeys(handleBacked = true)
  private[kufuli] trait XKeysBytes:
    given XKeys = StubXKeys(handleBacked = false)
  private[kufuli] trait XKeysHandles:
    given XKeys = StubXKeys(handleBacked = true)
  private[kufuli] trait EcKeysBytes:
    given EcKeys[P256] = StubEcKeys(P256, Der.p256SpkiPrefix, Der.oidP256, handleBacked = false)
    given EcKeys[P384] = StubEcKeys(P384, Der.p384SpkiPrefix, Der.oidP384, handleBacked = false)
    given EcKeys[P521] = StubEcKeys(P521, Der.p521SpkiPrefix, Der.oidP521, handleBacked = false)
  private[kufuli] trait EcKeysHandles:
    given EcKeys[P256] = StubEcKeys(P256, Der.p256SpkiPrefix, Der.oidP256, handleBacked = true)
    given EcKeys[P384] = StubEcKeys(P384, Der.p384SpkiPrefix, Der.oidP384, handleBacked = true)
    given EcKeys[P521] = StubEcKeys(P521, Der.p521SpkiPrefix, Der.oidP521, handleBacked = true)
  private[kufuli] trait RsaKeysBytes:
    given RsaKeys = StubRsaKeys(handleBacked = false)
  private[kufuli] trait RsaKeysHandles:
    given RsaKeys = StubRsaKeys(handleBacked = true)
end stubs
