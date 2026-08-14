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
// Deterministic, input-sensitive stub backend for the browser row, which is the one unit with no
// real provider yet: round-trips are real byte equalities and tamper checks real rejections, over
// the same op seam as a real backend.
package kufuli

import java.util.concurrent.atomic.AtomicLong

import boilerplate.Slice
import boilerplate.effect.Eff

private[kufuli] object stubs:

  private def splitmix(z0: Long): Long =
    val z = z0 + 0x9e3779b97f4a7c15L
    val a = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L
    val b = (a ^ (a >>> 27)) * 0x94d049bb133111ebL
    b ^ (b >>> 31)

  // Deterministic `len` bytes sensitive to every input byte.
  private def mix(len: Int)(parts: Slice*): Array[Byte] =
    val seed = parts.foldLeft(0xcbf29ce484222325L) { (h, s) =>
      (0 until s.length).foldLeft(h)((h2, i) => (h2 ^ (s(i) & 0xff)) * 0x100000001b3L)
    }
    Array.tabulate(len)(i => (splitmix(seed + i) & 0xff).toByte)

  private def xorBytes(a: Slice, b: Slice): Array[Byte] =
    Array.tabulate(math.min(a.length, b.length))(i => (a(i) ^ b(i)).toByte)

  private def schemeTag(s: Scheme[?]): Array[Byte] = s match
    case _: Ed.type  => Array(1)
    case ECDSA(h)    => Array(2, h.length.toByte)
    case RsaPss(h)   => Array(3, h.length.toByte)
    case RsaPkcs1(h) => Array(4, h.length.toByte)

  private val seq = new AtomicLong(0)
  private def longBytes(l: Long): Array[Byte] = Array.tabulate(8)(i => (l >>> (56 - 8 * i)).toByte)

  // Deterministic-but-distinct bytes per call (no ambient randomness).
  private def fresh(tag: String)(len: Int): Array[Byte] =
    mix(len)(Slice.of(tag.getBytes), Slice.of(longBytes(seq.incrementAndGet())))

  // Ciphertext = plaintext ++ tag where the tag mixes key, nonce, aad, and payload - so
  // round-trips are real byte equalities and ANY input difference (tampered ciphertext, wrong
  // key/nonce/aad - including the authenticated box header) fails authentication.
  private def sealBytes[A <: AeadAlgorithm](spec: AeadSpec[A])(key: SecretKey[A], nonce: Array[Byte], aad: Slice, pt: Slice): Array[Byte] =
    val tag = key.material(k => mix(spec.tagLength)(k, Slice.of(nonce), aad, pt))
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
      val expected = key.material(k => mix(spec.tagLength)(k, Slice.of(nonce), aad, payload))
      if Slice.of(expected).constantTimeEquals(ct.drop(payload.length)) then Right(payload) else Left(AuthFailed)

  private[kufuli] def aead[A <: AeadAlgorithm](spec: AeadSpec[A]): AEAD[A] = new:
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice) =
      Eff.suspend(Slice.of(sealBytes(spec)(key, nonce.repr, aad, plaintext)))
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice) =
      Eff.delay(openBytes(spec)(key, nonce.repr, aad, ciphertext))

  private[kufuli] def mac[H <: MacAlgorithm](spec: MacSpec[H]): MAC[H] = new:
    private[kufuli] def sign(key: SecretKey[H], data: Slice) =
      Eff.suspend(Signature.unsafe(key.material(k => mix(spec.outLength)(k, data))))

  private[kufuli] def signerOf[A <: SignatureAlgorithm](len: Int): Signing[A] = new:
    private[kufuli] def sign(key: PrivateKey[A], data: Slice, scheme: Scheme[A]) =
      Eff.suspend(Signature.unsafe[A](key.material(k => mix(len)(k, data, Slice.of(schemeTag(scheme))))))
  private[kufuli] def verifierOf[A <: SignatureAlgorithm](len: Int): Verifying[A] = new:
    private[kufuli] def verify(key: PublicKey[A], data: Slice, sig: Signature[A], scheme: Scheme[A]) =
      Eff.defer {
        val expected = mix(len)(Slice.of(keyBytes(key.repr)), data, Slice.of(schemeTag(scheme)))
        Eff.raiseUnless(Slice.of(expected).constantTimeEquals(Slice.of(sig.repr)))(SignatureRejected)
      }

  // Stub keypairs carry pub == priv bytes so verify/agree/decapsulate can recompute.
  private[kufuli] def agreement[A <: AgreementAlgorithm]: Agreement[A] = new:
    private[kufuli] def agree(priv: PrivateKey[A], pub: PublicKey[A]) =
      Eff.suspend(SharedSecret.unsafe(priv.material(p => xorBytes(p, Slice.of(keyBytes(pub.repr))))))

  private[kufuli] def wrapOf[W <: WrapAlgorithm]: Wrap[W] = new:
    private[kufuli] def wrap(kek: SecretKey[W], target: Slice) =
      Eff.suspend {
        kek.material { k =>
          val body = xorBytes(target, Slice.of(mix(target.length)(k)))
          val hdr = mix(8)(k, Slice.of(body))
          val out = new Array[Byte](8 + body.length)
          val _ = Slice.of(hdr).copyInto(Slice.of(out))
          val _ = Slice.of(body).copyInto(Slice.of(out).drop(8))
          Slice.of(out)
        }
      }
    private[kufuli] def unwrap(kek: SecretKey[W], wrapped: Slice) =
      Eff.defer {
        kek.material { k =>
          if wrapped.length < 8 then Eff.fail(UnwrapFailed)
          else
            val body = wrapped.drop(8)
            val expected = mix(8)(k, body)
            if !Slice.of(expected).constantTimeEquals(wrapped.take(8)) then Eff.fail(UnwrapFailed)
            else Eff.succeed(Slice.of(xorBytes(body, Slice.of(mix(body.length)(k)))))
        }
      }

  private[kufuli] def kdf: KDF = new:
    private[kufuli] def extract(hash: Sha2, salt: Slice, ikm: Slice) =
      Eff.suspend(PRK.unsafe(mix(hash.length)(salt, ikm)))
    private[kufuli] def expand(hash: Sha2, prk: PRK, info: Slice, length: Int) =
      Eff.suspend(prk.read(p => Slice.of(mix(length)(p, info))))
    private[kufuli] def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int) =
      Eff.suspend(Slice.of(mix(length)(password, salt, Slice.of(Array(iterations.toByte)))))

  private[kufuli] def hash[D <: HashAlgorithm](spec: HashSpec[D]): Hash[D] = new:
    private[kufuli] def digest(data: Slice) = Eff.suspend(Digest.unsafe(mix(spec.length)(data)))

  private[kufuli] def oaep: OAEP = new:
    private[kufuli] def encrypt(key: PublicKey[RSA], plaintext: Slice, scheme: RsaOaep) = Eff.suspend {
      val hdr = mix(16)(Slice.of(keyBytes(key.repr)), Slice.of(Array(scheme.hash.length.toByte)))
      val out = new Array[Byte](16 + plaintext.length)
      val _ = Slice.of(hdr).copyInto(Slice.of(out))
      val _ = plaintext.copyInto(Slice.of(out).drop(16))
      Slice.of(out)
    }
    private[kufuli] def decrypt(key: PrivateKey[RSA], ciphertext: Slice, scheme: RsaOaep) = Eff.defer {
      key.material { k =>
        val hdr = mix(16)(k, Slice.of(Array(scheme.hash.length.toByte)))
        if ciphertext.length >= 16 && Slice.of(hdr).constantTimeEquals(ciphertext.take(16))
        then Eff.succeed(ciphertext.drop(16))
        else Eff.fail(AuthFailed)
      }
    }

  private[kufuli] def random: Random = new:
    private[kufuli] def bytes(n: Int) = Eff.suspend(Slice.of(fresh("random")(n)))
    private[kufuli] def fill(dst: Slice) = Eff.suspend {
      val _ = Slice.of(fresh("fill")(dst.length)).copyInto(dst)
    }

  // Key lifecycle stubs: pub == priv bytes; imports validate byte-faithfully; exports emit
  // REAL encodings (RFC 8410 templates for Ed/X, DER-built SPKI/PKCS#8 for EC/RSA) so the shared
  // peek round-trips executed blobs. Validation conventions: a 0xFF-led point is "off-curve"; an
  // all-zero X25519 point is a weak point.
  //
  // Generated-key custody belongs to the platform (`keyGenerated`/`secretGenerated`), so the same
  // instance bodies express WebCrypto's contract without a flag: a generated private key refuses
  // export by arm, while its public key exports, and operations reach material through the door.

  final private[kufuli] class StubEdKeys extends EdKeys:
    private[kufuli] def generate = Eff.suspend {
      val body = fresh("ed")(32)
      body(0) = (body(0) & 0x7f).toByte // never collide with the stub off-curve marker
      KeyPair(PublicKey.unsafe(keyGenerated(body.clone)), PrivateKey.unsafeRepr(secretGenerated(body)))
    }
    private[kufuli] def fromRaw(bytes: Slice) = Eff.delay {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes(0) == -1 then Left(InvalidKey.NotOnCurve)
      else Right(PublicKey.unsafe[Ed25519](keyRepr(bytes.toArray)))
    }
    private[kufuli] def fromSpki(der: Slice) = Eff.from(DER.payload(der, DER.edSpkiPrefix, 32)).flatMap(fromRaw)
    private[kufuli] def fromPkcs8(der: Slice) =
      Eff.delay(DER.payload(der, DER.edPkcs8Prefix, 32).map(s => PrivateKey.unsafe[Ed25519](s.toArray)))
    private[kufuli] def raw(key: PublicKey[Ed25519]) = Eff.succeed(IArray.from(keyBytes(key.repr)))
    private[kufuli] def spki(key: PublicKey[Ed25519]) = Eff.succeed(IArray.from(DER.edSpkiPrefix ++ keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[Ed25519]) =
      Eff.defer(
        if !key.exportable then Eff.fail(KeyNotExportable)
        else key.material(s => Eff.succeed(IArray.from(DER.edPkcs8Prefix ++ s.toArray)))
      )
  end StubEdKeys

  final private[kufuli] class StubXKeys extends XKeys:
    private[kufuli] def generate = Eff.suspend {
      val b = fresh("x")(32)
      KeyPair(PublicKey.unsafe(keyGenerated(b.clone)), PrivateKey.unsafeRepr(secretGenerated(b)))
    }
    private[kufuli] def fromRaw(bytes: Slice) = Eff.delay {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes.toArray.forall(_ == 0) then Left(InvalidKey.WeakPoint)
      else Right(PublicKey.unsafe[X25519](keyRepr(bytes.toArray)))
    }
    private[kufuli] def fromSpki(der: Slice) = Eff.from(DER.payload(der, DER.xSpkiPrefix, 32)).flatMap(fromRaw)
    private[kufuli] def fromPkcs8(der: Slice) =
      Eff.delay(DER.payload(der, DER.xPkcs8Prefix, 32).map(s => PrivateKey.unsafe[X25519](s.toArray)))
    private[kufuli] def raw(key: PublicKey[X25519]) = Eff.succeed(IArray.from(keyBytes(key.repr)))
    private[kufuli] def spki(key: PublicKey[X25519]) = Eff.succeed(IArray.from(DER.xSpkiPrefix ++ keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[X25519]) =
      Eff.defer(
        if !key.exportable then Eff.fail(KeyNotExportable)
        else key.material(s => Eff.succeed(IArray.from(DER.xPkcs8Prefix ++ s.toArray)))
      )
  end StubXKeys

  final private[kufuli] class StubEcKeys[C <: EcCurve](
    spec: EcSpec[C],
    spkiPrefix: Array[Byte],
    curveOid: Array[Byte]
  ) extends EcKeys[C]:
    private val pointLength = 1 + 2 * spec.fieldLength
    private[kufuli] def generate = Eff.suspend {
      val body = Array[Byte](4) ++ fresh("ec")(2 * spec.fieldLength)
      body(1) = (body(1) & 0x7f).toByte // never collide with the stub off-curve marker
      KeyPair(PublicKey.unsafe(keyGenerated(body.clone)), PrivateKey.unsafeRepr(secretGenerated(body)))
    }
    private[kufuli] def fromSec1(point: Slice) = Eff.delay {
      if point.length != pointLength then Left(InvalidKey.WrongLength(pointLength, point.length))
      else if point(0) != 4.toByte then Left(InvalidKey.Malformed)
      else if point(1) == -1 then Left(InvalidKey.NotOnCurve)
      else Right(PublicKey.unsafe[C](keyRepr(point.toArray)))
    }
    private[kufuli] def fromSpki(der: Slice) = Eff.from(DER.payload(der, spkiPrefix, pointLength)).flatMap(fromSec1)
    private[kufuli] def fromPkcs8(der: Slice) = Eff.delay {
      val expected = DER.sequence(
        DER.integer(Array.emptyByteArray),
        DER.sequence(DER.objectId(DER.oidEcPublic), DER.objectId(curveOid)),
        DER.octetString(new Array[Byte](pointLength))
      )
      if der.length != expected.length then Left(InvalidKey.Malformed)
      else Right(PrivateKey.unsafe[C](der.drop(der.length - pointLength).toArray))
    }
    private[kufuli] def sec1(key: PublicKey[C]) = Eff.succeed(IArray.from(keyBytes(key.repr)))
    private[kufuli] def spki(key: PublicKey[C]) = Eff.succeed(IArray.from(spkiPrefix ++ keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[C]) =
      Eff.defer(
        if !key.exportable then Eff.fail(KeyNotExportable)
        else
          key.material(s =>
            Eff.succeed(
              IArray.from(
                DER.sequence(
                  DER.integer(Array.emptyByteArray),
                  DER.sequence(DER.objectId(DER.oidEcPublic), DER.objectId(curveOid)),
                  DER.octetString(s.toArray)
                )
              )
            )
          )
      )
  end StubEcKeys

  final private[kufuli] class StubRsaKeys extends RsaKeys:
    // stub key layout: repr = modulus ++ exponent(3 bytes, 0x010001)
    private val e = Array[Byte](1, 0, 1)
    private[kufuli] def generate(size: RSA.Size) = Eff.suspend {
      val body = fresh("rsa")(size.bits / 8) ++ e
      KeyPair(PublicKey.unsafe(keyGenerated(body.clone)), PrivateKey.unsafeRepr(secretGenerated(body)))
    }
    private[kufuli] def fromComponents(modulus: Slice, exponent: Slice) = Eff.delay {
      if modulus.isEmpty || exponent.isEmpty then Left(InvalidKey.Malformed)
      else RSA.flooredComponents(modulus).map(_ => PublicKey.unsafe[RSA](keyRepr(modulus.toArray ++ exponent.toArray)))
    }
    // A DER INTEGER carries a leading zero only to clear a set sign bit, so an exponent such as
    // 65537 has none and its first content octet is magnitude.
    private def magnitude(der: Slice, t: DER.Tlv): Array[Byte] =
      val from = if t.contentLen > 1 && der(t.contentOff) == 0.toByte then t.contentOff + 1 else t.contentOff
      der.slice(from, t.next).toArray
    private[kufuli] def fromSpki(der: Slice) = Eff
      .delay {
        // real parse via the bounded reader: SEQ { SEQ { oid, NULL }, BIT STRING { SEQ { INT n, INT e } } }
        for
          outer <- DER.read(der, 0, 0x30)
          algId <- DER.within(der, outer.contentOff, 0x30, outer.next)
          bits <- DER.within(der, algId.next, 0x03, outer.next)
          inner <- DER.within(der, bits.contentOff + 1, 0x30, bits.next)
          n <- DER.within(der, inner.contentOff, 0x02, inner.next)
          ex <- DER.within(der, n.next, 0x02, inner.next)
        yield (magnitude(der, n), magnitude(der, ex))
      }
      .flatMap((n, ex) => fromComponents(Slice.of(n), Slice.of(ex)))
    private[kufuli] def fromPkcs8(der: Slice) = Eff.delay {
      for
        outer <- DER.read(der, 0, 0x30)
        v <- DER.read(der, outer.contentOff, 0x02)
        algId <- DER.read(der, v.next, 0x30)
        octets <- DER.read(der, algId.next, 0x04)
        body = der.slice(octets.contentOff, octets.next)
        _ <- if body.length > e.length then Right(()) else Left(InvalidKey.Malformed)
        _ <- RSA.floored(body.take(body.length - e.length))
      yield PrivateKey.unsafe[RSA](body.toArray)
    }
    private[kufuli] def components(key: PublicKey[RSA]) =
      val b = keyBytes(key.repr)
      Eff.succeed(RSA.Components(IArray.from(b.take(b.length - 3)), IArray.from(b.drop(b.length - 3))))
    private[kufuli] def spki(key: PublicKey[RSA]) =
      val b = keyBytes(key.repr)
      Eff.succeed(
        IArray.from(
          DER.sequence(
            DER.sequence(DER.objectId(DER.oidRsa), DER.nullValue),
            DER.bitString(DER.sequence(DER.integer(b.take(b.length - 3)), DER.integer(b.drop(b.length - 3))))
          )
        )
      )
    private[kufuli] def pkcs8(key: PrivateKey[RSA]) =
      Eff.defer(
        if !key.exportable then Eff.fail(KeyNotExportable)
        else
          key.material(s =>
            Eff.succeed(
              IArray.from(
                DER.sequence(
                  DER.integer(Array.emptyByteArray),
                  DER.sequence(DER.objectId(DER.oidRsa), DER.nullValue),
                  DER.octetString(s.toArray)
                )
              )
            )
          )
      )
  end StubRsaKeys

  // Composable instance bundles: each per-unit platform trait extends exactly its backend's set.

  private[kufuli] trait AeadUniversal:
    given AEAD[AesGcm128] = aead(AesGcm128)
    given AEAD[AesGcm192] = aead(AesGcm192)
    given AEAD[AesGcm256] = aead(AesGcm256)
    given AEAD[A128CbcHs256] = aead(A128CbcHs256)
    given AEAD[A256CbcHs512] = aead(A256CbcHs512)
  private[kufuli] trait MacAll:
    given MAC[HmacSha256] = mac(HmacSha256)
    given MAC[HmacSha384] = mac(HmacSha384)
    given MAC[HmacSha512] = mac(HmacSha512)
    given MAC[HmacSha1] = mac(HmacSha1)

  private[kufuli] trait SignersAll:
    given Signing[Ed25519] = signerOf(64)
    given Signing[P256] = signerOf(64)
    given Signing[P384] = signerOf(96)
    given Signing[P521] = signerOf(132)
    given Signing[RSA] = signerOf(256)
  private[kufuli] trait VerifiersAll:
    given Verifying[Ed25519] = verifierOf(64)
    given Verifying[P256] = verifierOf(64)
    given Verifying[P384] = verifierOf(96)
    given Verifying[P521] = verifierOf(132)
    given Verifying[RSA] = verifierOf(256)

  private[kufuli] trait AgreementAll:
    given Agreement[X25519] = agreement
    given Agreement[P256] = agreement
    given Agreement[P384] = agreement
    given Agreement[P521] = agreement

  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapOf
    given Wrap[AesKw256] = wrapOf

  private[kufuli] trait KdfDefault:
    given KDF = kdf

  private[kufuli] trait HashAll:
    given Hash[Sha1] = hash(Sha1)
    given Hash[Sha256] = hash(Sha256)
    given Hash[Sha384] = hash(Sha384)
    given Hash[Sha512] = hash(Sha512)

  private[kufuli] trait OaepDefault:
    given OAEP = oaep

  private[kufuli] trait RandomDefault:
    given Random = random

  private[kufuli] trait EdKeysAll:
    given EdKeys = StubEdKeys()
  private[kufuli] trait XKeysAll:
    given XKeys = StubXKeys()
  private[kufuli] trait EcKeysAll:
    given EcKeys[P256] = StubEcKeys(P256, DER.p256SpkiPrefix, DER.oidP256)
    given EcKeys[P384] = StubEcKeys(P384, DER.p384SpkiPrefix, DER.oidP384)
    given EcKeys[P521] = StubEcKeys(P521, DER.p521SpkiPrefix, DER.oidP521)
  private[kufuli] trait RsaKeysAll:
    given RsaKeys = StubRsaKeys()
end stubs
