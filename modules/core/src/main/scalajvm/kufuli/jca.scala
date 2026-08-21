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
// JVM backend instances over the Java Cryptography Architecture (JCA, JDK 25 floor). Each family
// here is the real provider the JVM capability table wires into the shared companion. Keys are
// carried as their standard encodings (SPKI for public, PKCS#8 for private, raw octets for
// symmetric material); operations parse them to JCA key objects. Every op routes through `guard`,
// so a provider anomaly becomes a sanitised `Unexpected` defect rather than a wrong success.
package kufuli

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey as JPrivateKey
import java.security.PublicKey as JPublicKey
import java.security.SecureRandom
import java.security.Signature as JSignature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher as JCipher
import javax.crypto.KEM as JKem
import javax.crypto.KeyAgreement
import javax.crypto.Mac as JMac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.effect.Eff
import boilerplate.effect.UEff
import cats.effect.IO
import cats.effect.Resource

private[kufuli] object jca:

  private def op[A](thunk: => A): UEff[A] = guard(IO(thunk))
  private def blockingOp[A](thunk: => A): UEff[A] = guard(IO.blocking(thunk))
  private def opE[E <: Throwable, A](thunk: => Either[E, A]): Eff[E, A] = Eff.lift(guard(IO(thunk)))

  // Import refusal is BINARY here: the companion door names the public arm from the form it was
  // handed, so this backend cannot classify differently from its siblings.
  private def refusing[A](f: => A): Either[Refused, A] =
    try Right(f)
    catch
      case _: InvalidKeySpecException           => Left(Refused)
      case _: java.security.InvalidKeyException => Left(Refused)

  // JCA key and spec constructors clone the array they are handed, so the copy taken out of a
  // carrier is ours to erase; what the provider retains beyond that is the documented JVM boundary.
  private def wiping[A](secret: Slice)(f: Array[Byte] => A): A =
    val bytes = secret.toArray
    try f(bytes)
    finally Slice.of(bytes).wipe()

  private def kf(alg: String): KeyFactory = KeyFactory.getInstance(alg)
  private def parsePub(alg: String, spki: Array[Byte]): JPublicKey = kf(alg).generatePublic(new X509EncodedKeySpec(spki))
  private def parsePriv(alg: String, pkcs8: Array[Byte]): JPrivateKey = kf(alg).generatePrivate(new PKCS8EncodedKeySpec(pkcs8))

  // What is stored is the encoding JCA re-marshals from the parsed key, so every stored blob is
  // canonical and an export reads a header kufuli itself produced. JCA infers the family from that
  // encoding and reports no curve of its own, so the stored AlgorithmIdentifier is also what binds
  // the import to the family and curve the caller named.
  private def storePub[A <: Algorithm](alg: String, expect: DER.Alg, spki: Array[Byte]): Either[Refused, PublicKey[A]] =
    refusing(parsePub(alg, spki).getEncoded)
      .flatMap(stored => DER.requireSpki(Slice.of(stored), expect).left.map(_ => Refused).map(_ => PublicKey.unsafe[A](keyRepr(stored))))

  // JCA's EC KeyFactory accepts any coordinate pair, so an off-curve point imports here and only
  // misbehaves later, where aws-lc and node both refuse it at parse. kufuli's three curves have
  // cofactor 1, so in-field coordinates satisfying the curve equation IS full public-key validation
  // (SEC1 section 3.2.2), and it is what makes `agree` total on this backend too.
  private def onCurve(key: JPublicKey): Boolean = key match
    case ec: ECPublicKey =>
      val curve = ec.getParams.getCurve
      curve.getField match
        case field: ECFieldFp =>
          val p = field.getP
          val w = ec.getW
          val x = w.getAffineX
          val y = w.getAffineY
          def inField(v: BigInteger): Boolean = v.signum >= 0 && v.compareTo(p) < 0
          !w.equals(ECPoint.POINT_INFINITY) && inField(x) && inField(y) &&
          y.multiply(y).mod(p).compareTo(x.multiply(x).multiply(x).add(curve.getA.multiply(x)).add(curve.getB).mod(p)) == 0
        case _ => false
    case _ => false

  private def storeEcPub[C <: EcCurve](expect: DER.Alg, spki: Array[Byte]): Either[Refused, PublicKey[C]] =
    refusing(parsePub("EC", spki))
      .flatMap(parsed => if onCurve(parsed) then Right(parsed.getEncoded) else Left(Refused))
      .flatMap(stored => DER.requireSpki(Slice.of(stored), expect).left.map(_ => Refused).map(_ => PublicKey.unsafe[C](keyRepr(stored))))

  // The canonical encoding before it becomes a carrier: adoption wipes the source, so a check over
  // the stored bytes has to run here.
  private def canonicalPriv(alg: String, expect: DER.Alg, pkcs8: Array[Byte]): Either[Refused, Array[Byte]] =
    refusing(parsePriv(alg, pkcs8).getEncoded)
      .flatMap(stored => DER.requirePkcs8(Slice.of(stored), expect).left.map(_ => Refused).map(_ => stored))

  private def storePriv[A <: Algorithm](alg: String, expect: DER.Alg, pkcs8: Array[Byte]): Either[Refused, PrivateKey[A]] =
    canonicalPriv(alg, expect, pkcs8).map(PrivateKey.unsafe[A])

  // Public-point export walks the stored SPKI to its BIT STRING; the algorithm-independent length
  // assertion is what keeps a wire form (a TLS key_share, a JWK coordinate pair) exactly its curve.
  private def publicPoint(key: KeyRepr, length: Int): IArray[Byte] =
    IArray.from(demand(DER.spkiPublicBits(Slice.of(keyBytes(key)), length)).toArray)

  private def unsigned(bi: BigInteger): Array[Byte] =
    val b = bi.toByteArray
    if b.length > 1 && b(0) == 0.toByte then b.drop(1) else b

  private def hmacName(hash: Sha2): String = hash match
    case _: Sha256.type => "HmacSHA256"
    case _: Sha384.type => "HmacSHA384"
    case _: Sha512.type => "HmacSHA512"

  private def hmac(name: String, key: Array[Byte], data: Array[Byte]): Array[Byte] =
    hmac(name, key, 0, key.length, data)

  // The window form keys a MAC from part of a larger buffer, so a composite key needs no half copies.
  private def hmac(name: String, key: Array[Byte], from: Int, length: Int, data: Array[Byte]): Array[Byte] =
    val m = JMac.getInstance(name)
    m.init(new SecretKeySpec(key, from, length, name))
    m.doFinal(data)

  private val rng = new SecureRandom()
  private[kufuli] val random: Random = new Random:
    private[kufuli] def bytes(n: Int): UEff[Slice] = op { val b = new Array[Byte](n); rng.nextBytes(b); Slice.of(b) }
    private[kufuli] def fill(dst: Slice): UEff[Unit] = op {
      val b = new Array[Byte](dst.length)
      rng.nextBytes(b)
      val _ = Slice.of(b).copyInto(dst)
    }

  // AES-GCM and ChaCha20-Poly1305 are JCA AEAD ciphers (output is ct || tag). AES-CBC-HMAC-SHA2 is
  // the RFC 7518 composite (encrypt-then-MAC); the shared box layout hands this tier its whole
  // ciphertext (ct || tag) back on open.
  private def aeadAead[A <: AeadAlgorithm](spec: AeadSpec[A], cipherName: String, keyAlg: String, gcm: Boolean): AEAD[A] =
    new AEAD[A]:
      private def params(nonce: Array[Byte]) =
        if gcm then new GCMParameterSpec(spec.tagLength * 8, nonce) else new IvParameterSpec(nonce)
      private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEff[Slice] = op {
        key.material { k =>
          val c = JCipher.getInstance(cipherName)
          c.init(JCipher.ENCRYPT_MODE, wiping(k)(new SecretKeySpec(_, keyAlg)), params(nonce.repr))
          if aad.length > 0 then c.updateAAD(aad.toArray)
          Slice.of(c.doFinal(plaintext.toArray))
        }
      }
      private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): Eff[AuthFailed, Slice] = opE {
        key.material { k =>
          val c = JCipher.getInstance(cipherName)
          c.init(JCipher.DECRYPT_MODE, wiping(k)(new SecretKeySpec(_, keyAlg)), params(nonce.repr))
          if aad.length > 0 then c.updateAAD(aad.toArray)
          try Right(Slice.of(c.doFinal(ciphertext.toArray)))
          catch case _: javax.crypto.AEADBadTagException => Left(AuthFailed)
        }
      }

  // AES-CBC-HMAC-SHA2 composite (RFC 7518 section 5.2): key = MAC || ENC halves; tag is the leading
  // half of HMAC over aad || iv || ct || AL, with AL the 64-bit big-endian aad bit length.
  private def aeadCbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], mac: String): AEAD[A] = new AEAD[A]:
    // Both halves are windows onto the one key copy `wiping` erases, so neither becomes a copy of
    // its own.
    private def macTag(kb: Array[Byte], half: Int, iv: Array[Byte], aad: Slice, ct: Array[Byte]): Array[Byte] =
      val al = new Array[Byte](8)
      Slice.of(al).writeBE[Long](0, aad.length.toLong * 8)
      hmac(mac, kb, 0, half, aad.toArray ++ iv ++ ct ++ al).take(spec.tagLength)
    private def cipher(mode: Int, kb: Array[Byte], half: Int, iv: Array[Byte]): JCipher =
      val c = JCipher.getInstance("AES/CBC/PKCS5Padding")
      c.init(mode, new SecretKeySpec(kb, half, half, "AES"), new IvParameterSpec(iv))
      c
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEff[Slice] = op {
      key.material { k =>
        wiping(k) { kb =>
          val half = kb.length / 2
          val iv = nonce.repr
          val ct = cipher(JCipher.ENCRYPT_MODE, kb, half, iv).doFinal(plaintext.toArray)
          Slice.of(ct ++ macTag(kb, half, iv, aad, ct))
        }
      }
    }
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): Eff[AuthFailed, Slice] = opE {
      key.material { k =>
        wiping(k) { kb =>
          val half = kb.length / 2
          val iv = nonce.repr
          val whole = ciphertext.toArray
          if whole.length < spec.tagLength then Left(AuthFailed)
          else
            val ct = whole.take(whole.length - spec.tagLength)
            val tag = whole.drop(whole.length - spec.tagLength)
            if !Slice.of(macTag(kb, half, iv, aad, ct)).constantTimeEquals(Slice.of(tag)) then Left(AuthFailed)
            else
              // Both failures are data, and this channel is typed.
              try Right(Slice.of(cipher(JCipher.DECRYPT_MODE, kb, half, iv).doFinal(ct)))
              catch case _: javax.crypto.BadPaddingException | _: javax.crypto.IllegalBlockSizeException => Left(AuthFailed)
        }
      }
    }

  private def aeadGcm[A <: AeadAlgorithm](spec: AeadSpec[A]): AEAD[A] = aeadAead(spec, "AES/GCM/NoPadding", "AES", gcm = true)
  private def aeadChaCha(spec: AeadSpec[ChaCha20Poly1305]): AEAD[ChaCha20Poly1305] =
    aeadAead(spec, "ChaCha20-Poly1305", "ChaCha20", gcm = false)

  final private class GcmEngine[A <: AeadAlgorithm](kb: Array[Byte], spec: AeadSpec[A], cipherName: String, keyAlg: String, gcm: Boolean)
      extends Cipher.Engine[A]:
    private val jk = new SecretKeySpec(kb, keyAlg)

    // Runs per record on the loop thread: `getInstance` was 2821 ns of the 3750 ns a 1300-byte
    // AES-256-GCM record cost on JDK 25, so the instance is held and re-initialised per nonce
    // (1263 ns with the buffer forms below). JCA accepts every nonce but a repeat of the one
    // immediately preceding, which turns the single misuse this whole tier exists to prevent into
    // a loud failure instead of a silent one.
    private val engine = JCipher.getInstance(cipherName)
    private def params(nonce: Slice) =
      if gcm then new GCMParameterSpec(spec.tagLength * 8, nonce.unsafeArray, nonce.unsafeOffset, nonce.length)
      else new IvParameterSpec(nonce.unsafeArray, nonce.unsafeOffset, nonce.length)
    private def prepare(mode: Int, aad: Slice, nonce: Slice): Unit =
      engine.init(mode, jk, params(nonce))
      if aad.length > 0 then engine.updateAAD(aad.unsafeArray, aad.unsafeOffset, aad.length)
    private[kufuli] def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
      prepare(JCipher.ENCRYPT_MODE, aad, nonce)
      engine.doFinal(src.unsafeArray, src.unsafeOffset, src.length, dst.unsafeArray, dst.unsafeOffset)
    private[kufuli] def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      prepare(JCipher.DECRYPT_MODE, aad, nonce)
      try Right(engine.doFinal(src.unsafeArray, src.unsafeOffset, src.length, dst.unsafeArray, dst.unsafeOffset))
      catch
        case _: javax.crypto.AEADBadTagException =>
          // `Left` carries no length, so the buffer has to be clean for it to mean nothing was
          // produced. SunJCE erases the output itself (executed), but the JCA contract does not say
          // so and a JVM's security provider is a deployment choice - this makes it kufuli's own.
          // aws-lc states the same erase in its own contract (aead.h:336), so Native needs none.
          dst.take(math.min(dst.length, math.max(0, src.length - spec.tagLength))).wipe()
          Left(AuthFailed)
    private[jca] def release(): Unit = Slice.of(kb).wipe()
  end GcmEngine

  // The engine's key copy is wiped at release, so it does not outlive the Resource. JCA's own
  // SecretKeySpec copy is beyond reach - the documented JVM best-effort boundary.
  private def cipheringOf[A <: AeadAlgorithm](spec: AeadSpec[A], cipherName: String, keyAlg: String, gcm: Boolean): Ciphering[A] =
    new Ciphering[A]:
      private[kufuli] def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]] =
        Resource
          .make(IO {
            val kb = key.material(_.toArray)
            // Engine construction sits between the copy and the release becoming armed, so its
            // failure erases the copy here.
            try new GcmEngine(kb, spec, cipherName, keyAlg, gcm)
            catch
              case t: Throwable =>
                Slice.of(kb).wipe()
                throw t // scalafix:ok DisableSyntax.throw
          })(e => IO(e.release()))
          .map(identity)
  private def cipheringGcm[A <: AeadAlgorithm](spec: AeadSpec[A]): Ciphering[A] =
    cipheringOf(spec, "AES/GCM/NoPadding", "AES", gcm = true)
  private def cipheringChaCha(spec: AeadSpec[ChaCha20Poly1305]): Ciphering[ChaCha20Poly1305] =
    cipheringOf(spec, "ChaCha20-Poly1305", "ChaCha20", gcm = false)

  private def macOf[H <: MacAlgorithm](name: String): MAC[H] = new MAC[H]:
    private[kufuli] def sign(key: SecretKey[H], data: Slice): UEff[Signature[H]] =
      op(Signature.unsafe[H](key.material(k => wiping(k)(kb => hmac(name, kb, data.toArray)))))

  private def pssParams(hash: Sha2): java.security.spec.PSSParameterSpec =
    val (h, mgf, len) = hash match
      case _: Sha256.type => ("SHA-256", MGF1ParameterSpec.SHA256, 32)
      case _: Sha384.type => ("SHA-384", MGF1ParameterSpec.SHA384, 48)
      case _: Sha512.type => ("SHA-512", MGF1ParameterSpec.SHA512, 64)
    new java.security.spec.PSSParameterSpec(h, "MGF1", mgf, len, 1)
  private def pkcs1Name(hash: Sha2): String = hash match
    case _: Sha256.type => "SHA256withRSA"
    case _: Sha384.type => "SHA384withRSA"
    case _: Sha512.type => "SHA512withRSA"
  private def ecdsaName(hash: Sha2): String = hash match
    case _: Sha256.type => "SHA256withECDSA"
    case _: Sha384.type => "SHA384withECDSA"
    case _: Sha512.type => "SHA512withECDSA"

  private def edSigner: Signing[Ed25519] = new Signing[Ed25519]:
    private[kufuli] def sign(key: PrivateKey[Ed25519], data: Slice, scheme: Scheme[Ed25519]): UEff[Signature[Ed25519]] = op {
      key.material { s =>
        val sg = JSignature.getInstance("Ed25519")
        sg.initSign(wiping(s)(parsePriv("Ed25519", _)))
        sg.update(data.toArray)
        Signature.unsafe[Ed25519](sg.sign())
      }
    }
  private def edVerifier: Verifying[Ed25519] = new Verifying[Ed25519]:
    private[kufuli] def verify(
      key: PublicKey[Ed25519],
      data: Slice,
      sig: Signature[Ed25519],
      scheme: Scheme[Ed25519]): Eff[SignatureRejected, Unit] =
      opE {
        val sg = JSignature.getInstance("Ed25519")
        sg.initVerify(parsePub("Ed25519", keyBytes(key.repr)))
        sg.update(data.toArray)
        if sg.verify(sig.repr) then Right(()) else Left(SignatureRejected)
      }

  private def ecSigner[C <: EcCurve](fieldLength: Int): Signing[C] = new Signing[C]:
    private[kufuli] def sign(key: PrivateKey[C], data: Slice, scheme: Scheme[C]): UEff[Signature[C]] = op {
      val h = scheme.runtimeChecked match
        case ECDSA(hash) => hash
      key.material { s =>
        val sg = JSignature.getInstance(ecdsaName(h))
        sg.initSign(wiping(s)(parsePriv("EC", _)))
        sg.update(data.toArray)
        Signature.unsafe[C](demand(Signature.ecdsaDerToRaw(Slice.of(sg.sign()), fieldLength)))
      }
    }
  private def ecVerifier[C <: EcCurve]: Verifying[C] = new Verifying[C]:
    private[kufuli] def verify(key: PublicKey[C], data: Slice, sig: Signature[C], scheme: Scheme[C]): Eff[SignatureRejected, Unit] = opE {
      val h = scheme.runtimeChecked match
        case ECDSA(hash) => hash
      val sg = JSignature.getInstance(ecdsaName(h))
      sg.initVerify(parsePub("EC", keyBytes(key.repr)))
      sg.update(data.toArray)
      if sg.verify(Signature.ecdsaRawToDer(sig.repr)) then Right(()) else Left(SignatureRejected)
    }

  private def rsaSigner: Signing[RSA] = new Signing[RSA]:
    private[kufuli] def sign(key: PrivateKey[RSA], data: Slice, scheme: Scheme[RSA]): UEff[Signature[RSA]] = op {
      key.material { s =>
        val priv = wiping(s)(parsePriv("RSA", _))
        val sg = scheme.runtimeChecked match
          case RsaPss(h)   => val x = JSignature.getInstance("RSASSA-PSS"); x.setParameter(pssParams(h)); x
          case RsaPkcs1(h) => JSignature.getInstance(pkcs1Name(h))
        sg.initSign(priv)
        sg.update(data.toArray)
        Signature.unsafe[RSA](sg.sign())
      }
    }
  private def rsaVerifier: Verifying[RSA] = new Verifying[RSA]:
    private[kufuli] def verify(key: PublicKey[RSA], data: Slice, sig: Signature[RSA], scheme: Scheme[RSA]): Eff[SignatureRejected, Unit] =
      opE {
        val pub = parsePub("RSA", keyBytes(key.repr))
        val sg = scheme.runtimeChecked match
          case RsaPss(h)   => val x = JSignature.getInstance("RSASSA-PSS"); x.setParameter(pssParams(h)); x
          case RsaPkcs1(h) => JSignature.getInstance(pkcs1Name(h))
        sg.initVerify(pub)
        sg.update(data.toArray)
        if sg.verify(sig.repr) then Right(()) else Left(SignatureRejected)
      }

  private def agreementOf[A <: AgreementAlgorithm](name: String, keyAlg: String): Agreement[A] = new Agreement[A]:
    private[kufuli] def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEff[SharedSecret] = op {
      priv.material { s =>
        val ka = KeyAgreement.getInstance(name)
        ka.init(wiping(s)(parsePriv(keyAlg, _)))
        val _ = ka.doPhase(parsePub(keyAlg, keyBytes(pub.repr)), true)
        SharedSecret.unsafe(ka.generateSecret())
      }
    }

  // ML-KEM public keys travel raw on the wire; store the standard SPKI and convert at the edges.
  private def mlkemOid(spec: KemSpec[?]): Array[Byte] = spec match
    case _: MlKem768.type  => Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02)
    case _: MlKem1024.type => Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03)
  private def mlkemSpki(spec: KemSpec[?], raw: Array[Byte]): Array[Byte] =
    DER.sequence(DER.sequence(DER.objectId(mlkemOid(spec))), DER.bitString(raw))
  // The argument is an SPKI kufuli marshalled or JCA re-marshalled, so an unwalkable one is a
  // backend anomaly rather than caller data, and the wire must not receive a short key for it.
  private def mlkemRaw(spki: Array[Byte]): Array[Byte] =
    demand(DER.spkiPublicBits(Slice.of(spki))).toArray

  private def kemOf[K <: KemAlgorithm]: KEM[K] = new KEM[K]:
    private[kufuli] def encapsulate(pub: PublicKey[K]): UEff[Encapsulated[K]] = op {
      val e = JKem.getInstance("ML-KEM").newEncapsulator(parsePub("ML-KEM", keyBytes(pub.repr))).encapsulate()
      Encapsulated(SharedSecret.unsafe(e.key.getEncoded), KemCiphertext.unsafe(e.encapsulation()))
    }
    private[kufuli] def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEff[SharedSecret] = op {
      priv.material { s =>
        val d = JKem.getInstance("ML-KEM").newDecapsulator(wiping(s)(parsePriv("ML-KEM", _)))
        SharedSecret.unsafe(d.decapsulate(ct.repr).getEncoded)
      }
    }

  private def wrapAes[W <: WrapAlgorithm](cipherName: String): Wrap[W] = new Wrap[W]:
    private[kufuli] def wrap(kek: SecretKey[W], target: Slice): UEff[Slice] = op {
      kek.material { k =>
        val c = JCipher.getInstance(cipherName)
        c.init(JCipher.WRAP_MODE, wiping(k)(new SecretKeySpec(_, "AES")))
        Slice.of(c.wrap(wiping(target)(new SecretKeySpec(_, "AES"))))
      }
    }
    private[kufuli] def unwrap(kek: SecretKey[W], wrapped: Slice): Eff[UnwrapFailed, Slice] = opE {
      kek.material { k =>
        val c = JCipher.getInstance(cipherName)
        c.init(JCipher.UNWRAP_MODE, wiping(k)(new SecretKeySpec(_, "AES")))
        try Right(Slice.of(c.unwrap(wrapped.toArray, "AES", JCipher.SECRET_KEY).getEncoded))
        catch case _: java.security.GeneralSecurityException => Left(UnwrapFailed)
      }
    }

  private[kufuli] val kdf: KDF = new KDF:
    private[kufuli] def extract(hash: Sha2, salt: Slice, ikm: Slice): UEff[PRK] = op {
      val name = hmacName(hash)
      val key = if salt.length == 0 then new Array[Byte](hash.length) else salt.toArray
      wiping(ikm)(bytes => PRK.unsafe(hmac(name, key, bytes)))
    }
    private[kufuli] def expand(hash: Sha2, prk: PRK, info: Slice, length: Int): UEff[Slice] = op {
      prk.read { p =>
        wiping(p) { key =>
          val name = hmacName(hash)
          val hlen = hash.length
          val n = (length + hlen - 1) / hlen
          val out = new Array[Byte](n * hlen)
          val infoBytes = info.toArray
          // The counter chain carries the derived key forward, so each round erases its input and
          // its predecessor - in `finally`, so a failing primitive cannot abandon them - and the
          // accumulator is erased on every exit path.
          @tailrec def go(i: Int, prev: Array[Byte]): Unit =
            if i > n then Slice.of(prev).wipe()
            else
              val input = prev ++ infoBytes ++ Array[Byte](i.toByte)
              val block =
                try hmac(name, key, input)
                finally
                  Slice.of(input).wipe()
                  Slice.of(prev).wipe()
              Array.copy(block, 0, out, (i - 1) * hlen, hlen)
              go(i + 1, block)
          try
            go(1, Array.emptyByteArray)
            Slice.of(out.take(length))
          finally Slice.of(out).wipe()
        }
      }
    }
    private[kufuli] def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEff[Slice] = blockingOp {
      val name = hmacName(hash)
      wiping(password) { pw =>
        val hlen = hash.length
        val blocks = (length + hlen - 1) / hlen
        val out = new Array[Byte](blocks * hlen)
        val saltBytes = salt.toArray
        // Each U is derived key material in its own right, so it is erased once the next one is
        // folded in - in `finally`, so a failing primitive cannot abandon it - and the block
        // accumulator and output are erased on every exit path.
        @tailrec def accumulate(t: Array[Byte], u: Array[Byte], it: Int): Array[Byte] =
          if it >= iterations then
            Slice.of(u).wipe()
            t
          else
            val next =
              try hmac(name, pw, u)
              finally Slice.of(u).wipe()
            @tailrec def xor(j: Int): Unit = if j < hlen then
              t(j) = (t(j) ^ next(j)).toByte; xor(j + 1)
            xor(0)
            accumulate(t, next, it + 1)
        @tailrec def block(b: Int): Unit =
          if b <= blocks then
            val intB = Array[Byte]((b >>> 24).toByte, (b >>> 16).toByte, (b >>> 8).toByte, b.toByte)
            val u1 = hmac(name, pw, saltBytes ++ intB)
            val t = u1.clone
            try
              val _ = accumulate(t, u1, 1)
              Array.copy(t, 0, out, (b - 1) * hlen, hlen)
            finally Slice.of(t).wipe()
            block(b + 1)
        try
          block(1)
          Slice.of(out.take(length))
        finally Slice.of(out).wipe()
      }
    }

  private def hashOf[D <: HashAlgorithm](name: String): Hash[D] = new Hash[D]:
    private[kufuli] def digest(data: Slice): UEff[Digest] = op(Digest.unsafe(MessageDigest.getInstance(name).digest(data.toArray)))
  private def hashingOf[D <: HashAlgorithm](name: String): Hashing[D] = new Hashing[D]:
    private[kufuli] def hasher: Resource[IO, Hasher] = Resource.eval(IO {
      new Hasher:
        private val md = MessageDigest.getInstance(name)
        def update(data: Slice): Unit = md.update(data.toArray)
        def digest: Digest = demand(md.clone() match
          case snapshot: MessageDigest => Right(Digest.unsafe(snapshot.digest()))
          case _                       => Left(()))
    })

  private def oaepSpec(hash: Sha2): OAEPParameterSpec =
    val (h, mgf) = hash match
      case _: Sha256.type => ("SHA-256", MGF1ParameterSpec.SHA256)
      case _: Sha384.type => ("SHA-384", MGF1ParameterSpec.SHA384)
      case _: Sha512.type => ("SHA-512", MGF1ParameterSpec.SHA512)
    new OAEPParameterSpec(h, "MGF1", mgf, PSource.PSpecified.DEFAULT)
  private[kufuli] val oaep: OAEP = new OAEP:
    private[kufuli] def encrypt(key: PublicKey[RSA], plaintext: Slice, scheme: RsaOaep): UEff[Slice] = op {
      val c = JCipher.getInstance("RSA/ECB/OAEPPadding")
      c.init(JCipher.ENCRYPT_MODE, parsePub("RSA", keyBytes(key.repr)), oaepSpec(scheme.hash))
      Slice.of(c.doFinal(plaintext.toArray))
    }
    private[kufuli] def decrypt(key: PrivateKey[RSA], ciphertext: Slice, scheme: RsaOaep): Eff[AuthFailed, Slice] = opE {
      key.material { s =>
        val c = JCipher.getInstance("RSA/ECB/OAEPPadding")
        c.init(JCipher.DECRYPT_MODE, wiping(s)(parsePriv("RSA", _)), oaepSpec(scheme.hash))
        try Right(Slice.of(c.doFinal(ciphertext.toArray)))
        catch case _: javax.crypto.BadPaddingException | _: javax.crypto.IllegalBlockSizeException => Left(AuthFailed)
      }
    }

  private[kufuli] val edKeys: EdKeys = new EdKeys:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = op {
      val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[Ed25519]] =
      opE(storePub[Ed25519]("Ed25519", DER.Alg.Ed, DER.edSpkiPrefix ++ bytes.toArray))
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[Ed25519]] =
      opE(storePub[Ed25519]("Ed25519", DER.Alg.Ed, der.toArray))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[Ed25519]] =
      opE(storePriv[Ed25519]("Ed25519", DER.Alg.Ed, der.toArray))
    private[kufuli] def raw(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] =
      op(publicPoint(key.repr, 32))
    private[kufuli] def spki(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(s => wiping(s)(IArray.from(_)))))

  private[kufuli] val xKeys: XKeys = new XKeys:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = op {
      val kp = KeyPairGenerator.getInstance("X25519").generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[X25519]] =
      opE(storePub[X25519]("X25519", DER.Alg.X, DER.xSpkiPrefix ++ bytes.toArray))
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[X25519]] =
      opE(storePub[X25519]("X25519", DER.Alg.X, der.toArray))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[X25519]] =
      opE(storePriv[X25519]("X25519", DER.Alg.X, der.toArray))
    private[kufuli] def raw(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] =
      op(publicPoint(key.repr, 32))
    private[kufuli] def spki(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(s => wiping(s)(IArray.from(_)))))

  private def ecKeysOf[C <: EcCurve](curveName: String, curve: DER.Alg, fieldLength: Int, prefix: Array[Byte]): EcKeys[C] = new EcKeys[C]:
    private val pointLength = 1 + 2 * fieldLength
    private[kufuli] def generate: UEff[KeyPair[PublicKey[C], PrivateKey[C]]] = op {
      val kpg = KeyPairGenerator.getInstance("EC")
      kpg.initialize(new ECGenParameterSpec(curveName))
      val kp = kpg.generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    private[kufuli] def fromSec1(point: Slice): Eff[Refused, PublicKey[C]] =
      opE(storeEcPub[C](curve, prefix ++ point.toArray))
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[C]] =
      opE(storeEcPub[C](curve, der.toArray))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[C]] =
      opE(storePriv[C]("EC", curve, der.toArray))
    private[kufuli] def sec1(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]] =
      op(publicPoint(key.repr, pointLength))
    private[kufuli] def spki(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[C]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(s => wiping(s)(IArray.from(_)))))

  private[kufuli] val rsaKeys: RsaKeys = new RsaKeys:
    private[kufuli] def generate(size: RSA.Size): UEff[KeyPair[PublicKey[RSA], PrivateKey[RSA]]] = blockingOp {
      val kpg = KeyPairGenerator.getInstance("RSA")
      kpg.initialize(size.bits)
      val kp = kpg.generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    private[kufuli] def fromComponents(modulus: Slice, exponent: Slice): Eff[Refused, PublicKey[RSA]] = opE {
      refusing {
        val n = new BigInteger(1, modulus.toArray)
        val e = new BigInteger(1, exponent.toArray)
        val jk = kf("RSA").generatePublic(new RSAPublicKeySpec(n, e))
        PublicKey.unsafe[RSA](keyRepr(jk.getEncoded))
      }
    }
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[RSA]] =
      opE(storePub[RSA]("RSA", DER.Alg.Rsa, der.toArray))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[RSA]] =
      opE(storePriv[RSA]("RSA", DER.Alg.Rsa, der.toArray))
    private[kufuli] def components(key: PublicKey[RSA]): Eff[KeyNotExportable, RSA.Components] = op {
      // The non-RSA arm is unreachable with a conformant provider, and a JWK built from an export
      // that succeeded without components would carry empty `n` and `e`.
      demand(parsePub("RSA", keyBytes(key.repr)) match
        case jk: RSAPublicKey =>
          Right(RSA.Components(IArray.from(unsigned(jk.getModulus)), IArray.from(unsigned(jk.getPublicExponent))))
        case _ => Left(()))
    }
    private[kufuli] def spki(key: PublicKey[RSA]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[RSA]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(s => wiping(s)(IArray.from(_)))))

  // JCA has no seeded ML-KEM import: its generator draws FIPS 203's (d || z) from the SecureRandom
  // it is handed and stores those 64 bytes verbatim as the PKCS#8 private key, so replaying the seed
  // through this source reproduces the published pair exactly (executed against JDK 25 for both
  // parameter sets). A wrong draw order would fail the conformance vectors immediately.
  final private class SeedSource(seed: Array[Byte]) extends SecureRandom:
    private val taken = new AtomicInteger(0)
    override def nextBytes(bytes: Array[Byte]): Unit =
      val from = taken.getAndAdd(bytes.length)
      bytes.indices.foreach(i => bytes(i) = if from + i < seed.length then seed(from + i) else 0.toByte)

  private def kemKeysOf[K <: KemAlgorithm](spec: KemSpec[K], param: String): KemKeys[K] = new KemKeys[K]:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[K], PrivateKey[K]]] = op {
      val kp = KeyPairGenerator.getInstance(param).generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[K]] = opE {
      val spki = mlkemSpki(spec, bytes.toArray)
      // The KeyFactory accepts any well-formed encoding; FIPS 203 section 7.2's coefficient check
      // runs when an encapsulator is constructed, so one is constructed here and discarded - the
      // peer key is adversarial input and belongs in the typed channel at import.
      refusing {
        val _ = JKem.getInstance("ML-KEM").newEncapsulator(parsePub("ML-KEM", spki))
        PublicKey.unsafe[K](keyRepr(spki))
      }
    }
    private[kufuli] def raw(key: PublicKey[K]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(mlkemRaw(keyBytes(key.repr))))
    private[kufuli] def fromSeed(seed: Slice): Eff[InvalidKey, KeyPair[PublicKey[K], PrivateKey[K]]] = opE {
      if seed.length != 64 then Left(InvalidKey.WrongLength(64, seed.length))
      else
        refusing {
          // The source outlives the draw only as garbage, and it is the seed pair itself.
          wiping(seed) { bytes =>
            val g = KeyPairGenerator.getInstance(param)
            g.initialize(new NamedParameterSpec(param), new SeedSource(bytes))
            val kp = g.generateKeyPair()
            KeyPair(PublicKey.unsafe[K](keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe[K](kp.getPrivate.getEncoded))
          }
        }.left.map(_ => InvalidKey.Malformed)
    }

  // Capability bundles the JVM platform table wires each companion into.
  private[kufuli] trait RandomDefault:
    given Random = random
  private[kufuli] trait AeadUniversal:
    given AEAD[AesGcm128] = aeadGcm(AesGcm128)
    given AEAD[AesGcm192] = aeadGcm(AesGcm192)
    given AEAD[AesGcm256] = aeadGcm(AesGcm256)
    given AEAD[A128CbcHs256] = aeadCbcHs(A128CbcHs256, "HmacSHA256")
    given AEAD[A256CbcHs512] = aeadCbcHs(A256CbcHs512, "HmacSHA512")
  private[kufuli] trait AeadChaCha:
    given AEAD[ChaCha20Poly1305] = aeadChaCha(ChaCha20Poly1305)
  private[kufuli] trait CipheringUniversal:
    given Ciphering[AesGcm128] = cipheringGcm(AesGcm128)
    given Ciphering[AesGcm192] = cipheringGcm(AesGcm192)
    given Ciphering[AesGcm256] = cipheringGcm(AesGcm256)
  private[kufuli] trait CipheringChaCha:
    given Ciphering[ChaCha20Poly1305] = cipheringChaCha(ChaCha20Poly1305)
  private[kufuli] trait MacAll:
    given MAC[HmacSha256] = macOf("HmacSHA256")
    given MAC[HmacSha384] = macOf("HmacSHA384")
    given MAC[HmacSha512] = macOf("HmacSHA512")
    given MAC[HmacSha1] = macOf("HmacSHA1")
  private[kufuli] trait SignersAll:
    given Signing[Ed25519] = edSigner
    given Signing[P256] = ecSigner(32)
    given Signing[P384] = ecSigner(48)
    given Signing[P521] = ecSigner(66)
    given Signing[RSA] = rsaSigner
  private[kufuli] trait VerifiersAll:
    given Verifying[Ed25519] = edVerifier
    given Verifying[P256] = ecVerifier
    given Verifying[P384] = ecVerifier
    given Verifying[P521] = ecVerifier
    given Verifying[RSA] = rsaVerifier
  private[kufuli] trait AgreementAll:
    given Agreement[X25519] = agreementOf("X25519", "X25519")
    given Agreement[P256] = agreementOf("ECDH", "EC")
    given Agreement[P384] = agreementOf("ECDH", "EC")
    given Agreement[P521] = agreementOf("ECDH", "EC")
  private[kufuli] trait KemAll:
    given KEM[MlKem768] = kemOf
    given KEM[MlKem1024] = kemOf
  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapAes("AESWrap")
    given Wrap[AesKw256] = wrapAes("AESWrap")
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapAes("AESWrapPad")
    given Wrap[AesKwp256] = wrapAes("AESWrapPad")
  private[kufuli] trait KdfDefault:
    given KDF = kdf
  private[kufuli] trait HashAll:
    given Hash[Sha1] = hashOf("SHA-1")
    given Hash[Sha256] = hashOf("SHA-256")
    given Hash[Sha384] = hashOf("SHA-384")
    given Hash[Sha512] = hashOf("SHA-512")
  private[kufuli] trait HashingSync:
    given Hashing[Sha256] = hashingOf("SHA-256")
    given Hashing[Sha384] = hashingOf("SHA-384")
    given Hashing[Sha512] = hashingOf("SHA-512")
  private[kufuli] trait OaepDefault:
    given OAEP = oaep
  private[kufuli] trait EdKeysJca:
    given EdKeys = edKeys
  private[kufuli] trait XKeysJca:
    given XKeys = xKeys
  private[kufuli] trait EcKeysJca:
    given EcKeys[P256] = ecKeysOf("secp256r1", DER.Alg.EcP256, 32, DER.p256SpkiPrefix)
    given EcKeys[P384] = ecKeysOf("secp384r1", DER.Alg.EcP384, 48, DER.p384SpkiPrefix)
    given EcKeys[P521] = ecKeysOf("secp521r1", DER.Alg.EcP521, 66, DER.p521SpkiPrefix)
  private[kufuli] trait RsaKeysJca:
    given RsaKeys = rsaKeys
  private[kufuli] trait KemKeysJca:
    given KemKeys[MlKem768] = kemKeysOf(MlKem768, "ML-KEM-768")
    given KemKeys[MlKem1024] = kemKeysOf(MlKem1024, "ML-KEM-1024")
end jca
