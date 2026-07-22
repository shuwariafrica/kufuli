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
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher as JCipher
import javax.crypto.KEM
import javax.crypto.KeyAgreement
import javax.crypto.Mac as JMac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import cats.effect.IO
import cats.effect.Resource

private[kufuli] object jca:

  private def op[A](thunk: => A): UEffIO[A] = EffIO.liftF(guard(IO(thunk)))
  private def blockingOp[A](thunk: => A): UEffIO[A] = EffIO.liftF(guard(IO.blocking(thunk)))
  private def opE[E <: Throwable, A](thunk: => Either[E, A]): EffIO[E, A] = EffIO.lift(guard(IO(thunk)))

  // Import validation: a malformed encoding is a typed value, not a defect.
  private def validating[A](notOnCurve: Boolean)(f: => A): Either[InvalidKey, A] =
    try Right(f)
    catch
      case _: InvalidKeySpecException           => Left(if notOnCurve then InvalidKey.NotOnCurve else InvalidKey.Malformed)
      case _: java.security.InvalidKeyException => Left(if notOnCurve then InvalidKey.NotOnCurve else InvalidKey.Malformed)

  private def kf(alg: String): KeyFactory = KeyFactory.getInstance(alg)
  private def parsePub(alg: String, spki: Array[Byte]): JPublicKey = kf(alg).generatePublic(new X509EncodedKeySpec(spki))
  private def parsePriv(alg: String, pkcs8: Array[Byte]): JPrivateKey = kf(alg).generatePrivate(new PKCS8EncodedKeySpec(pkcs8))
  private def unsigned(bi: BigInteger): Array[Byte] =
    val b = bi.toByteArray
    if b.length > 1 && b(0) == 0.toByte then b.drop(1) else b

  private def hmacName(hash: Sha2): String = hash match
    case _: Sha256.type => "HmacSHA256"
    case _: Sha384.type => "HmacSHA384"
    case _: Sha512.type => "HmacSHA512"

  private def hmac(name: String, key: Array[Byte], data: Array[Byte]): Array[Byte] =
    val m = JMac.getInstance(name)
    m.init(new SecretKeySpec(key, name))
    m.doFinal(data)

  private val rng = new SecureRandom()
  private[kufuli] val random: Random = new Random:
    def bytes(n: Int): UEffIO[Slice] = op { val b = new Array[Byte](n); rng.nextBytes(b); Slice.of(b) }
    def fill(dst: Slice): UEffIO[Unit] = op {
      val b = new Array[Byte](dst.length)
      rng.nextBytes(b)
      val _ = Slice.of(b).copyInto(dst)
    }

  // AES-GCM and ChaCha20-Poly1305 are JCA AEAD ciphers (output is ct || tag). AES-CBC-HMAC-SHA2 is
  // the RFC 7518 composite (encrypt-then-MAC); the shared box layout hands this tier its whole
  // ciphertext (ct || tag) back on open.
  private def aeadAead[A <: AeadAlgorithm](spec: AeadSpec[A], cipherName: String, keyAlg: String, gcm: Boolean): Aead[A] =
    new Aead[A]:
      private def params(nonce: Array[Byte]) =
        if gcm then new GCMParameterSpec(spec.tagLength * 8, nonce) else new IvParameterSpec(nonce)
      def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
        key.read { k =>
          val c = JCipher.getInstance(cipherName)
          c.init(JCipher.ENCRYPT_MODE, new SecretKeySpec(k.toArray, keyAlg), params(nonce.repr))
          if aad.length > 0 then c.updateAAD(aad.toArray)
          Slice.of(c.doFinal(plaintext.toArray))
        }
      }
      def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice] = opE {
        key.read { k =>
          val c = JCipher.getInstance(cipherName)
          c.init(JCipher.DECRYPT_MODE, new SecretKeySpec(k.toArray, keyAlg), params(nonce.repr))
          if aad.length > 0 then c.updateAAD(aad.toArray)
          try Right(Slice.of(c.doFinal(ciphertext.toArray)))
          catch case _: javax.crypto.AEADBadTagException => Left(AuthFailed)
        }
      }

  // AES-CBC-HMAC-SHA2 composite (RFC 7518 section 5.2): key = MAC || ENC halves; tag is the leading
  // half of HMAC over aad || iv || ct || AL, with AL the 64-bit big-endian aad bit length.
  private def aeadCbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], mac: String): Aead[A] = new Aead[A]:
    private def macTag(macKey: Array[Byte], iv: Array[Byte], aad: Slice, ct: Array[Byte]): Array[Byte] =
      val al = new Array[Byte](8)
      Slice.of(al).writeBE[Long](0, aad.length.toLong * 8)
      hmac(mac, macKey, aad.toArray ++ iv ++ ct ++ al).take(spec.tagLength)
    def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
      key.read { k =>
        val kb = k.toArray
        val half = kb.length / 2
        val macKey = kb.take(half)
        val encKey = kb.drop(half)
        val iv = nonce.repr
        val c = JCipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(JCipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv))
        val ct = c.doFinal(plaintext.toArray)
        Slice.of(ct ++ macTag(macKey, iv, aad, ct))
      }
    }
    def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice] = opE {
      key.read { k =>
        val kb = k.toArray
        val half = kb.length / 2
        val macKey = kb.take(half)
        val encKey = kb.drop(half)
        val iv = nonce.repr
        val whole = ciphertext.toArray
        if whole.length < spec.tagLength then Left(AuthFailed)
        else
          val ct = whole.take(whole.length - spec.tagLength)
          val tag = whole.drop(whole.length - spec.tagLength)
          if !Slice.of(macTag(macKey, iv, aad, ct)).constantTimeEquals(Slice.of(tag)) then Left(AuthFailed)
          else
            val c = JCipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(JCipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv))
            try Right(Slice.of(c.doFinal(ct)))
            catch case _: javax.crypto.BadPaddingException => Left(AuthFailed)
      }
    }

  private def aeadGcm[A <: AeadAlgorithm](spec: AeadSpec[A]): Aead[A] = aeadAead(spec, "AES/GCM/NoPadding", "AES", gcm = true)
  private def aeadChaCha(spec: AeadSpec[ChaCha20Poly1305]): Aead[ChaCha20Poly1305] =
    aeadAead(spec, "ChaCha20-Poly1305", "ChaCha20", gcm = false)

  final private class GcmEngine[A <: AeadAlgorithm](kb: Array[Byte], spec: AeadSpec[A], cipherName: String, keyAlg: String, gcm: Boolean)
      extends Cipher.Engine[A]:
    private val jk = new SecretKeySpec(kb, keyAlg)
    private def params(nonce: Slice) =
      if gcm then new GCMParameterSpec(spec.tagLength * 8, nonce.toArray) else new IvParameterSpec(nonce.toArray)
    def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
      val c = JCipher.getInstance(cipherName)
      c.init(JCipher.ENCRYPT_MODE, jk, params(nonce))
      if aad.length > 0 then c.updateAAD(aad.toArray)
      val out = c.doFinal(src.toArray)
      val _ = Slice.of(out).copyInto(dst)
      out.length
    def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      val c = JCipher.getInstance(cipherName)
      c.init(JCipher.DECRYPT_MODE, jk, params(nonce))
      if aad.length > 0 then c.updateAAD(aad.toArray)
      try
        val out = c.doFinal(src.toArray)
        val _ = Slice.of(out).copyInto(dst)
        Right(out.length)
      catch case _: javax.crypto.AEADBadTagException => Left(AuthFailed)
  end GcmEngine

  private def cipheringGcm[A <: AeadAlgorithm](spec: AeadSpec[A]): Ciphering[A] = new Ciphering[A]:
    def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]] =
      Resource.eval(IO(new GcmEngine(key.read(_.toArray), spec, "AES/GCM/NoPadding", "AES", gcm = true)))
  private def cipheringChaCha(spec: AeadSpec[ChaCha20Poly1305]): Ciphering[ChaCha20Poly1305] =
    new Ciphering[ChaCha20Poly1305]:
      def engine(key: SecretKey[ChaCha20Poly1305]): Resource[IO, Cipher.Engine[ChaCha20Poly1305]] =
        Resource.eval(IO(new GcmEngine(key.read(_.toArray), spec, "ChaCha20-Poly1305", "ChaCha20", gcm = false)))

  private def macOf[H <: MacAlgorithm](name: String): Mac[H] = new Mac[H]:
    def sign(key: SecretKey[H], data: Slice): UEffIO[Signature[H]] =
      op(Signature.unsafe[H](key.read(k => hmac(name, k.toArray, data.toArray))))

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

  private def edSigner: Signer[Ed25519] = new Signer[Ed25519]:
    def sign(key: PrivateKey[Ed25519], data: Slice, scheme: Scheme[Ed25519]): UEffIO[Signature[Ed25519]] = op {
      key.read { s =>
        val sg = JSignature.getInstance("Ed25519")
        sg.initSign(parsePriv("Ed25519", s.toArray))
        sg.update(data.toArray)
        Signature.unsafe[Ed25519](sg.sign())
      }
    }
  private def edVerifier: Verifier[Ed25519] = new Verifier[Ed25519]:
    def verify(key: PublicKey[Ed25519], data: Slice, sig: Signature[Ed25519], scheme: Scheme[Ed25519]): EffIO[SignatureRejected, Unit] =
      opE {
        val sg = JSignature.getInstance("Ed25519")
        sg.initVerify(parsePub("Ed25519", keyBytes(key.repr)))
        sg.update(data.toArray)
        if sg.verify(sig.repr) then Right(()) else Left(SignatureRejected)
      }

  private def ecSigner[C <: EcCurve](fieldLength: Int): Signer[C] = new Signer[C]:
    def sign(key: PrivateKey[C], data: Slice, scheme: Scheme[C]): UEffIO[Signature[C]] = op {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => hash
      key.read { s =>
        val sg = JSignature.getInstance(ecdsaName(h))
        sg.initSign(parsePriv("EC", s.toArray))
        sg.update(data.toArray)
        Signature.unsafe[C](Signature.ecdsaDerToRaw(Slice.of(sg.sign()), fieldLength).getOrElse(new Array[Byte](2 * fieldLength)))
      }
    }
  private def ecVerifier[C <: EcCurve]: Verifier[C] = new Verifier[C]:
    def verify(key: PublicKey[C], data: Slice, sig: Signature[C], scheme: Scheme[C]): EffIO[SignatureRejected, Unit] = opE {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => hash
      val sg = JSignature.getInstance(ecdsaName(h))
      sg.initVerify(parsePub("EC", keyBytes(key.repr)))
      sg.update(data.toArray)
      if sg.verify(Signature.ecdsaRawToDer(sig.repr)) then Right(()) else Left(SignatureRejected)
    }

  private def rsaSigner: Signer[Rsa] = new Signer[Rsa]:
    def sign(key: PrivateKey[Rsa], data: Slice, scheme: Scheme[Rsa]): UEffIO[Signature[Rsa]] = op {
      key.read { s =>
        val priv = parsePriv("RSA", s.toArray)
        val sg = scheme.runtimeChecked match
          case RsaPss(h)   => val x = JSignature.getInstance("RSASSA-PSS"); x.setParameter(pssParams(h)); x
          case RsaPkcs1(h) => JSignature.getInstance(pkcs1Name(h))
        sg.initSign(priv)
        sg.update(data.toArray)
        Signature.unsafe[Rsa](sg.sign())
      }
    }
  private def rsaVerifier: Verifier[Rsa] = new Verifier[Rsa]:
    def verify(key: PublicKey[Rsa], data: Slice, sig: Signature[Rsa], scheme: Scheme[Rsa]): EffIO[SignatureRejected, Unit] = opE {
      val pub = parsePub("RSA", keyBytes(key.repr))
      val sg = scheme.runtimeChecked match
        case RsaPss(h)   => val x = JSignature.getInstance("RSASSA-PSS"); x.setParameter(pssParams(h)); x
        case RsaPkcs1(h) => JSignature.getInstance(pkcs1Name(h))
      sg.initVerify(pub)
      sg.update(data.toArray)
      if sg.verify(sig.repr) then Right(()) else Left(SignatureRejected)
    }

  private def agreementOf[A <: AgreementAlgorithm](name: String, keyAlg: String): Agreement[A] = new Agreement[A]:
    def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEffIO[SharedSecret] = op {
      priv.read { s =>
        val ka = KeyAgreement.getInstance(name)
        ka.init(parsePriv(keyAlg, s.toArray))
        val _ = ka.doPhase(parsePub(keyAlg, keyBytes(pub.repr)), true)
        SharedSecret.unsafe(ka.generateSecret())
      }
    }

  // ML-KEM public keys travel raw on the wire; store the standard SPKI and convert at the edges.
  private def mlkemOid(spec: KemSpec[?]): Array[Byte] = spec match
    case _: MlKem768.type  => Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02)
    case _: MlKem1024.type => Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03)
  private def mlkemSpki(spec: KemSpec[?], raw: Array[Byte]): Array[Byte] =
    Der.sequence(Der.sequence(Der.objectId(mlkemOid(spec))), Der.bitString(raw))
  private def mlkemRaw(spki: Array[Byte]): Array[Byte] =
    val s = Slice.of(spki)
    (for
      outer <- Der.read(s, 0, 0x30)
      alg <- Der.read(s, outer.contentOff, 0x30)
      bits <- Der.read(s, alg.next, 0x03)
    yield s.slice(bits.contentOff + 1, bits.next).toArray).getOrElse(Array.emptyByteArray)

  private def kemOf[K <: KemAlgorithm]: Kem[K] = new Kem[K]:
    def encapsulate(pub: PublicKey[K]): UEffIO[Encapsulated[K]] = op {
      val e = KEM.getInstance("ML-KEM").newEncapsulator(parsePub("ML-KEM", keyBytes(pub.repr))).encapsulate()
      Encapsulated(SharedSecret.unsafe(e.key.getEncoded), KemCiphertext.unsafe(e.encapsulation()))
    }
    def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEffIO[SharedSecret] = op {
      priv.read { s =>
        val d = KEM.getInstance("ML-KEM").newDecapsulator(parsePriv("ML-KEM", s.toArray))
        SharedSecret.unsafe(d.decapsulate(ct.repr).getEncoded)
      }
    }

  private def wrapAes[W <: WrapAlgorithm](cipherName: String): Wrap[W] = new Wrap[W]:
    def wrap(kek: SecretKey[W], target: Slice): UEffIO[Slice] = op {
      kek.read { k =>
        val c = JCipher.getInstance(cipherName)
        c.init(JCipher.WRAP_MODE, new SecretKeySpec(k.toArray, "AES"))
        Slice.of(c.wrap(new SecretKeySpec(target.toArray, "AES")))
      }
    }
    def unwrap(kek: SecretKey[W], wrapped: Slice): EffIO[UnwrapFailed, Slice] = opE {
      kek.read { k =>
        val c = JCipher.getInstance(cipherName)
        c.init(JCipher.UNWRAP_MODE, new SecretKeySpec(k.toArray, "AES"))
        try Right(Slice.of(c.unwrap(wrapped.toArray, "AES", JCipher.SECRET_KEY).getEncoded))
        catch case _: java.security.GeneralSecurityException => Left(UnwrapFailed)
      }
    }

  private[kufuli] val kdf: Kdf = new Kdf:
    def extract(hash: Sha2, salt: Slice, ikm: Slice): UEffIO[Prk] = op {
      val name = hmacName(hash)
      val key = if salt.length == 0 then new Array[Byte](hash.length) else salt.toArray
      Prk.unsafe(hmac(name, key, ikm.toArray))
    }
    def expand(hash: Sha2, prk: Prk, info: Slice, length: Int): UEffIO[Slice] = op {
      prk.read { p =>
        val name = hmacName(hash)
        val hlen = hash.length
        val n = (length + hlen - 1) / hlen
        val out = new Array[Byte](n * hlen)
        val key = p.toArray
        val infoBytes = info.toArray
        @tailrec def go(i: Int, prev: Array[Byte]): Unit =
          if i <= n then
            val block = hmac(name, key, prev ++ infoBytes ++ Array[Byte](i.toByte))
            Array.copy(block, 0, out, (i - 1) * hlen, hlen)
            go(i + 1, block)
        go(1, Array.emptyByteArray)
        Slice.of(out.take(length))
      }
    }
    def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEffIO[Slice] = blockingOp {
      val name = hmacName(hash)
      val pw = password.toArray
      val hlen = hash.length
      val blocks = (length + hlen - 1) / hlen
      val out = new Array[Byte](blocks * hlen)
      val saltBytes = salt.toArray
      @tailrec def accumulate(t: Array[Byte], u: Array[Byte], it: Int): Array[Byte] =
        if it >= iterations then t
        else
          val next = hmac(name, pw, u)
          @tailrec def xor(j: Int): Unit = if j < hlen then
            t(j) = (t(j) ^ next(j)).toByte; xor(j + 1)
          xor(0)
          accumulate(t, next, it + 1)
      @tailrec def block(b: Int): Unit =
        if b <= blocks then
          val intB = Array[Byte]((b >>> 24).toByte, (b >>> 16).toByte, (b >>> 8).toByte, b.toByte)
          val u1 = hmac(name, pw, saltBytes ++ intB)
          val t = accumulate(u1.clone, u1, 1)
          Array.copy(t, 0, out, (b - 1) * hlen, hlen)
          block(b + 1)
      block(1)
      Slice.of(out.take(length))
    }

  private def hashOf[D <: HashAlgorithm](name: String): Hash[D] = new Hash[D]:
    def digest(data: Slice): UEffIO[Digest] = op(Digest.unsafe(MessageDigest.getInstance(name).digest(data.toArray)))
  private def hashingOf[D <: HashAlgorithm](name: String): Hashing[D] = new Hashing[D]:
    def hasher: Resource[IO, Hasher] = Resource.eval(IO {
      new Hasher:
        private val md = MessageDigest.getInstance(name)
        def update(data: Slice): Unit = md.update(data.toArray)
        def digest: Digest = md.clone() match
          case snapshot: MessageDigest => Digest.unsafe(snapshot.digest())
          case _                       => Digest.unsafe(Array.emptyByteArray)
    })

  private def oaepSpec(hash: Sha2): OAEPParameterSpec =
    val (h, mgf) = hash match
      case _: Sha256.type => ("SHA-256", MGF1ParameterSpec.SHA256)
      case _: Sha384.type => ("SHA-384", MGF1ParameterSpec.SHA384)
      case _: Sha512.type => ("SHA-512", MGF1ParameterSpec.SHA512)
    new OAEPParameterSpec(h, "MGF1", mgf, PSource.PSpecified.DEFAULT)
  private[kufuli] val oaep: Oaep = new Oaep:
    def encrypt(key: PublicKey[Rsa], plaintext: Slice, scheme: RsaOaep): UEffIO[Slice] = op {
      val c = JCipher.getInstance("RSA/ECB/OAEPPadding")
      c.init(JCipher.ENCRYPT_MODE, parsePub("RSA", keyBytes(key.repr)), oaepSpec(scheme.hash))
      Slice.of(c.doFinal(plaintext.toArray))
    }
    def decrypt(key: PrivateKey[Rsa], ciphertext: Slice, scheme: RsaOaep): EffIO[AuthFailed, Slice] = opE {
      key.read { s =>
        val c = JCipher.getInstance("RSA/ECB/OAEPPadding")
        c.init(JCipher.DECRYPT_MODE, parsePriv("RSA", s.toArray), oaepSpec(scheme.hash))
        try Right(Slice.of(c.doFinal(ciphertext.toArray)))
        catch case _: javax.crypto.BadPaddingException | _: javax.crypto.IllegalBlockSizeException => Left(AuthFailed)
      }
    }

  private[kufuli] val edKeys: EdKeys = new EdKeys:
    def generate: UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = op {
      val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else
        val spki = Der.edSpkiPrefix ++ bytes.toArray
        validating(notOnCurve = true) { val _ = parsePub("Ed25519", spki); PublicKey.unsafe[Ed25519](keyRepr(spki)) }
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePub("Ed25519", d); PublicKey.unsafe[Ed25519](keyRepr(d)) }
    }
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Ed25519]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePriv("Ed25519", d); PrivateKey.unsafe[Ed25519](d) }
    }
    def raw(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(IArray.from(keyBytes(key.repr).drop(Der.edSpkiPrefix.length)))
    def spki(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private[kufuli] val xKeys: XKeys = new XKeys:
    def generate: UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = op {
      val kp = KeyPairGenerator.getInstance("X25519").generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[X25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes.toArray.forall(_ == 0) then Left(InvalidKey.WeakPoint)
      else
        val spki = Der.xSpkiPrefix ++ bytes.toArray
        validating(notOnCurve = true) { val _ = parsePub("X25519", spki); PublicKey.unsafe[X25519](keyRepr(spki)) }
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[X25519]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePub("X25519", d); PublicKey.unsafe[X25519](keyRepr(d)) }
    }
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[X25519]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePriv("X25519", d); PrivateKey.unsafe[X25519](d) }
    }
    def raw(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(IArray.from(keyBytes(key.repr).drop(Der.xSpkiPrefix.length)))
    def spki(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private def ecKeysOf[C <: EcCurve](curveName: String, fieldLength: Int, prefix: Array[Byte]): EcKeys[C] = new EcKeys[C]:
    private val pointLength = 1 + 2 * fieldLength
    def generate: UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]] = op {
      val kpg = KeyPairGenerator.getInstance("EC")
      kpg.initialize(new ECGenParameterSpec(curveName))
      val kp = kpg.generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    def fromSec1(point: Slice): EffIO[InvalidKey, PublicKey[C]] = opE {
      if point.length != pointLength then Left(InvalidKey.WrongLength(pointLength, point.length))
      else if point(0) != 4.toByte then Left(InvalidKey.Malformed)
      else
        val spki = prefix ++ point.toArray
        validating(notOnCurve = true) { val _ = parsePub("EC", spki); PublicKey.unsafe[C](keyRepr(spki)) }
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[C]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePub("EC", d); PublicKey.unsafe[C](keyRepr(d)) }
    }
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[C]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePriv("EC", d); PrivateKey.unsafe[C](d) }
    }
    def sec1(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(IArray.from(keyBytes(key.repr).drop(prefix.length)))
    def spki(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[C]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private[kufuli] val rsaKeys: RsaKeys = new RsaKeys:
    def generate(size: Rsa.Size): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]] = blockingOp {
      val kpg = KeyPairGenerator.getInstance("RSA")
      kpg.initialize(size.bits)
      val kp = kpg.generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    def fromComponents(modulus: Slice, exponent: Slice): EffIO[InvalidKey, PublicKey[Rsa]] = opE {
      validating(notOnCurve = false) {
        val n = new BigInteger(1, modulus.toArray)
        val e = new BigInteger(1, exponent.toArray)
        val jk = kf("RSA").generatePublic(new RSAPublicKeySpec(n, e))
        PublicKey.unsafe[Rsa](keyRepr(jk.getEncoded))
      }
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Rsa]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePub("RSA", d); PublicKey.unsafe[Rsa](keyRepr(d)) }
    }
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Rsa]] = opE {
      val d = der.toArray
      validating(notOnCurve = false) { val _ = parsePriv("RSA", d); PrivateKey.unsafe[Rsa](d) }
    }
    def components(key: PublicKey[Rsa]): EffIO[KeyNotExportable, Rsa.Components] = op {
      parsePub("RSA", keyBytes(key.repr)) match
        case jk: RSAPublicKey =>
          Rsa.Components(IArray.from(unsigned(jk.getModulus)), IArray.from(unsigned(jk.getPublicExponent)))
        case _ => Rsa.Components(IArray.empty, IArray.empty) // RSA KeyFactory always yields an RSAPublicKey
    }
    def spki(key: PublicKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private def kemKeysOf[K <: KemAlgorithm](spec: KemSpec[K], param: String): KemKeys[K] = new KemKeys[K]:
    def generate: UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]] = op {
      val kp = KeyPairGenerator.getInstance(param).generateKeyPair()
      KeyPair(PublicKey.unsafe(keyRepr(kp.getPublic.getEncoded)), PrivateKey.unsafe(kp.getPrivate.getEncoded))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[K]] = opE {
      if bytes.length != spec.publicKeyLength then Left(InvalidKey.WrongLength(spec.publicKeyLength, bytes.length))
      else
        val spki = mlkemSpki(spec, bytes.toArray)
        validating(notOnCurve = false) { val _ = parsePub("ML-KEM", spki); PublicKey.unsafe[K](keyRepr(spki)) }
    }
    def raw(key: PublicKey[K]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(mlkemRaw(keyBytes(key.repr))))

  // Capability bundles the JVM platform table wires each companion into.
  private[kufuli] trait RandomDefault:
    given Random = random
  private[kufuli] trait AeadUniversal:
    given Aead[AesGcm128] = aeadGcm(AesGcm128)
    given Aead[AesGcm192] = aeadGcm(AesGcm192)
    given Aead[AesGcm256] = aeadGcm(AesGcm256)
    given Aead[A128CbcHs256] = aeadCbcHs(A128CbcHs256, "HmacSHA256")
    given Aead[A256CbcHs512] = aeadCbcHs(A256CbcHs512, "HmacSHA512")
  private[kufuli] trait AeadChaCha:
    given Aead[ChaCha20Poly1305] = aeadChaCha(ChaCha20Poly1305)
  private[kufuli] trait CipheringUniversal:
    given Ciphering[AesGcm128] = cipheringGcm(AesGcm128)
    given Ciphering[AesGcm192] = cipheringGcm(AesGcm192)
    given Ciphering[AesGcm256] = cipheringGcm(AesGcm256)
  private[kufuli] trait CipheringChaCha:
    given Ciphering[ChaCha20Poly1305] = cipheringChaCha(ChaCha20Poly1305)
  private[kufuli] trait MacAll:
    given Mac[HmacSha256] = macOf("HmacSHA256")
    given Mac[HmacSha384] = macOf("HmacSHA384")
    given Mac[HmacSha512] = macOf("HmacSHA512")
  private[kufuli] trait SignersAll:
    given Signer[Ed25519] = edSigner
    given Signer[P256] = ecSigner(32)
    given Signer[P384] = ecSigner(48)
    given Signer[P521] = ecSigner(66)
    given Signer[Rsa] = rsaSigner
  private[kufuli] trait VerifiersAll:
    given Verifier[Ed25519] = edVerifier
    given Verifier[P256] = ecVerifier
    given Verifier[P384] = ecVerifier
    given Verifier[P521] = ecVerifier
    given Verifier[Rsa] = rsaVerifier
  private[kufuli] trait AgreementAll:
    given Agreement[X25519] = agreementOf("X25519", "X25519")
    given Agreement[P256] = agreementOf("ECDH", "EC")
    given Agreement[P384] = agreementOf("ECDH", "EC")
    given Agreement[P521] = agreementOf("ECDH", "EC")
  private[kufuli] trait KemAll:
    given Kem[MlKem768] = kemOf
    given Kem[MlKem1024] = kemOf
  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapAes("AESWrap")
    given Wrap[AesKw256] = wrapAes("AESWrap")
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapAes("AESWrapPad")
    given Wrap[AesKwp256] = wrapAes("AESWrapPad")
  private[kufuli] trait KdfDefault:
    given Kdf = kdf
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
    given Oaep = oaep
  private[kufuli] trait EdKeysJca:
    given EdKeys = edKeys
  private[kufuli] trait XKeysJca:
    given XKeys = xKeys
  private[kufuli] trait EcKeysJca:
    given EcKeys[P256] = ecKeysOf("secp256r1", 32, Der.p256SpkiPrefix)
    given EcKeys[P384] = ecKeysOf("secp384r1", 48, Der.p384SpkiPrefix)
    given EcKeys[P521] = ecKeysOf("secp521r1", 66, Der.p521SpkiPrefix)
  private[kufuli] trait RsaKeysJca:
    given RsaKeys = rsaKeys
  private[kufuli] trait KemKeysJca:
    given KemKeys[MlKem768] = kemKeysOf(MlKem768, "ML-KEM-768")
    given KemKeys[MlKem1024] = kemKeysOf(MlKem1024, "ML-KEM-1024")
end jca
