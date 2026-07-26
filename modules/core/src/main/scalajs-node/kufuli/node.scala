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
// Node backend instances over `node:crypto`. Keys are carried as their standard encodings and
// re-parsed to a node KeyObject per op; every op routes through `guard`. Key generation runs off
// the event loop on node's async threadpool.
package kufuli

import scala.annotation.tailrec
import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import boilerplate.nullable.option
import cats.effect.IO
import cats.effect.Resource

import kufuli.nodecrypto.*

private[kufuli] object node:

  private def op[A](thunk: => A): UEffIO[A] = EffIO.liftF(guard(IO(thunk)))
  private def opE[E <: Throwable, A](thunk: => Either[E, A]): EffIO[E, A] = EffIO.lift(guard(IO(thunk)))

  private def genKeyPair(kind: String, options: js.Any): UEffIO[(KeyObject, KeyObject)] =
    EffIO.liftF(guard(IO.async_ { cb =>
      crypto.generateKeyPair(
        kind,
        options,
        (err, pub, priv) =>
          err.option match
            case None    => cb(Right((pub, priv)))
            case Some(e) => cb(Left(js.JavaScriptException(e)))
      )
    }))

  private def withSecret[A](secret: Slice)(f: Uint8Array => A): A =
    val bytes = secret.toArray
    val buf = u8(bytes)
    try f(buf)
    finally
      zero(buf)
      val _ = Slice.of(bytes).wipe()

  // node reports a data failure - an unauthenticated tag, bad padding, an unreadable encoding, an
  // invalid encapsulation key - with no `code` at all or with an `ERR_OSSL_*`/`ERR_INVALID_ARG_VALUE`
  // one, and reports OUR mistakes under the codes below. Typing the latter as the caller's failure
  // is what turns a kufuli bug into a logged forgery. Nonce, tag and key lengths are all fixed by a
  // spec before the call, so none of these is reachable from caller data.
  private val defectCodes: Set[String] =
    Set(
      "ERR_INVALID_ARG_TYPE",
      "ERR_OUT_OF_RANGE",
      "ERR_CRYPTO_INVALID_AUTH_TAG",
      "ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE",
      "ERR_CRYPTO_SIGN_KEY_REQUIRED",
      "ERR_OSSL_EVP_UNSUPPORTED_ALGORITHM"
    )

  // Re-raising sends the error through `guard` to a sanitised `Unexpected` defect, which is where a
  // wrongly-called primitive belongs.
  private def failing[E, A](error: E)(f: => A): Either[E, A] =
    try Right(f)
    catch
      case e: js.JavaScriptException =>
        if errorCode(e).exists(defectCodes.contains) then throw e // scalafix:ok DisableSyntax.throw
        else Left(error)

  private def validating[A](notOnCurve: Boolean)(f: => A): Either[InvalidKey, A] =
    failing(if notOnCurve then InvalidKey.NotOnCurve else InvalidKey.Malformed)(f)

  private def derPub(der: Uint8Array): js.Any = js.Dynamic.literal(key = der, format = "der", `type` = "spki")
  private def derPriv(der: Uint8Array): js.Any = js.Dynamic.literal(key = der, format = "der", `type` = "pkcs8")
  private def parsePub(spki: Array[Byte]): KeyObject = crypto.createPublicKey(derPub(u8(spki)))
  private def exportSpki(k: KeyObject): Array[Byte] = ba(k.`export`(js.Dynamic.literal(`type` = "spki", format = "der")))
  private def exportPkcs8(k: KeyObject): Array[Byte] = ba(k.`export`(js.Dynamic.literal(`type` = "pkcs8", format = "der")))

  // node infers a key's family from the encoding, binds nothing to the family the caller asked
  // for, and tolerates bytes appended after the outer SEQUENCE - so the family, the curve and full
  // consumption are all asserted here, and what is stored is node's own canonical re-export.
  private def bound(k: KeyObject, kind: String, curve: Option[String]): Boolean =
    k.asymmetricKeyType.toOption.contains(kind) &&
      curve.forall(c => k.asymmetricKeyDetails.toOption.flatMap(_.namedCurve.toOption).contains(c))

  private def storePub(der: Array[Byte], kind: String, curve: Option[String], notOnCurve: Boolean): Either[InvalidKey, Array[Byte]] =
    if !Der.spansWhole(Slice.of(der), 0x30) then Left(InvalidKey.Malformed)
    else
      validating(notOnCurve)(parsePub(der)).flatMap(k => if bound(k, kind, curve) then Right(exportSpki(k)) else Left(InvalidKey.Malformed))

  private def storePriv(der: Array[Byte], kind: String, curve: Option[String]): Either[InvalidKey, Array[Byte]] =
    if !Der.spansWhole(Slice.of(der), 0x30) then Left(InvalidKey.Malformed)
    else
      validating(notOnCurve = false)(crypto.createPrivateKey(derPriv(u8(der))))
        .flatMap(k => if bound(k, kind, curve) then Right(exportPkcs8(k)) else Left(InvalidKey.Malformed))

  private def publicPoint(key: KeyRepr, length: Int): IArray[Byte] =
    IArray.from(demand(Der.spkiPublicBits(Slice.of(keyBytes(key)), length)).toArray)

  private def digestName(hash: Sha2): String = hash match
    case _: Sha256.type => "sha256"
    case _: Sha384.type => "sha384"
    case _: Sha512.type => "sha512"

  private def hmacRaw(name: String, key: Array[Byte], data: Array[Byte]): Array[Byte] =
    val keyBuf = u8(key)
    val out = ba(crypto.createHmac(name, keyBuf).update(u8(data)).digest())
    zero(keyBuf)
    out

  private def setAad(c: NodeCipher, aad: Slice): Unit =
    if aad.length > 0 then c.setAAD(u8(aad.toArray))

  private def unsigned(b: Array[Byte]): Array[Byte] =
    if b.length > 1 && b(0) == 0.toByte then b.drop(1) else b

  private[kufuli] val random: Random = new Random:
    private[kufuli] def bytes(n: Int): UEffIO[Slice] = op {
      val buf = new Uint8Array(n)
      val _ = crypto.randomFillSync(buf)
      Slice.of(ba(buf))
    }
    private[kufuli] def fill(dst: Slice): UEffIO[Unit] = op {
      val buf = new Uint8Array(dst.length)
      val _ = crypto.randomFillSync(buf)
      val _ = Slice.of(ba(buf)).copyInto(dst)
    }

  private def aead[A <: AeadAlgorithm](spec: AeadSpec[A], cipherName: String, chacha: Boolean): Aead[A] = new Aead[A]:
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
      key.read { k =>
        withSecret(k) { kb =>
          val c = mkCipher(cipherName, kb, u8(nonce.repr), chacha, decrypt = false)
          setAad(c, aad)
          val ct = ba(c.update(u8(plaintext.toArray))) ++ ba(c.`final`())
          Slice.of(ct ++ ba(c.getAuthTag()))
        }
      }
    }
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice] = opE {
      key.read { k =>
        withSecret(k) { kb =>
          val whole = ciphertext.toArray
          if whole.length < spec.tagLength then Left(AuthFailed)
          else
            val ct = whole.take(whole.length - spec.tagLength)
            val tag = whole.drop(whole.length - spec.tagLength)
            val d = mkCipher(cipherName, kb, u8(nonce.repr), chacha, decrypt = true)
            setAad(d, aad)
            d.setAuthTag(u8(tag))
            try Right(Slice.of(ba(d.update(u8(ct))) ++ ba(d.`final`())))
            catch case _: js.JavaScriptException => Left(AuthFailed)
        }
      }
    }

  private def mkCipher(name: String, key: Uint8Array, iv: Uint8Array, chacha: Boolean, decrypt: Boolean): NodeCipher =
    if chacha then
      val opts = js.Dynamic.literal(authTagLength = 16)
      if decrypt then crypto.createDecipheriv(name, key, iv, opts) else crypto.createCipheriv(name, key, iv, opts)
    else if decrypt then crypto.createDecipheriv(name, key, iv)
    else crypto.createCipheriv(name, key, iv)

  // AES-CBC-HMAC-SHA2 composite (RFC 7518 section 5.2): key = MAC || ENC halves; the tag is the
  // leading half of HMAC over aad || iv || ct || AL, with AL the 64-bit big-endian aad bit length.
  private def cbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], mac: String): Aead[A] = new Aead[A]:
    private def macTag(macKey: Array[Byte], iv: Array[Byte], aad: Slice, ct: Array[Byte]): Array[Byte] =
      val al = new Array[Byte](8)
      Slice.of(al).writeBE[Long](0, aad.length.toLong * 8)
      hmacRaw(mac, macKey, aad.toArray ++ iv ++ ct ++ al).take(spec.tagLength)
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
      key.read { k =>
        val kb = k.toArray
        val half = kb.length / 2
        val macKey = kb.take(half)
        val encKey = kb.drop(half)
        val iv = nonce.repr
        val encBuf = u8(encKey)
        val c = crypto.createCipheriv(s"aes-${encKey.length * 8}-cbc", encBuf, u8(iv))
        val ct = ba(c.update(u8(plaintext.toArray))) ++ ba(c.`final`())
        val out = Slice.of(ct ++ macTag(macKey, iv, aad, ct))
        zero(encBuf)
        val _ = Slice.of(kb).wipe()
        out
      }
    }
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice] = opE {
      key.read { k =>
        val kb = k.toArray
        val half = kb.length / 2
        val macKey = kb.take(half)
        val encKey = kb.drop(half)
        val iv = nonce.repr
        val whole = ciphertext.toArray
        val result =
          if whole.length < spec.tagLength then Left(AuthFailed)
          else
            val ct = whole.take(whole.length - spec.tagLength)
            val tag = whole.drop(whole.length - spec.tagLength)
            if !Slice.of(macTag(macKey, iv, aad, ct)).constantTimeEquals(Slice.of(tag)) then Left(AuthFailed)
            else
              val encBuf = u8(encKey)
              val d = crypto.createDecipheriv(s"aes-${encKey.length * 8}-cbc", encBuf, u8(iv))
              val opened =
                try Right(Slice.of(ba(d.update(u8(ct))) ++ ba(d.`final`())))
                catch case _: js.JavaScriptException => Left(AuthFailed)
              zero(encBuf)
              opened
        val _ = Slice.of(kb).wipe()
        result
      }
    }

  // node has no reusable AEAD context, so each record creates a fresh cipher, as JCA does per op.
  final private class AeadEngine[A <: AeadAlgorithm](keyBuf: Uint8Array, spec: AeadSpec[A], cipherName: String, chacha: Boolean)
      extends Cipher.Engine[A]:
    private[kufuli] def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
      val c = mkCipher(cipherName, keyBuf, u8(nonce.toArray), chacha, decrypt = false)
      setAad(c, aad)
      val out = ba(c.update(u8(src.toArray))) ++ ba(c.`final`()) ++ ba(c.getAuthTag())
      val _ = Slice.of(out).copyInto(dst)
      out.length
    private[kufuli] def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      val whole = src.toArray
      // A `src` below the tag length has no ciphertext to authenticate, and node accepts a 4-byte
      // GCM tag: treating those bytes as the tag verifies against a truncated one, 2^32 work.
      if whole.length < spec.tagLength then Left(AuthFailed)
      else decryptChecked(dst, whole, aad, nonce)

    private def decryptChecked(dst: Slice, whole: Array[Byte], aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      val ct = whole.take(whole.length - spec.tagLength)
      val tag = whole.drop(whole.length - spec.tagLength)
      val d = mkCipher(cipherName, keyBuf, u8(nonce.toArray), chacha, decrypt = true)
      setAad(d, aad)
      val _ = d.setAuthTag(u8(tag))
      try
        val out = ba(d.update(u8(ct))) ++ ba(d.`final`())
        val _ = Slice.of(out).copyInto(dst)
        Right(out.length)
      catch case _: js.JavaScriptException => Left(AuthFailed)
    end decryptChecked
  end AeadEngine

  private def ciphering[A <: AeadAlgorithm](spec: AeadSpec[A], cipherName: String, chacha: Boolean): Ciphering[A] = new Ciphering[A]:
    private[kufuli] def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]] =
      Resource
        .make(guard(IO(key.read { k =>
          val a = k.toArray
          val buf = u8(a)
          val _ = Slice.of(a).wipe()
          buf
        })))(buf => IO(zero(buf)))
        .map(buf => new AeadEngine(buf, spec, cipherName, chacha))

  private def macOf[H <: MacAlgorithm](name: String): Mac[H] = new Mac[H]:
    private[kufuli] def sign(key: SecretKey[H], data: Slice): UEffIO[Signature[H]] =
      op(key.read(k => Signature.unsafe[H](withSecret(k)(kb => ba(crypto.createHmac(name, kb).update(u8(data.toArray)).digest())))))

  private def edSigner: Signer[Ed25519] = new Signer[Ed25519]:
    private[kufuli] def sign(key: PrivateKey[Ed25519], data: Slice, scheme: Scheme[Ed25519]): UEffIO[Signature[Ed25519]] = op {
      key.read { der =>
        withSecret(der) { buf =>
          Signature.unsafe[Ed25519](ba(crypto.sign(js.undefined, u8(data.toArray), crypto.createPrivateKey(derPriv(buf)))))
        }
      }
    }
  private def edVerifier: Verifier[Ed25519] = new Verifier[Ed25519]:
    private[kufuli] def verify(
      key: PublicKey[Ed25519],
      data: Slice,
      sig: Signature[Ed25519],
      scheme: Scheme[Ed25519]): EffIO[SignatureRejected, Unit] =
      opE {
        val ok = crypto.verify(js.undefined, u8(data.toArray), parsePub(keyBytes(key.repr)), u8(sig.repr))
        if ok then Right(()) else Left(SignatureRejected)
      }

  private def ecKey(k: KeyObject): js.Any = js.Dynamic.literal(key = k, dsaEncoding = "ieee-p1363")
  private def ecSigner[C <: EcCurve]: Signer[C] = new Signer[C]:
    private[kufuli] def sign(key: PrivateKey[C], data: Slice, scheme: Scheme[C]): UEffIO[Signature[C]] = op {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => digestName(hash)
      key.read { der =>
        withSecret(der) { buf =>
          Signature.unsafe[C](ba(crypto.sign(h, u8(data.toArray), ecKey(crypto.createPrivateKey(derPriv(buf))))))
        }
      }
    }
  private def ecVerifier[C <: EcCurve]: Verifier[C] = new Verifier[C]:
    private[kufuli] def verify(key: PublicKey[C], data: Slice, sig: Signature[C], scheme: Scheme[C]): EffIO[SignatureRejected, Unit] = opE {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => digestName(hash)
      val ok = crypto.verify(h, u8(data.toArray), ecKey(parsePub(keyBytes(key.repr))), u8(sig.repr))
      if ok then Right(()) else Left(SignatureRejected)
    }

  private def rsaKey(k: KeyObject, scheme: Scheme[Rsa]): (algorithm: String, key: js.Any) = scheme.runtimeChecked match
    case RsaPss(h) =>
      (algorithm = digestName(h),
       key =
         js.Dynamic.literal(key = k, padding = crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST)
      )
    case RsaPkcs1(h) => (algorithm = digestName(h), key = k)
  private def rsaSigner: Signer[Rsa] = new Signer[Rsa]:
    private[kufuli] def sign(key: PrivateKey[Rsa], data: Slice, scheme: Scheme[Rsa]): UEffIO[Signature[Rsa]] = op {
      key.read { der =>
        withSecret(der) { buf =>
          val r = rsaKey(crypto.createPrivateKey(derPriv(buf)), scheme)
          Signature.unsafe[Rsa](ba(crypto.sign(r.algorithm, u8(data.toArray), r.key)))
        }
      }
    }
  private def rsaVerifier: Verifier[Rsa] = new Verifier[Rsa]:
    private[kufuli] def verify(key: PublicKey[Rsa], data: Slice, sig: Signature[Rsa], scheme: Scheme[Rsa]): EffIO[SignatureRejected, Unit] =
      opE {
        val r = rsaKey(parsePub(keyBytes(key.repr)), scheme)
        if crypto.verify(r.algorithm, u8(data.toArray), r.key, u8(sig.repr)) then Right(()) else Left(SignatureRejected)
      }

  private def agreementOf[A <: AgreementAlgorithm]: Agreement[A] = new Agreement[A]:
    private[kufuli] def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEffIO[SharedSecret] = op {
      priv.read { der =>
        withSecret(der) { buf =>
          val secret = crypto.diffieHellman(
            js.Dynamic.literal(privateKey = crypto.createPrivateKey(derPriv(buf)), publicKey = parsePub(keyBytes(pub.repr)))
          )
          SharedSecret.unsafe(ba(secret))
        }
      }
    }

  private def kemOf[K <: KemAlgorithm](kind: String): Kem[K] = new Kem[K]:
    private[kufuli] def encapsulate(pub: PublicKey[K]): UEffIO[Encapsulated[K]] = op {
      val e = crypto.encapsulate(crypto.createPublicKey(rawPublic(u8(keyBytes(pub.repr)), kind)))
      Encapsulated(SharedSecret.unsafe(ba(e.sharedKey)), KemCiphertext.unsafe(ba(e.ciphertext)))
    }
    private[kufuli] def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEffIO[SharedSecret] = op {
      priv.read { seed =>
        withSecret(seed) { buf =>
          SharedSecret.unsafe(ba(crypto.decapsulate(crypto.createPrivateKey(rawSeed(buf, kind)), u8(ct.repr))))
        }
      }
    }

  private def rawPublic(key: Uint8Array, kind: String): js.Any =
    js.Dynamic.literal(key = key, format = "raw-public", asymmetricKeyType = kind)
  private def rawSeed(key: Uint8Array, kind: String): js.Any =
    js.Dynamic.literal(key = key, format = "raw-seed", asymmetricKeyType = kind)

  // The RFC 3394 / 5649 default integrity IVs.
  private val kwIv: Array[Byte] = Array.fill[Byte](8)(0xa6.toByte)
  private val kwpIv: Array[Byte] = Array[Byte](0xa6.toByte, 0x59, 0x59, 0xa6.toByte)
  private def wrapOf[W <: WrapAlgorithm](padded: Boolean): Wrap[W] = new Wrap[W]:
    private def cipherName(kekLen: Int): String = s"id-aes${kekLen * 8}-wrap${if padded then "-pad" else ""}"
    private def iv: Array[Byte] = if padded then kwpIv else kwIv
    private[kufuli] def wrap(kek: SecretKey[W], target: Slice): UEffIO[Slice] = op {
      kek.read { k =>
        withSecret(k) { kb =>
          val c = crypto.createCipheriv(cipherName(kb.length), kb, u8(iv))
          Slice.of(ba(c.update(u8(target.toArray))) ++ ba(c.`final`()))
        }
      }
    }
    private[kufuli] def unwrap(kek: SecretKey[W], wrapped: Slice): EffIO[UnwrapFailed, Slice] = opE {
      kek.read { k =>
        withSecret(k) { kb =>
          val d = crypto.createDecipheriv(cipherName(kb.length), kb, u8(iv))
          try Right(Slice.of(ba(d.update(u8(wrapped.toArray))) ++ ba(d.`final`())))
          catch case _: js.JavaScriptException => Left(UnwrapFailed)
        }
      }
    }

  private[kufuli] val kdf: Kdf = new Kdf:
    private[kufuli] def extract(hash: Sha2, salt: Slice, ikm: Slice): UEffIO[Prk] = op {
      val name = digestName(hash)
      val key = if salt.length == 0 then new Array[Byte](hash.length) else salt.toArray
      Prk.unsafe(hmacRaw(name, key, ikm.toArray))
    }
    private[kufuli] def expand(hash: Sha2, prk: Prk, info: Slice, length: Int): UEffIO[Slice] = op {
      prk.read { p =>
        val name = digestName(hash)
        val hlen = hash.length
        val n = (length + hlen - 1) / hlen
        val out = new Array[Byte](n * hlen)
        val key = p.toArray
        val infoBytes = info.toArray
        @tailrec def go(i: Int, prev: Array[Byte]): Unit =
          if i <= n then
            val block = hmacRaw(name, key, prev ++ infoBytes ++ Array[Byte](i.toByte))
            Array.copy(block, 0, out, (i - 1) * hlen, hlen)
            go(i + 1, block)
        go(1, Array.emptyByteArray)
        val _ = Slice.of(key).wipe()
        Slice.of(out.take(length))
      }
    }
    private[kufuli] def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEffIO[Slice] =
      // node's synchronous PBKDF2 runs on the event loop, stalling every fibre, socket and timer
      // for the whole derivation; at SCRAM's 600k iterations that is a reachable denial of service.
      EffIO.liftF(guard(IO.async_ { cb =>
        crypto.pbkdf2(
          u8(password.toArray),
          u8(salt.toArray),
          iterations,
          length,
          digestName(hash),
          (err, out) =>
            err.option match
              case None    => cb(Right(Slice.of(ba(out))))
              case Some(e) => cb(Left(js.JavaScriptException(e)))
        )
      }))

  private def hashOf[D <: HashAlgorithm](name: String): Hash[D] = new Hash[D]:
    private[kufuli] def digest(data: Slice): UEffIO[Digest] = op(Digest.unsafe(ba(crypto.createHash(name).update(u8(data.toArray)).digest())))
  private def hashingOf[D <: HashAlgorithm](name: String): Hashing[D] = new Hashing[D]:
    private[kufuli] def hasher: Resource[IO, Hasher] = Resource.eval(IO {
      new Hasher:
        private val h = crypto.createHash(name)
        def update(data: Slice): Unit =
          val _ = h.update(u8(data.toArray))
        def digest: Digest = Digest.unsafe(ba(h.copy().digest()))
    })

  private def oaepOptions(k: KeyObject, hash: Sha2): js.Any =
    js.Dynamic.literal(key = k, padding = crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash = digestName(hash))
  private[kufuli] val oaep: Oaep = new Oaep:
    private[kufuli] def encrypt(key: PublicKey[Rsa], plaintext: Slice, scheme: RsaOaep): UEffIO[Slice] = op {
      Slice.of(ba(crypto.publicEncrypt(oaepOptions(parsePub(keyBytes(key.repr)), scheme.hash), u8(plaintext.toArray))))
    }
    private[kufuli] def decrypt(key: PrivateKey[Rsa], ciphertext: Slice, scheme: RsaOaep): EffIO[AuthFailed, Slice] = opE {
      key.read { der =>
        withSecret(der) { buf =>
          try Right(Slice.of(ba(crypto.privateDecrypt(oaepOptions(crypto.createPrivateKey(derPriv(buf)), scheme.hash), u8(ciphertext.toArray)))))
          catch case _: js.JavaScriptException => Left(AuthFailed)
        }
      }
    }

  private def emptyOptions: js.Any = js.Dynamic.literal()

  private[kufuli] val edKeys: EdKeys = new EdKeys:
    private[kufuli] def generate: UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] =
      genKeyPair("ed25519", emptyOptions).map((pub, priv) =>
        KeyPair(PublicKey.unsafe(keyRepr(exportSpki(pub))), PrivateKey.unsafe(exportPkcs8(priv)))
      )
    private[kufuli] def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else storePub(Der.edSpkiPrefix ++ bytes.toArray, "ed25519", None, notOnCurve = true).map(b => PublicKey.unsafe[Ed25519](keyRepr(b)))
    }
    private[kufuli] def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] =
      opE(storePub(der.toArray, "ed25519", None, notOnCurve = false).map(b => PublicKey.unsafe[Ed25519](keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Ed25519]] =
      opE(storePriv(der.toArray, "ed25519", None).map(PrivateKey.unsafe[Ed25519]))
    private[kufuli] def raw(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(publicPoint(key.repr, 32))
    private[kufuli] def spki(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(op(key.read(s => IArray.from(s.toArray))))

  private[kufuli] val xKeys: XKeys = new XKeys:
    private[kufuli] def generate: UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] =
      genKeyPair("x25519", emptyOptions).map((pub, priv) =>
        KeyPair(PublicKey.unsafe(keyRepr(exportSpki(pub))), PrivateKey.unsafe(exportPkcs8(priv)))
      )
    private[kufuli] def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[X25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes.toArray.forall(_ == 0) then Left(InvalidKey.WeakPoint)
      else storePub(Der.xSpkiPrefix ++ bytes.toArray, "x25519", None, notOnCurve = true).map(b => PublicKey.unsafe[X25519](keyRepr(b)))
    }
    private[kufuli] def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[X25519]] =
      opE(storePub(der.toArray, "x25519", None, notOnCurve = false).map(b => PublicKey.unsafe[X25519](keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[X25519]] =
      opE(storePriv(der.toArray, "x25519", None).map(PrivateKey.unsafe[X25519]))
    private[kufuli] def raw(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(publicPoint(key.repr, 32))
    private[kufuli] def spki(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(op(key.read(s => IArray.from(s.toArray))))

  private def ecKeysOf[C <: EcCurve](curveName: String, fieldLength: Int, prefix: Array[Byte]): EcKeys[C] = new EcKeys[C]:
    private val pointLength = 1 + 2 * fieldLength
    private[kufuli] def generate: UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]] =
      genKeyPair("ec", js.Dynamic.literal(namedCurve = curveName)).map((pub, priv) =>
        KeyPair(PublicKey.unsafe(keyRepr(exportSpki(pub))), PrivateKey.unsafe(exportPkcs8(priv)))
      )
    private[kufuli] def fromSec1(point: Slice): EffIO[InvalidKey, PublicKey[C]] = opE {
      if point.length != pointLength then Left(InvalidKey.WrongLength(pointLength, point.length))
      else if point(0) != 4.toByte then Left(InvalidKey.Malformed)
      else storePub(prefix ++ point.toArray, "ec", Some(curveName), notOnCurve = true).map(b => PublicKey.unsafe[C](keyRepr(b)))
    }
    private[kufuli] def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[C]] =
      opE(storePub(der.toArray, "ec", Some(curveName), notOnCurve = false).map(b => PublicKey.unsafe[C](keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[C]] =
      opE(storePriv(der.toArray, "ec", Some(curveName)).map(PrivateKey.unsafe[C]))
    private[kufuli] def sec1(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] = op(publicPoint(key.repr, pointLength))
    private[kufuli] def spki(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[C]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(op(key.read(s => IArray.from(s.toArray))))

  private[kufuli] val rsaKeys: RsaKeys = new RsaKeys:
    private[kufuli] def generate(size: Rsa.Size): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]] =
      genKeyPair("rsa", js.Dynamic.literal(modulusLength = size.bits)).map((pub, priv) =>
        KeyPair(PublicKey.unsafe(keyRepr(exportSpki(pub))), PrivateKey.unsafe(exportPkcs8(priv)))
      )
    private[kufuli] def fromComponents(modulus: Slice, exponent: Slice): EffIO[InvalidKey, PublicKey[Rsa]] = opE {
      validating(notOnCurve = false) {
        val jwk = js.Dynamic.literal(kty = "RSA", n = Base64Url.encode(modulus.toArray), e = Base64Url.encode(exponent.toArray))
        val ko = crypto.createPublicKey(js.Dynamic.literal(key = jwk, format = "jwk"))
        PublicKey.unsafe[Rsa](keyRepr(exportSpki(ko)))
      }
    }
    private[kufuli] def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Rsa]] =
      opE(storePub(der.toArray, "rsa", None, notOnCurve = false).map(b => PublicKey.unsafe[Rsa](keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Rsa]] =
      opE(storePriv(der.toArray, "rsa", None).map(PrivateKey.unsafe[Rsa]))
    private[kufuli] def components(key: PublicKey[Rsa]): EffIO[KeyNotExportable, Rsa.Components] = op {
      val der = Slice.of(keyBytes(key.repr))
      demand(
        for
          bits <- Der.spkiPublicBits(der)
          inner <- Der.read(bits, 0, 0x30)
          n <- Der.read(bits, inner.contentOff, 0x02)
          e <- Der.read(bits, n.next, 0x02)
        yield Rsa.Components(
          IArray.from(unsigned(bits.slice(n.contentOff, n.next).toArray)),
          IArray.from(unsigned(bits.slice(e.contentOff, e.next).toArray))
        )
      )
    }
    private[kufuli] def spki(key: PublicKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(op(key.read(s => IArray.from(s.toArray))))

  private def kemKeysOf[K <: KemAlgorithm](kind: String, spec: KemSpec[K]): KemKeys[K] = new KemKeys[K]:
    private[kufuli] def generate: UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]] =
      genKeyPair(kind, emptyOptions).map { (pub, priv) =>
        val rawPub = ba(pub.`export`(js.Dynamic.literal(format = "raw-public")))
        val seed = ba(priv.`export`(js.Dynamic.literal(format = "raw-seed")))
        KeyPair(PublicKey.unsafe(keyRepr(rawPub)), PrivateKey.unsafe(seed))
      }
    private[kufuli] def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[K]] = opE {
      if bytes.length != spec.publicKeyLength then Left(InvalidKey.WrongLength(spec.publicKeyLength, bytes.length))
      else
        // FIPS 203 section 7.2's encapsulation-key check; without it a peer key of the right length
        // fails at `encapsulate` as a defect instead of at import as a value, and the JVM already
        // rejects it at import.
        validating(notOnCurve = false) {
          val _ = crypto.createPublicKey(rawPublic(u8(bytes.toArray), kind))
          PublicKey.unsafe[K](keyRepr(bytes.toArray))
        }
    }
    private[kufuli] def raw(key: PublicKey[K]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def fromSeed(seed: Slice): EffIO[InvalidKey, KeyPair[PublicKey[K], PrivateKey[K]]] = opE {
      if seed.length != 64 then Left(InvalidKey.WrongLength(64, seed.length))
      else
        validating(notOnCurve = false) {
          val priv = crypto.createPrivateKey(rawSeed(u8(seed.toArray), kind))
          val pub = ba(crypto.createPublicKey(priv).`export`(js.Dynamic.literal(format = "raw-public")))
          KeyPair(PublicKey.unsafe[K](keyRepr(pub)), PrivateKey.unsafe[K](seed.toArray))
        }
    }

  // Capability bundles the node platform table wires each companion into.
  private[kufuli] trait RandomDefault:
    given Random = random
  private[kufuli] trait AeadUniversal:
    given Aead[AesGcm128] = aead(AesGcm128, "aes-128-gcm", chacha = false)
    given Aead[AesGcm192] = aead(AesGcm192, "aes-192-gcm", chacha = false)
    given Aead[AesGcm256] = aead(AesGcm256, "aes-256-gcm", chacha = false)
    given Aead[A128CbcHs256] = cbcHs(A128CbcHs256, "sha256")
    given Aead[A256CbcHs512] = cbcHs(A256CbcHs512, "sha512")
  private[kufuli] trait AeadChaCha:
    given Aead[ChaCha20Poly1305] = aead(ChaCha20Poly1305, "chacha20-poly1305", chacha = true)
  private[kufuli] trait CipheringUniversal:
    given Ciphering[AesGcm128] = ciphering(AesGcm128, "aes-128-gcm", chacha = false)
    given Ciphering[AesGcm192] = ciphering(AesGcm192, "aes-192-gcm", chacha = false)
    given Ciphering[AesGcm256] = ciphering(AesGcm256, "aes-256-gcm", chacha = false)
  private[kufuli] trait CipheringChaCha:
    given Ciphering[ChaCha20Poly1305] = ciphering(ChaCha20Poly1305, "chacha20-poly1305", chacha = true)
  private[kufuli] trait MacAll:
    given Mac[HmacSha256] = macOf("sha256")
    given Mac[HmacSha384] = macOf("sha384")
    given Mac[HmacSha512] = macOf("sha512")
    given Mac[HmacSha1] = macOf("sha1")
  private[kufuli] trait SignersAll:
    given Signer[Ed25519] = edSigner
    given Signer[P256] = ecSigner
    given Signer[P384] = ecSigner
    given Signer[P521] = ecSigner
    given Signer[Rsa] = rsaSigner
  private[kufuli] trait VerifiersAll:
    given Verifier[Ed25519] = edVerifier
    given Verifier[P256] = ecVerifier
    given Verifier[P384] = ecVerifier
    given Verifier[P521] = ecVerifier
    given Verifier[Rsa] = rsaVerifier
  private[kufuli] trait AgreementAll:
    given Agreement[X25519] = agreementOf
    given Agreement[P256] = agreementOf
    given Agreement[P384] = agreementOf
    given Agreement[P521] = agreementOf
  private[kufuli] trait KemAll:
    given Kem[MlKem768] = kemOf("ml-kem-768")
    given Kem[MlKem1024] = kemOf("ml-kem-1024")
  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapOf(padded = false)
    given Wrap[AesKw256] = wrapOf(padded = false)
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapOf(padded = true)
    given Wrap[AesKwp256] = wrapOf(padded = true)
  private[kufuli] trait KdfDefault:
    given Kdf = kdf
  private[kufuli] trait HashAll:
    given Hash[Sha1] = hashOf("sha1")
    given Hash[Sha256] = hashOf("sha256")
    given Hash[Sha384] = hashOf("sha384")
    given Hash[Sha512] = hashOf("sha512")
  private[kufuli] trait HashingSync:
    given Hashing[Sha256] = hashingOf("sha256")
    given Hashing[Sha384] = hashingOf("sha384")
    given Hashing[Sha512] = hashingOf("sha512")
  private[kufuli] trait OaepDefault:
    given Oaep = oaep
  private[kufuli] trait EdKeysBytes:
    given EdKeys = edKeys
  private[kufuli] trait XKeysBytes:
    given XKeys = xKeys
  private[kufuli] trait EcKeysBytes:
    given EcKeys[P256] = ecKeysOf("prime256v1", 32, Der.p256SpkiPrefix)
    given EcKeys[P384] = ecKeysOf("secp384r1", 48, Der.p384SpkiPrefix)
    given EcKeys[P521] = ecKeysOf("secp521r1", 66, Der.p521SpkiPrefix)
  private[kufuli] trait RsaKeysBytes:
    given RsaKeys = rsaKeys
  private[kufuli] trait KemKeysAll:
    given KemKeys[MlKem768] = kemKeysOf("ml-kem-768", MlKem768)
    given KemKeys[MlKem1024] = kemKeysOf("ml-kem-1024", MlKem1024)
end node
