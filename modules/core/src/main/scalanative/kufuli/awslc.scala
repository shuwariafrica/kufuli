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
// Native backend instances over aws-lc, through the C shim `kufuli_awslc.c`. The shim normalises
// aws-lc's return conventions to 1=success and speaks (interior-ptr, len), so a Slice reaches C as
// (s.unsafePtr, s.length); a backend anomaly (an unexpected 0/NULL from an infallible primitive) is
// raised and sanitised to `Unexpected` by the shared `guard`. Keys are carried as their standard
// encodings (SPKI public, PKCS#8 private, raw for ML-KEM) and parsed to an EVP_PKEY handle per op.
package kufuli

import scala.scalanative.unsafe.*
import scala.scalanative.unsigned.*

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import cats.effect.IO
import cats.effect.Resource

@extern
private[kufuli] object awslcffi:
  def kufuli_is_awslc(): CInt = extern
  def kufuli_random_bytes(out: Ptr[Byte], len: CSize): CInt = extern
  def kufuli_cleanse(p: Ptr[Byte], len: CSize): Unit = extern
  def kufuli_aead_new(alg: CInt, key: Ptr[Byte], keyLen: CSize): Ptr[Byte] = extern
  def kufuli_aead_free(ctx: Ptr[Byte]): Unit = extern
  def kufuli_aead_seal(
    ctx: Ptr[Byte],
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize,
    nonce: Ptr[Byte],
    nonceLen: CSize,
    in: Ptr[Byte],
    inLen: CSize,
    ad: Ptr[Byte],
    adLen: CSize): CInt = extern
  def kufuli_aead_open(
    ctx: Ptr[Byte],
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize,
    nonce: Ptr[Byte],
    nonceLen: CSize,
    in: Ptr[Byte],
    inLen: CSize,
    ad: Ptr[Byte],
    adLen: CSize): CInt = extern
  def kufuli_hkdf_extract(
    outPrk: Ptr[Byte],
    outLen: Ptr[CSize],
    md: CInt,
    salt: Ptr[Byte],
    saltLen: CSize,
    ikm: Ptr[Byte],
    ikmLen: CSize): CInt = extern
  def kufuli_hkdf_expand(out: Ptr[Byte], outLen: CSize, md: CInt, prk: Ptr[Byte], prkLen: CSize, info: Ptr[Byte], infoLen: CSize): CInt =
    extern
  def kufuli_pbkdf2(
    out: Ptr[Byte],
    outLen: CSize,
    md: CInt,
    password: Ptr[Byte],
    passwordLen: CSize,
    salt: Ptr[Byte],
    saltLen: CSize,
    iterations: CUnsignedInt): CInt = extern
  def kufuli_hmac(md: CInt, key: Ptr[Byte], keyLen: CSize, data: Ptr[Byte], dataLen: CSize, out: Ptr[Byte], outLen: Ptr[CSize]): CInt =
    extern
  def kufuli_digest_size(md: CInt): CInt = extern
  def kufuli_digest(md: CInt, data: Ptr[Byte], len: CSize, out: Ptr[Byte]): CInt = extern
  def kufuli_hasher_new(md: CInt): Ptr[Byte] = extern
  def kufuli_hasher_free(ctx: Ptr[Byte]): Unit = extern
  def kufuli_hasher_update(ctx: Ptr[Byte], data: Ptr[Byte], len: CSize): CInt = extern
  def kufuli_hasher_digest(ctx: Ptr[Byte], out: Ptr[Byte]): CInt = extern
  def kufuli_aes_wrap(
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize,
    kek: Ptr[Byte],
    kekLen: CSize,
    in: Ptr[Byte],
    inLen: CSize,
    padded: CInt): CInt = extern
  def kufuli_aes_unwrap(
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize,
    kek: Ptr[Byte],
    kekLen: CSize,
    in: Ptr[Byte],
    inLen: CSize,
    padded: CInt): CInt = extern
  def kufuli_aes_cbc(
    encrypt: CInt,
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize,
    key: Ptr[Byte],
    keyLen: CSize,
    iv: Ptr[Byte],
    in: Ptr[Byte],
    inLen: CSize): CInt = extern
  def kufuli_aes_block_encrypt(out: Ptr[Byte], in: Ptr[Byte], key: Ptr[Byte], keyLen: CSize): CInt = extern
  def kufuli_chacha20_keystream(out: Ptr[Byte], outLen: CSize, key: Ptr[Byte], nonce: Ptr[Byte], counter: CUnsignedInt): CInt =
    extern
  def kufuli_kem_sizes(kem: CInt, pub: Ptr[CSize], priv: Ptr[CSize], ct: Ptr[CSize], ss: Ptr[CSize]): CInt = extern
  def kufuli_kem_keypair(kem: CInt, outPub: Ptr[Byte], outPubLen: Ptr[CSize], outPriv: Ptr[Byte], outPrivLen: Ptr[CSize]): CInt =
    extern
  def kufuli_kem_encapsulate(
    kem: CInt,
    pub: Ptr[Byte],
    pubLen: CSize,
    outCt: Ptr[Byte],
    outCtLen: Ptr[CSize],
    outSs: Ptr[Byte],
    outSsLen: Ptr[CSize]): CInt = extern
  def kufuli_kem_decapsulate(
    kem: CInt,
    priv: Ptr[Byte],
    privLen: CSize,
    ct: Ptr[Byte],
    ctLen: CSize,
    outSs: Ptr[Byte],
    outSsLen: Ptr[CSize]): CInt = extern
  def kufuli_pkey_generate(tpe: CInt, rsaBits: CInt): Ptr[Byte] = extern
  def kufuli_pkey_free(pkey: Ptr[Byte]): Unit = extern
  def kufuli_pkey_from_spki(der: Ptr[Byte], len: CSize): Ptr[Byte] = extern
  def kufuli_pkey_from_pkcs8(der: Ptr[Byte], len: CSize): Ptr[Byte] = extern
  def kufuli_pkey_from_raw_public(tpe: CInt, raw: Ptr[Byte], len: CSize): Ptr[Byte] = extern
  def kufuli_pkey_from_ec_point(tpe: CInt, point: Ptr[Byte], len: CSize): Ptr[Byte] = extern
  def kufuli_pkey_from_rsa_components(n: Ptr[Byte], nLen: CSize, e: Ptr[Byte], eLen: CSize): Ptr[Byte] = extern
  def kufuli_pkey_spki(pkey: Ptr[Byte], out: Ptr[Byte], outLen: Ptr[CSize], maxOut: CSize): CInt = extern
  def kufuli_pkey_pkcs8(pkey: Ptr[Byte], out: Ptr[Byte], outLen: Ptr[CSize], maxOut: CSize): CInt = extern
  def kufuli_pkey_raw_public(pkey: Ptr[Byte], out: Ptr[Byte], outLen: Ptr[CSize], maxOut: CSize): CInt = extern
  def kufuli_pkey_ec_point(pkey: Ptr[Byte], out: Ptr[Byte], outLen: Ptr[CSize], maxOut: CSize): CInt = extern
  def kufuli_pkey_rsa_components(
    pkey: Ptr[Byte],
    nOut: Ptr[Byte],
    nLen: Ptr[CSize],
    nMax: CSize,
    eOut: Ptr[Byte],
    eLen: Ptr[CSize],
    eMax: CSize): CInt = extern
  def kufuli_pkey_sign(
    pkey: Ptr[Byte],
    scheme: CInt,
    md: CInt,
    data: Ptr[Byte],
    len: CSize,
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize): CInt = extern
  def kufuli_pkey_verify(pkey: Ptr[Byte], scheme: CInt, md: CInt, data: Ptr[Byte], len: CSize, sig: Ptr[Byte], sigLen: CSize): CInt = extern
  def kufuli_pkey_derive(priv: Ptr[Byte], peerPub: Ptr[Byte], out: Ptr[Byte], outLen: Ptr[CSize], maxOut: CSize): CInt = extern
  def kufuli_pkey_oaep_encrypt(
    pub: Ptr[Byte],
    md: CInt,
    in: Ptr[Byte],
    inLen: CSize,
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize): CInt = extern
  def kufuli_pkey_oaep_decrypt(
    priv: Ptr[Byte],
    md: CInt,
    in: Ptr[Byte],
    inLen: CSize,
    out: Ptr[Byte],
    outLen: Ptr[CSize],
    maxOut: CSize): CInt = extern
end awslcffi

private[kufuli] object awslc:
  import awslcffi.*

  // Shim algorithm codes (mirroring kufuli_awslc.h).
  private inline val AeadAesGcm128 = 1
  private inline val AeadAesGcm192 = 2
  private inline val AeadAesGcm256 = 3
  private inline val AeadChaCha = 4
  private inline val AeadXChaCha = 5
  private inline val AeadGcmSiv256 = 6
  private inline val MdSha1 = 1
  private inline val MdSha256 = 2
  private inline val MdSha384 = 3
  private inline val MdSha512 = 4
  private inline val KemMlKem768 = 1
  private inline val KemMlKem1024 = 2
  private inline val PkeyEd25519 = 1
  private inline val PkeyX25519 = 2
  private inline val PkeyP256 = 3
  private inline val PkeyP384 = 4
  private inline val PkeyP521 = 5
  private inline val PkeyRsa = 6
  private inline val SchemeEd25519 = 1
  private inline val SchemeEcdsa = 2
  private inline val SchemeRsaPss = 3
  private inline val SchemeRsaPkcs1 = 4

  private def op[A](thunk: => A): UEffIO[A] = EffIO.liftF(guard(IO(thunk)))
  private def blockingOp[A](thunk: => A): UEffIO[A] = EffIO.liftF(guard(IO.blocking(thunk)))
  private def opE[E <: Throwable, A](thunk: => Either[E, A]): EffIO[E, A] = EffIO.lift(guard(IO(thunk)))

  // A backend primitive that returns 0 for a call the caller has already made total (a valid key, an
  // in-range length) is a genuine anomaly; raising here routes it through `guard` to a sanitised
  // `Unexpected` defect rather than a wrong success.
  private def require1(ok: CInt): Unit =
    if ok != 1 then throw new IllegalStateException("aws-lc primitive failed unexpectedly") // scalafix:ok DisableSyntax.throw

  // aws-lc yields a null handle (address 0) when it rejects an input. A native pointer is a value,
  // not a nullable reference, so this tests the address directly: boilerplate.nullable does not
  // apply (it boxes an `A | Null` reference) and no `null` literal is needed.
  private def present(p: Ptr[Byte]): Boolean = p.toLong != 0L

  private def requirePresent(p: Ptr[Byte]): Unit = require1(if present(p) then 1 else 0)

  private def mdCode(hash: Sha2): CInt = hash match
    case _: Sha256.type => MdSha256
    case _: Sha384.type => MdSha384
    case _: Sha512.type => MdSha512

  // Runs a shim call that writes at most `max` bytes plus its length, returning the written prefix;
  // the length pointer is consumed here and never escapes, so a stack buffer is sound.
  private def collect(max: Int)(call: (Ptr[Byte], Ptr[CSize]) => CInt): Array[Byte] =
    val buf = new Array[Byte](max)
    val lenP = stackalloc[CSize]()
    require1(call(Slice.of(buf).unsafePtr, lenP))
    buf.take((!lenP).toInt)

  // As `collect`, but a 0 return is the typed failure `e` rather than a defect.
  private def collectE[E](max: Int, e: E)(call: (Ptr[Byte], Ptr[CSize]) => CInt): Either[E, Array[Byte]] =
    val buf = new Array[Byte](max)
    val lenP = stackalloc[CSize]()
    if call(Slice.of(buf).unsafePtr, lenP) == 1 then Right(buf.take((!lenP).toInt)) else Left(e)

  // Parse a stored encoding to an EVP_PKEY handle, use it, and always free it.
  private def withHandle[A](handle: Ptr[Byte])(f: Ptr[Byte] => A): A =
    try f(handle)
    finally kufuli_pkey_free(handle)

  private def parsePub(der: Slice): Ptr[Byte] = kufuli_pkey_from_spki(der.unsafePtr, der.length.toCSize)
  private def parsePriv(der: Slice): Ptr[Byte] = kufuli_pkey_from_pkcs8(der.unsafePtr, der.length.toCSize)

  // Validate a parsed handle and store its canonical encoding as the key's bytes.
  private def storePub(handle: Ptr[Byte], maxLen: Int): Either[InvalidKey, Array[Byte]] =
    if present(handle) then
      try Right(collect(maxLen)((o, l) => kufuli_pkey_spki(handle, o, l, maxLen.toCSize)))
      finally kufuli_pkey_free(handle)
    else Left(InvalidKey.Malformed)

  private def storePriv(handle: Ptr[Byte], maxLen: Int): Either[InvalidKey, Array[Byte]] =
    if present(handle) then
      try Right(collect(maxLen)((o, l) => kufuli_pkey_pkcs8(handle, o, l, maxLen.toCSize)))
      finally kufuli_pkey_free(handle)
    else Left(InvalidKey.Malformed)

  private[kufuli] val random: Random = new Random:
    def bytes(n: Int): UEffIO[Slice] = op {
      val b = new Array[Byte](n)
      require1(kufuli_random_bytes(Slice.of(b).unsafePtr, n.toCSize))
      Slice.of(b)
    }
    def fill(dst: Slice): UEffIO[Unit] = op(require1(kufuli_random_bytes(dst.unsafePtr, dst.length.toCSize)))

  private def aeadOf[A <: AeadAlgorithm](spec: AeadSpec[A], alg: CInt): Aead[A] = new Aead[A]:
    def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
      key.read { k =>
        val ctx = kufuli_aead_new(alg, k.unsafePtr, k.length.toCSize)
        requirePresent(ctx)
        try
          Slice.of(collect(plaintext.length + spec.tagLength) { (o, l) =>
            kufuli_aead_seal(
              ctx,
              o,
              l,
              (plaintext.length + spec.tagLength).toCSize,
              Slice.of(nonce.repr).unsafePtr,
              spec.nonceLength.toCSize,
              plaintext.unsafePtr,
              plaintext.length.toCSize,
              aad.unsafePtr,
              aad.length.toCSize
            )
          })
        finally kufuli_aead_free(ctx)
        end try
      }
    }
    def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice] = opE {
      key.read { k =>
        val ctx = kufuli_aead_new(alg, k.unsafePtr, k.length.toCSize)
        requirePresent(ctx)
        try
          collectE(math.max(0, ciphertext.length - spec.tagLength), AuthFailed) { (o, l) =>
            kufuli_aead_open(
              ctx,
              o,
              l,
              math.max(0, ciphertext.length - spec.tagLength).toCSize,
              Slice.of(nonce.repr).unsafePtr,
              spec.nonceLength.toCSize,
              ciphertext.unsafePtr,
              ciphertext.length.toCSize,
              aad.unsafePtr,
              aad.length.toCSize
            )
          }.map(Slice.of(_))
        finally kufuli_aead_free(ctx)
        end try
      }
    }

  // One const EVP_AEAD_CTX for the engine's lifetime (aws-lc documents these AEADs concurrent-safe);
  // the ctx is zeroised and freed at release.
  final private class AeadEngine[A <: AeadAlgorithm](ctx: Ptr[Byte]) extends Cipher.Engine[A]:
    def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
      val lenP = stackalloc[CSize]()
      require1(
        kufuli_aead_seal(ctx,
                         dst.unsafePtr,
                         lenP,
                         dst.length.toCSize,
                         nonce.unsafePtr,
                         nonce.length.toCSize,
                         src.unsafePtr,
                         src.length.toCSize,
                         aad.unsafePtr,
                         aad.length.toCSize
        )
      )
      (!lenP).toInt
    end encrypt
    def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
      val lenP = stackalloc[CSize]()
      if kufuli_aead_open(ctx,
                          dst.unsafePtr,
                          lenP,
                          dst.length.toCSize,
                          nonce.unsafePtr,
                          nonce.length.toCSize,
                          src.unsafePtr,
                          src.length.toCSize,
                          aad.unsafePtr,
                          aad.length.toCSize
        ) == 1
      then Right((!lenP).toInt)
      else Left(AuthFailed)
      end if
    end decrypt
  end AeadEngine

  private def cipheringOf[A <: AeadAlgorithm](alg: CInt): Ciphering[A] = new Ciphering[A]:
    def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]] =
      Resource
        .make(guard(IO {
          val ctx = key.read(k => kufuli_aead_new(alg, k.unsafePtr, k.length.toCSize))
          requirePresent(ctx)
          ctx
        }))(ctx => IO(kufuli_aead_free(ctx)))
        .map(ctx => new AeadEngine(ctx))

  // AES-CBC-HMAC-SHA2 composite (RFC 7518 section 5.2): key = MAC || ENC halves; the tag is the
  // leading half of HMAC over aad || iv || ct || AL (AL = the 64-bit big-endian aad bit length).
  private def hmacRaw(md: CInt, key: Array[Byte], data: Array[Byte]): Array[Byte] =
    collect(64)((o, l) => kufuli_hmac(md, Slice.of(key).unsafePtr, key.length.toCSize, Slice.of(data).unsafePtr, data.length.toCSize, o, l))
  private def aesCbc(encrypt: Boolean, key: Array[Byte], iv: Array[Byte], in: Array[Byte]): Option[Array[Byte]] =
    collectE(in.length + 16, ())((o, l) =>
      kufuli_aes_cbc(
        if encrypt then 1 else 0,
        o,
        l,
        (in.length + 16).toCSize,
        Slice.of(key).unsafePtr,
        key.length.toCSize,
        Slice.of(iv).unsafePtr,
        Slice.of(in).unsafePtr,
        in.length.toCSize
      )
    ).toOption

  private def cbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], md: CInt): Aead[A] = new Aead[A]:
    private def macTag(macKey: Array[Byte], iv: Array[Byte], aad: Slice, ct: Array[Byte]): Array[Byte] =
      val al = new Array[Byte](8)
      Slice.of(al).writeBE[Long](0, aad.length.toLong * 8)
      hmacRaw(md, macKey, aad.toArray ++ iv ++ ct ++ al).take(spec.tagLength)
    def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice] = op {
      key.read { k =>
        val kb = k.toArray
        val half = kb.length / 2
        val macKey = kb.take(half)
        val encKey = kb.drop(half)
        val iv = nonce.repr
        val ct = aesCbc(encrypt = true, encKey, iv, plaintext.toArray).getOrElse(new Array[Byte](0))
        require1(if ct.isEmpty && plaintext.length > 0 then 0 else 1)
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
          else aesCbc(encrypt = false, encKey, iv, ct).map(Slice.of(_)).toRight(AuthFailed)
      }
    }

  private def macOf[H <: MacAlgorithm](md: CInt): Mac[H] = new Mac[H]:
    def sign(key: SecretKey[H], data: Slice): UEffIO[Signature[H]] = op {
      key.read { k =>
        Signature.unsafe[H](collect(64)((o, l) => kufuli_hmac(md, k.unsafePtr, k.length.toCSize, data.unsafePtr, data.length.toCSize, o, l)))
      }
    }

  private def edSigner: Signer[Ed25519] = new Signer[Ed25519]:
    def sign(key: PrivateKey[Ed25519], data: Slice, scheme: Scheme[Ed25519]): UEffIO[Signature[Ed25519]] = op {
      key.read { der =>
        withHandle(parsePriv(der)) { h =>
          Signature.unsafe[Ed25519](
            collect(64)((o, l) => kufuli_pkey_sign(h, SchemeEd25519, 0, data.unsafePtr, data.length.toCSize, o, l, 64.toCSize))
          )
        }
      }
    }
  private def edVerifier: Verifier[Ed25519] = new Verifier[Ed25519]:
    def verify(key: PublicKey[Ed25519], data: Slice, sig: Signature[Ed25519], scheme: Scheme[Ed25519]): EffIO[SignatureRejected, Unit] =
      opE {
        withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { h =>
          val ok = kufuli_pkey_verify(h,
                                      SchemeEd25519,
                                      0,
                                      data.unsafePtr,
                                      data.length.toCSize,
                                      Slice.of(sig.repr).unsafePtr,
                                      sig.repr.length.toCSize
          )
          if ok == 1 then Right(()) else Left(SignatureRejected)
        }
      }

  private def ecSigner[C <: EcCurve](fieldLength: Int): Signer[C] = new Signer[C]:
    def sign(key: PrivateKey[C], data: Slice, scheme: Scheme[C]): UEffIO[Signature[C]] = op {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => mdCode(hash)
      key.read { der =>
        withHandle(parsePriv(der)) { pkey =>
          val derSig = collect(fieldLength * 2 + 16)((o, l) =>
            kufuli_pkey_sign(pkey, SchemeEcdsa, h, data.unsafePtr, data.length.toCSize, o, l, (fieldLength * 2 + 16).toCSize)
          )
          Signature.unsafe[C](Signature.ecdsaDerToRaw(Slice.of(derSig), fieldLength).getOrElse(new Array[Byte](2 * fieldLength)))
        }
      }
    }
  private def ecVerifier[C <: EcCurve]: Verifier[C] = new Verifier[C]:
    def verify(key: PublicKey[C], data: Slice, sig: Signature[C], scheme: Scheme[C]): EffIO[SignatureRejected, Unit] = opE {
      val h = scheme.runtimeChecked match
        case Ecdsa(hash) => mdCode(hash)
      val derSig = Signature.ecdsaRawToDer(sig.repr)
      withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { pkey =>
        val ok =
          kufuli_pkey_verify(pkey, SchemeEcdsa, h, data.unsafePtr, data.length.toCSize, Slice.of(derSig).unsafePtr, derSig.length.toCSize)
        if ok == 1 then Right(()) else Left(SignatureRejected)
      }
    }

  private def rsaScheme(scheme: Scheme[Rsa]): (scheme: CInt, md: CInt) = scheme.runtimeChecked match
    case RsaPss(hash)   => (scheme = SchemeRsaPss, md = mdCode(hash))
    case RsaPkcs1(hash) => (scheme = SchemeRsaPkcs1, md = mdCode(hash))
  private def rsaSigner: Signer[Rsa] = new Signer[Rsa]:
    def sign(key: PrivateKey[Rsa], data: Slice, scheme: Scheme[Rsa]): UEffIO[Signature[Rsa]] = op {
      val rsa = rsaScheme(scheme)
      key.read { der =>
        withHandle(parsePriv(der)) { pkey =>
          Signature.unsafe[Rsa](
            collect(1024)((o, l) => kufuli_pkey_sign(pkey, rsa.scheme, rsa.md, data.unsafePtr, data.length.toCSize, o, l, 1024.toCSize))
          )
        }
      }
    }
  private def rsaVerifier: Verifier[Rsa] = new Verifier[Rsa]:
    def verify(key: PublicKey[Rsa], data: Slice, sig: Signature[Rsa], scheme: Scheme[Rsa]): EffIO[SignatureRejected, Unit] = opE {
      val rsa = rsaScheme(scheme)
      withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { pkey =>
        val ok = kufuli_pkey_verify(pkey,
                                    rsa.scheme,
                                    rsa.md,
                                    data.unsafePtr,
                                    data.length.toCSize,
                                    Slice.of(sig.repr).unsafePtr,
                                    sig.repr.length.toCSize
        )
        if ok == 1 then Right(()) else Left(SignatureRejected)
      }
    }

  private def agreementOf[A <: AgreementAlgorithm]: Agreement[A] = new Agreement[A]:
    def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEffIO[SharedSecret] = op {
      priv.read { der =>
        withHandle(parsePriv(der)) { privH =>
          withHandle(parsePub(Slice.of(keyBytes(pub.repr)))) { pubH =>
            SharedSecret.unsafe(collect(64)((o, l) => kufuli_pkey_derive(privH, pubH, o, l, 64.toCSize)))
          }
        }
      }
    }

  private def kemOf[K <: KemAlgorithm](kem: CInt, spec: KemSpec[K]): Kem[K] = new Kem[K]:
    def encapsulate(pub: PublicKey[K]): UEffIO[Encapsulated[K]] = op {
      val pubBytes = keyBytes(pub.repr)
      val ctBuf = new Array[Byte](spec.ciphertextLength)
      val ssBuf = new Array[Byte](32)
      val ctLen = stackalloc[CSize]()
      val ssLen = stackalloc[CSize]()
      require1(
        kufuli_kem_encapsulate(kem,
                               Slice.of(pubBytes).unsafePtr,
                               pubBytes.length.toCSize,
                               Slice.of(ctBuf).unsafePtr,
                               ctLen,
                               Slice.of(ssBuf).unsafePtr,
                               ssLen
        )
      )
      Encapsulated(SharedSecret.unsafe(ssBuf.take((!ssLen).toInt)), KemCiphertext.unsafe(ctBuf.take((!ctLen).toInt)))
    }
    def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEffIO[SharedSecret] = op {
      priv.read { p =>
        val ssBuf = new Array[Byte](32)
        val ssLen = stackalloc[CSize]()
        require1(
          kufuli_kem_decapsulate(kem,
                                 p.unsafePtr,
                                 p.length.toCSize,
                                 Slice.of(ct.repr).unsafePtr,
                                 ct.repr.length.toCSize,
                                 Slice.of(ssBuf).unsafePtr,
                                 ssLen
          )
        )
        SharedSecret.unsafe(ssBuf.take((!ssLen).toInt))
      }
    }

  private def wrapOf[W <: WrapAlgorithm](padded: Boolean): Wrap[W] = new Wrap[W]:
    def wrap(kek: SecretKey[W], target: Slice): UEffIO[Slice] = op {
      kek.read { k =>
        Slice.of(
          collect(target.length + 16)((o, l) =>
            kufuli_aes_wrap(o,
                            l,
                            (target.length + 16).toCSize,
                            k.unsafePtr,
                            k.length.toCSize,
                            target.unsafePtr,
                            target.length.toCSize,
                            if padded then 1 else 0
            )
          )
        )
      }
    }
    def unwrap(kek: SecretKey[W], wrapped: Slice): EffIO[UnwrapFailed, Slice] = opE {
      kek.read { k =>
        collectE(wrapped.length, UnwrapFailed)((o, l) =>
          kufuli_aes_unwrap(o,
                            l,
                            wrapped.length.toCSize,
                            k.unsafePtr,
                            k.length.toCSize,
                            wrapped.unsafePtr,
                            wrapped.length.toCSize,
                            if padded then 1 else 0
          )
        ).map(Slice.of(_))
      }
    }

  private[kufuli] val kdf: Kdf = new Kdf:
    def extract(hash: Sha2, salt: Slice, ikm: Slice): UEffIO[Prk] = op {
      Prk.unsafe(
        collect(64)((o, l) => kufuli_hkdf_extract(o, l, mdCode(hash), salt.unsafePtr, salt.length.toCSize, ikm.unsafePtr, ikm.length.toCSize))
      )
    }
    def expand(hash: Sha2, prk: Prk, info: Slice, length: Int): UEffIO[Slice] = op {
      prk.read { p =>
        val out = new Array[Byte](length)
        require1(
          kufuli_hkdf_expand(Slice.of(out).unsafePtr,
                             length.toCSize,
                             mdCode(hash),
                             p.unsafePtr,
                             p.length.toCSize,
                             info.unsafePtr,
                             info.length.toCSize
          )
        )
        Slice.of(out)
      }
    }
    def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEffIO[Slice] = blockingOp {
      val out = new Array[Byte](length)
      require1(
        kufuli_pbkdf2(Slice.of(out).unsafePtr,
                      length.toCSize,
                      mdCode(hash),
                      password.unsafePtr,
                      password.length.toCSize,
                      salt.unsafePtr,
                      salt.length.toCSize,
                      iterations.toUInt
        )
      )
      Slice.of(out)
    }

  private def hashOf[D <: HashAlgorithm](md: CInt, length: Int): Hash[D] = new Hash[D]:
    def digest(data: Slice): UEffIO[Digest] = op {
      val out = new Array[Byte](length)
      require1(kufuli_digest(md, data.unsafePtr, data.length.toCSize, Slice.of(out).unsafePtr))
      Digest.unsafe(out)
    }
  private def hashingOf[D <: HashAlgorithm](md: CInt, length: Int): Hashing[D] = new Hashing[D]:
    def hasher: Resource[IO, Hasher] =
      Resource
        .make(guard(IO {
          val ctx = kufuli_hasher_new(md)
          requirePresent(ctx)
          ctx
        }))(ctx => IO(kufuli_hasher_free(ctx)))
        .map(ctx =>
          new Hasher:
            def update(data: Slice): Unit = require1(kufuli_hasher_update(ctx, data.unsafePtr, data.length.toCSize))
            def digest: Digest =
              val out = new Array[Byte](length)
              require1(kufuli_hasher_digest(ctx, Slice.of(out).unsafePtr))
              Digest.unsafe(out)
        )

  private[kufuli] val oaep: Oaep = new Oaep:
    def encrypt(key: PublicKey[Rsa], plaintext: Slice, scheme: RsaOaep): UEffIO[Slice] = op {
      withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { pkey =>
        Slice.of(
          collect(1024)((o, l) =>
            kufuli_pkey_oaep_encrypt(pkey, mdCode(scheme.hash), plaintext.unsafePtr, plaintext.length.toCSize, o, l, 1024.toCSize)
          )
        )
      }
    }
    def decrypt(key: PrivateKey[Rsa], ciphertext: Slice, scheme: RsaOaep): EffIO[AuthFailed, Slice] = opE {
      key.read { der =>
        withHandle(parsePriv(der)) { pkey =>
          collectE(1024, AuthFailed)((o, l) =>
            kufuli_pkey_oaep_decrypt(pkey, mdCode(scheme.hash), ciphertext.unsafePtr, ciphertext.length.toCSize, o, l, 1024.toCSize)
          ).map(Slice.of(_))
        }
      }
    }

  // Public keys are stored as SPKI, private keys as PKCS#8 (ML-KEM excepted, which travels raw). A
  // generous marshal buffer covers every family; the shim reports the true length.
  private inline val SpkiMax = 2048
  private inline val Pkcs8Max = 4096

  private def genPkey(tpe: CInt, rsaBits: CInt): (pub: Array[Byte], priv: Array[Byte]) =
    val h = kufuli_pkey_generate(tpe, rsaBits)
    requirePresent(h)
    try
      val pub = collect(SpkiMax)((o, l) => kufuli_pkey_spki(h, o, l, SpkiMax.toCSize))
      val priv = collect(Pkcs8Max)((o, l) => kufuli_pkey_pkcs8(h, o, l, Pkcs8Max.toCSize))
      (pub = pub, priv = priv)
    finally kufuli_pkey_free(h)

  private[kufuli] val edKeys: EdKeys = new EdKeys:
    def generate: UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = op {
      val kp = genPkey(PkeyEd25519, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else
        storePub(kufuli_pkey_from_raw_public(PkeyEd25519, bytes.unsafePtr, bytes.length.toCSize), SpkiMax).map(b =>
          PublicKey.unsafe(keyRepr(b))
        )
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Ed25519]] =
      opE(storePub(parsePub(der), SpkiMax).map(b => PublicKey.unsafe(keyRepr(b))))
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Ed25519]] =
      opE(storePriv(parsePriv(der), Pkcs8Max).map(PrivateKey.unsafe))
    def raw(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h => IArray.from(collect(32)((o, l) => kufuli_pkey_raw_public(h, o, l, 32.toCSize))))
      )
    def spki(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private[kufuli] val xKeys: XKeys = new XKeys:
    def generate: UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = op {
      val kp = genPkey(PkeyX25519, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[X25519]] = opE {
      if bytes.length != 32 then Left(InvalidKey.WrongLength(32, bytes.length))
      else if bytes.toArray.forall(_ == 0) then Left(InvalidKey.WeakPoint)
      else
        storePub(kufuli_pkey_from_raw_public(PkeyX25519, bytes.unsafePtr, bytes.length.toCSize), SpkiMax).map(b =>
          PublicKey.unsafe(keyRepr(b))
        )
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[X25519]] =
      opE(storePub(parsePub(der), SpkiMax).map(b => PublicKey.unsafe(keyRepr(b))))
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[X25519]] =
      opE(storePriv(parsePriv(der), Pkcs8Max).map(PrivateKey.unsafe))
    def raw(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h => IArray.from(collect(32)((o, l) => kufuli_pkey_raw_public(h, o, l, 32.toCSize))))
      )
    def spki(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private def ecKeysOf[C <: EcCurve](tpe: CInt, fieldLength: Int): EcKeys[C] = new EcKeys[C]:
    private val pointLength = 1 + 2 * fieldLength
    def generate: UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]] = op {
      val kp = genPkey(tpe, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    def fromSec1(point: Slice): EffIO[InvalidKey, PublicKey[C]] = opE {
      if point.length != pointLength then Left(InvalidKey.WrongLength(pointLength, point.length))
      else if point(0) != 4.toByte then Left(InvalidKey.Malformed)
      else
        val h = kufuli_pkey_from_ec_point(tpe, point.unsafePtr, point.length.toCSize)
        if present(h) then storePub(h, SpkiMax).map(b => PublicKey.unsafe(keyRepr(b))) else Left(InvalidKey.NotOnCurve)
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[C]] =
      opE(storePub(parsePub(der), SpkiMax).map(b => PublicKey.unsafe(keyRepr(b))))
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[C]] =
      opE(storePriv(parsePriv(der), Pkcs8Max).map(PrivateKey.unsafe))
    def sec1(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h =>
          IArray.from(collect(pointLength)((o, l) => kufuli_pkey_ec_point(h, o, l, pointLength.toCSize)))
        )
      )
    def spki(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[C]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private[kufuli] val rsaKeys: RsaKeys = new RsaKeys:
    def generate(size: Rsa.Size): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]] = blockingOp {
      val kp = genPkey(PkeyRsa, size.bits)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    def fromComponents(modulus: Slice, exponent: Slice): EffIO[InvalidKey, PublicKey[Rsa]] = opE {
      storePub(kufuli_pkey_from_rsa_components(modulus.unsafePtr, modulus.length.toCSize, exponent.unsafePtr, exponent.length.toCSize),
               SpkiMax
      ).map(b => PublicKey.unsafe(keyRepr(b)))
    }
    def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Rsa]] =
      opE(storePub(parsePub(der), SpkiMax).map(b => PublicKey.unsafe(keyRepr(b))))
    def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Rsa]] =
      opE(storePriv(parsePriv(der), Pkcs8Max).map(PrivateKey.unsafe))
    def components(key: PublicKey[Rsa]): EffIO[KeyNotExportable, Rsa.Components] = op {
      withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { h =>
        val nBuf = new Array[Byte](1024)
        val eBuf = new Array[Byte](16)
        val nLen = stackalloc[CSize]()
        val eLen = stackalloc[CSize]()
        require1(kufuli_pkey_rsa_components(h, Slice.of(nBuf).unsafePtr, nLen, 1024.toCSize, Slice.of(eBuf).unsafePtr, eLen, 16.toCSize))
        Rsa.Components(IArray.from(nBuf.take((!nLen).toInt)), IArray.from(eBuf.take((!eLen).toInt)))
      }
    }
    def spki(key: PublicKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    def pkcs8(key: PrivateKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]] =
      EffIO.defer(key.read(s => op(IArray.from(s.toArray))))

  private def kemKeysOf[K <: KemAlgorithm](kem: CInt, spec: KemSpec[K], privLength: Int): KemKeys[K] = new KemKeys[K]:
    def generate: UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]] = op {
      val pubBuf = new Array[Byte](spec.publicKeyLength)
      val privBuf = new Array[Byte](privLength)
      val pubLen = stackalloc[CSize]()
      val privLen = stackalloc[CSize]()
      require1(kufuli_kem_keypair(kem, Slice.of(pubBuf).unsafePtr, pubLen, Slice.of(privBuf).unsafePtr, privLen))
      KeyPair(PublicKey.unsafe(keyRepr(pubBuf.take((!pubLen).toInt))), PrivateKey.unsafe(privBuf.take((!privLen).toInt)))
    }
    def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[K]] = opE {
      if bytes.length != spec.publicKeyLength then Left(InvalidKey.WrongLength(spec.publicKeyLength, bytes.length))
      else Right(PublicKey.unsafe(keyRepr(bytes.toArray)))
    }
    def raw(key: PublicKey[K]): EffIO[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))

  // Capability bundles the Native platform table wires each companion into.
  private[kufuli] trait RandomDefault:
    given Random = random
  private[kufuli] trait AeadUniversal:
    given Aead[AesGcm128] = aeadOf(AesGcm128, AeadAesGcm128)
    given Aead[AesGcm192] = aeadOf(AesGcm192, AeadAesGcm192)
    given Aead[AesGcm256] = aeadOf(AesGcm256, AeadAesGcm256)
    given Aead[A128CbcHs256] = cbcHs(A128CbcHs256, MdSha256)
    given Aead[A256CbcHs512] = cbcHs(A256CbcHs512, MdSha512)
  private[kufuli] trait AeadChaCha:
    given Aead[ChaCha20Poly1305] = aeadOf(ChaCha20Poly1305, AeadChaCha)
  private[kufuli] trait AeadMisuseResistant:
    given Aead[XChaCha20Poly1305] = aeadOf(XChaCha20Poly1305, AeadXChaCha)
    given Aead[AesGcmSiv256] = aeadOf(AesGcmSiv256, AeadGcmSiv256)
  private[kufuli] trait CipheringUniversal:
    given Ciphering[AesGcm128] = cipheringOf(AeadAesGcm128)
    given Ciphering[AesGcm192] = cipheringOf(AeadAesGcm192)
    given Ciphering[AesGcm256] = cipheringOf(AeadAesGcm256)
  private[kufuli] trait CipheringChaCha:
    given Ciphering[ChaCha20Poly1305] = cipheringOf(AeadChaCha)
  private[kufuli] trait CipheringMisuseResistant:
    given Ciphering[XChaCha20Poly1305] = cipheringOf(AeadXChaCha)
    given Ciphering[AesGcmSiv256] = cipheringOf(AeadGcmSiv256)
  private[kufuli] trait MacAll:
    given Mac[HmacSha256] = macOf(MdSha256)
    given Mac[HmacSha384] = macOf(MdSha384)
    given Mac[HmacSha512] = macOf(MdSha512)
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
    given Agreement[X25519] = agreementOf
    given Agreement[P256] = agreementOf
    given Agreement[P384] = agreementOf
    given Agreement[P521] = agreementOf
  private[kufuli] trait KemAll:
    given Kem[MlKem768] = kemOf(KemMlKem768, MlKem768)
    given Kem[MlKem1024] = kemOf(KemMlKem1024, MlKem1024)
  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapOf(padded = false)
    given Wrap[AesKw256] = wrapOf(padded = false)
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapOf(padded = true)
    given Wrap[AesKwp256] = wrapOf(padded = true)
  private[kufuli] trait KdfDefault:
    given Kdf = kdf
  private[kufuli] trait HashAll:
    given Hash[Sha1] = hashOf(MdSha1, 20)
    given Hash[Sha256] = hashOf(MdSha256, 32)
    given Hash[Sha384] = hashOf(MdSha384, 48)
    given Hash[Sha512] = hashOf(MdSha512, 64)
  private[kufuli] trait HashingSync:
    given Hashing[Sha256] = hashingOf(MdSha256, 32)
    given Hashing[Sha384] = hashingOf(MdSha384, 48)
    given Hashing[Sha512] = hashingOf(MdSha512, 64)
  private[kufuli] trait OaepDefault:
    given Oaep = oaep
  private[kufuli] trait EdKeysBytes:
    given EdKeys = edKeys
  private[kufuli] trait XKeysBytes:
    given XKeys = xKeys
  private[kufuli] trait EcKeysBytes:
    given EcKeys[P256] = ecKeysOf(PkeyP256, 32)
    given EcKeys[P384] = ecKeysOf(PkeyP384, 48)
    given EcKeys[P521] = ecKeysOf(PkeyP521, 66)
  private[kufuli] trait RsaKeysBytes:
    given RsaKeys = rsaKeys
  private[kufuli] trait KemKeysAll:
    given KemKeys[MlKem768] = kemKeysOf(KemMlKem768, MlKem768, 2400)
    given KemKeys[MlKem1024] = kemKeysOf(KemMlKem1024, MlKem1024, 3168)
end awslc
