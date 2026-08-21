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
import boilerplate.effect.Eff
import boilerplate.effect.UEff
import boilerplate.nullable.option
import cats.effect.IO
import cats.effect.Resource

@extern
private[kufuli] object awslcffi:
  def kufuli_is_awslc(): CInt = extern
  def kufuli_random_bytes(out: Ptr[Byte], len: CSize): CInt = extern
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
  def kufuli_kem_public_valid(kem: CInt, pub: Ptr[Byte], pubLen: CSize): CInt = extern
  def kufuli_kem_keypair(
    kem: CInt,
    outPub: Ptr[Byte],
    outPubLen: Ptr[CSize],
    maxPub: CSize,
    outPriv: Ptr[Byte],
    outPrivLen: Ptr[CSize],
    maxPriv: CSize): CInt = extern
  def kufuli_kem_keypair_from_seed(
    kem: CInt,
    seed: Ptr[Byte],
    seedLen: CSize,
    outPub: Ptr[Byte],
    outPubLen: Ptr[CSize],
    maxPub: CSize,
    outPriv: Ptr[Byte],
    outPrivLen: Ptr[CSize],
    maxPriv: CSize): CInt = extern
  def kufuli_kem_encapsulate(
    kem: CInt,
    pub: Ptr[Byte],
    pubLen: CSize,
    outCt: Ptr[Byte],
    outCtLen: Ptr[CSize],
    maxCt: CSize,
    outSs: Ptr[Byte],
    outSsLen: Ptr[CSize],
    maxSs: CSize): CInt = extern
  def kufuli_kem_decapsulate(
    kem: CInt,
    priv: Ptr[Byte],
    privLen: CSize,
    ct: Ptr[Byte],
    ctLen: CSize,
    outSs: Ptr[Byte],
    outSsLen: Ptr[CSize],
    maxSs: CSize): CInt = extern
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

  private def op[A](thunk: => A): UEff[A] = guard(IO(thunk))
  private def blockingOp[A](thunk: => A): UEff[A] = guard(IO.blocking(thunk))
  private def opE[E <: Throwable, A](thunk: => Either[E, A]): Eff[E, A] = Eff.lift(guard(IO(thunk)))

  // A backend primitive that returns 0 for a call the caller has already made total (a valid key, an
  // in-range length) is a genuine anomaly; raising here routes it through `guard` to a sanitised
  // `Unexpected` defect rather than a wrong success.
  private def require1(ok: CInt): Unit =
    if ok != 1 then throw new IllegalStateException("aws-lc primitive failed unexpectedly") // scalafix:ok DisableSyntax.throw

  // aws-lc yields a null handle when it rejects an input, and Scala Native surfaces that as a null
  // REFERENCE, not as a pointer whose address is zero: the test must therefore be a reference test,
  // because reading the address off the handle dereferences it. Every `Refused` this
  // backend reports for a rejected encoding depends on this.
  private def present(p: Ptr[Byte]): Boolean =
    val handle: Ptr[Byte] | Null = p
    handle.option.isDefined

  private def requirePresent(p: Ptr[Byte]): Unit = require1(if present(p) then 1 else 0)

  // The compile-time OPENSSL_IS_AWSLC assertion and the link-time dialect gate both hold at build
  // time. A consumer who rebinds `crypto` to a system shared library can still put another provider
  // behind the same symbols, and this runs once, on first touch of any instance, before it can.
  require1(kufuli_is_awslc())

  private def mdCode(hash: Sha2): CInt = hash match
    case _: Sha256.type => MdSha256
    case _: Sha384.type => MdSha384
    case _: Sha512.type => MdSha512

  // Runs a shim call that writes at most `max` bytes plus its length, returning the written prefix;
  // the length pointer is consumed here and never escapes, so a stack buffer is sound.
  // The staging buffer holds whatever the call produced - a shared secret, a PRK, a PKCS#8 private
  // key - and `take` only copies the used prefix, so the buffer is wiped before it is released.
  // Native's `Slice.wipe` is a volatile store the optimiser must keep, which is why erasure here is
  // a guarantee rather than best effort.
  private def collect(max: Int)(call: (Ptr[Byte], Ptr[CSize]) => CInt): Array[Byte] =
    val buf = new Array[Byte](max)
    try
      val lenP = stackalloc[CSize]()
      require1(call(Slice.of(buf).unsafePtr, lenP))
      buf.take((!lenP).toInt)
    finally Slice.of(buf).wipe()

  // As `collect`, for the two marshalling calls that report the length they need (-1) instead of
  // failing when the buffer is short: the encoded length varies with the key, so a fixed buffer
  // would cap the key sizes this backend accepts while the others take them. The retry is bounded
  // because the modulus ceiling is enforced above every backend before a handle reaches here.
  private def marshalled(initial: Int)(call: (Ptr[Byte], Ptr[CSize], Int) => CInt): Array[Byte] =
    attempt(initial)(call) match
      case Right(bytes) => bytes
      case Left(needed) => demand(attempt(needed)(call))

  private def attempt(max: Int)(call: (Ptr[Byte], Ptr[CSize], Int) => CInt): Either[Int, Array[Byte]] =
    val buf = new Array[Byte](max)
    try
      val lenP = stackalloc[CSize]()
      val rc = call(Slice.of(buf).unsafePtr, lenP, max)
      require1(if rc == 0 then 0 else 1)
      if rc == 1 then Right(buf.take((!lenP).toInt)) else Left((!lenP).toInt)
    finally Slice.of(buf).wipe()

  // As `collect`, but a 0 return is the typed failure `e` rather than a defect.
  private def collectE[E](max: Int, e: E)(call: (Ptr[Byte], Ptr[CSize]) => CInt): Either[E, Array[Byte]] =
    val buf = new Array[Byte](max)
    try
      val lenP = stackalloc[CSize]()
      if call(Slice.of(buf).unsafePtr, lenP) == 1 then Right(buf.take((!lenP).toInt)) else Left(e)
    finally Slice.of(buf).wipe()

  // An export hands the caller a copy by contract; the transient between the carrier and that copy
  // is not part of it.
  private def exported(s: Slice): IArray[Byte] =
    val bytes = s.toArray
    try IArray.from(bytes)
    finally Slice.of(bytes).wipe()

  // Parse a stored encoding to an EVP_PKEY handle, use it, and always free it. A stored encoding is
  // one this backend marshalled itself, so an unparseable one is an anomaly - and it must not reach
  // the shim: aws-lc's EVP_PKEY_derive_set_peer reads the peer's type field with no null guard.
  private def withHandle[A](handle: Ptr[Byte])(f: Ptr[Byte] => A): A =
    requirePresent(handle)
    try f(handle)
    finally kufuli_pkey_free(handle)

  private def parsePub(der: Slice): Ptr[Byte] = kufuli_pkey_from_spki(der.unsafePtr, der.length.toCSize)
  private def parsePriv(der: Slice): Ptr[Byte] = kufuli_pkey_from_pkcs8(der.unsafePtr, der.length.toCSize)

  // Validate a parsed handle and store its canonical encoding as the key's bytes. aws-lc infers the
  // family from the encoding and one EC handle serves every curve, so the canonical encoding's own
  // AlgorithmIdentifier is what binds the import to the family and curve the caller named.
  // Import refusal is BINARY here: the companion door names the public arm from the form it was
  // handed, so this backend cannot classify differently from its siblings.
  private def storePub(handle: Ptr[Byte], maxLen: Int, expect: DER.Alg): Either[Refused, Array[Byte]] =
    if present(handle) then
      try
        val stored = marshalled(maxLen)((o, l, m) => kufuli_pkey_spki(handle, o, l, m.toCSize))
        DER.requireSpki(Slice.of(stored), expect).left.map(_ => Refused).map(_ => stored)
      finally kufuli_pkey_free(handle)
    else Left(Refused)

  private def storePriv(handle: Ptr[Byte], maxLen: Int, expect: DER.Alg): Either[Refused, Array[Byte]] =
    if present(handle) then
      try
        val stored = marshalled(maxLen)((o, l, m) => kufuli_pkey_pkcs8(handle, o, l, m.toCSize))
        DER.requirePkcs8(Slice.of(stored), expect).left.map(_ => Refused).map(_ => stored)
      finally kufuli_pkey_free(handle)
    else Left(Refused)

  private[kufuli] val random: Random = new Random:
    private[kufuli] def bytes(n: Int): UEff[Slice] = op {
      val b = new Array[Byte](n)
      require1(kufuli_random_bytes(Slice.of(b).unsafePtr, n.toCSize))
      Slice.of(b)
    }
    private[kufuli] def fill(dst: Slice): UEff[Unit] = op(require1(kufuli_random_bytes(dst.unsafePtr, dst.length.toCSize)))

  private def aeadOf[A <: AeadAlgorithm](spec: AeadSpec[A], alg: CInt): AEAD[A] = new AEAD[A]:
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEff[Slice] = op {
      key.material { k =>
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
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): Eff[AuthFailed, Slice] = opE {
      key.material { k =>
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
    private[kufuli] def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int =
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
    private[kufuli] def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int] =
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
      else
        // No erase here: aws-lc's own contract is that `out` is filled with zero bytes on any
        // failure (aead.h:336), which is the same guarantee the wrapper states.
        Left(AuthFailed)
      end if
    end decrypt
  end AeadEngine

  private def cipheringOf[A <: AeadAlgorithm](alg: CInt): Ciphering[A] = new Ciphering[A]:
    private[kufuli] def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]] =
      Resource
        .make(guard(IO {
          val ctx = key.material(k => kufuli_aead_new(alg, k.unsafePtr, k.length.toCSize))
          requirePresent(ctx)
          ctx
        }))(ctx => IO(kufuli_aead_free(ctx)))
        .map(ctx => new AeadEngine(ctx))

  // AES-CBC-HMAC-SHA2 composite (RFC 7518 section 5.2): key = MAC || ENC halves; the tag is the
  // leading half of HMAC over aad || iv || ct || AL (AL = the 64-bit big-endian aad bit length).
  // Both take the key as a Slice so a composite key can be halved by view: `drop` advances the
  // interior pointer, which is what a borrowed carrier reaches C as.
  private def hmacRaw(md: CInt, key: Slice, data: Array[Byte]): Array[Byte] =
    collect(64)((o, l) => kufuli_hmac(md, key.unsafePtr, key.length.toCSize, Slice.of(data).unsafePtr, data.length.toCSize, o, l))
  private def aesCbc(encrypt: Boolean, key: Slice, iv: Array[Byte], in: Array[Byte]): Option[Array[Byte]] =
    collectE(in.length + 16, ())((o, l) =>
      kufuli_aes_cbc(
        if encrypt then 1 else 0,
        o,
        l,
        (in.length + 16).toCSize,
        key.unsafePtr,
        key.length.toCSize,
        Slice.of(iv).unsafePtr,
        Slice.of(in).unsafePtr,
        in.length.toCSize
      )
    ).toOption

  private def cbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], md: CInt): AEAD[A] = new AEAD[A]:
    private def macTag(macKey: Slice, iv: Array[Byte], aad: Slice, ct: Array[Byte]): Array[Byte] =
      val al = new Array[Byte](8)
      Slice.of(al).writeBE[Long](0, aad.length.toLong * 8)
      hmacRaw(md, macKey, aad.toArray ++ iv ++ ct ++ al).take(spec.tagLength)
    // Both halves are windows onto the borrowed carrier, so the composite key is never copied out
    // and there is nothing to erase on the way back.
    private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEff[Slice] = op {
      key.material { k =>
        val half = k.length / 2
        val iv = nonce.repr
        // PKCS#7 always emits at least one block, for the empty plaintext included, so an empty
        // result is a failed encryption whatever went in.
        val ct = demand(aesCbc(encrypt = true, k.drop(half), iv, plaintext.toArray).toRight(()))
        require1(if ct.isEmpty then 0 else 1)
        Slice.of(ct ++ macTag(k.take(half), iv, aad, ct))
      }
    }
    private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): Eff[AuthFailed, Slice] = opE {
      key.material { k =>
        val half = k.length / 2
        val iv = nonce.repr
        val whole = ciphertext.toArray
        if whole.length < spec.tagLength then Left(AuthFailed)
        else
          val ct = whole.take(whole.length - spec.tagLength)
          val tag = whole.drop(whole.length - spec.tagLength)
          if !Slice.of(macTag(k.take(half), iv, aad, ct)).constantTimeEquals(Slice.of(tag)) then Left(AuthFailed)
          else aesCbc(encrypt = false, k.drop(half), iv, ct).map(Slice.of(_)).toRight(AuthFailed)
      }
    }

  private def macOf[H <: MacAlgorithm](md: CInt): MAC[H] = new MAC[H]:
    private[kufuli] def sign(key: SecretKey[H], data: Slice): UEff[Signature[H]] = op {
      key.material { k =>
        Signature.unsafe[H](collect(64)((o, l) => kufuli_hmac(md, k.unsafePtr, k.length.toCSize, data.unsafePtr, data.length.toCSize, o, l)))
      }
    }

  private def edSigner: Signing[Ed25519] = new Signing[Ed25519]:
    private[kufuli] def sign(key: PrivateKey[Ed25519], data: Slice, scheme: Scheme[Ed25519]): UEff[Signature[Ed25519]] = op {
      key.material { der =>
        withHandle(parsePriv(der)) { h =>
          Signature.unsafe[Ed25519](
            collect(64)((o, l) => kufuli_pkey_sign(h, SchemeEd25519, 0, data.unsafePtr, data.length.toCSize, o, l, 64.toCSize))
          )
        }
      }
    }
  private def edVerifier: Verifying[Ed25519] = new Verifying[Ed25519]:
    private[kufuli] def verify(
      key: PublicKey[Ed25519],
      data: Slice,
      sig: Signature[Ed25519],
      scheme: Scheme[Ed25519]): Eff[SignatureRejected, Unit] =
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

  private def ecSigner[C <: EcCurve](fieldLength: Int): Signing[C] = new Signing[C]:
    private[kufuli] def sign(key: PrivateKey[C], data: Slice, scheme: Scheme[C]): UEff[Signature[C]] = op {
      val h = scheme.runtimeChecked match
        case ECDSA(hash) => mdCode(hash)
      key.material { der =>
        withHandle(parsePriv(der)) { pkey =>
          val derSig = collect(fieldLength * 2 + 16)((o, l) =>
            kufuli_pkey_sign(pkey, SchemeEcdsa, h, data.unsafePtr, data.length.toCSize, o, l, (fieldLength * 2 + 16).toCSize)
          )
          Signature.unsafe[C](demand(Signature.ecdsaDerToRaw(Slice.of(derSig), fieldLength)))
        }
      }
    }
  private def ecVerifier[C <: EcCurve]: Verifying[C] = new Verifying[C]:
    private[kufuli] def verify(key: PublicKey[C], data: Slice, sig: Signature[C], scheme: Scheme[C]): Eff[SignatureRejected, Unit] = opE {
      val h = scheme.runtimeChecked match
        case ECDSA(hash) => mdCode(hash)
      val derSig = Signature.ecdsaRawToDer(sig.repr)
      withHandle(parsePub(Slice.of(keyBytes(key.repr)))) { pkey =>
        val ok =
          kufuli_pkey_verify(pkey, SchemeEcdsa, h, data.unsafePtr, data.length.toCSize, Slice.of(derSig).unsafePtr, derSig.length.toCSize)
        if ok == 1 then Right(()) else Left(SignatureRejected)
      }
    }

  private def rsaScheme(scheme: Scheme[RSA]): (scheme: CInt, md: CInt) = scheme.runtimeChecked match
    case RsaPss(hash)   => (scheme = SchemeRsaPss, md = mdCode(hash))
    case RsaPkcs1(hash) => (scheme = SchemeRsaPkcs1, md = mdCode(hash))
  // An RSA operation writes at most one modulus (a signature, an OAEP ciphertext, or the modulus
  // itself) and the stored encoding it derives from embeds that modulus, so that encoding's own
  // length is a sufficient capacity at any key size - where a fixed buffer would cap the modulus
  // this backend accepts.
  private def rsaSigner: Signing[RSA] = new Signing[RSA]:
    private[kufuli] def sign(key: PrivateKey[RSA], data: Slice, scheme: Scheme[RSA]): UEff[Signature[RSA]] = op {
      val rsa = rsaScheme(scheme)
      key.material { der =>
        val capacity = der.length
        withHandle(parsePriv(der)) { pkey =>
          Signature.unsafe[RSA](
            collect(capacity)((o, l) =>
              kufuli_pkey_sign(pkey, rsa.scheme, rsa.md, data.unsafePtr, data.length.toCSize, o, l, capacity.toCSize)
            )
          )
        }
      }
    }
  private def rsaVerifier: Verifying[RSA] = new Verifying[RSA]:
    private[kufuli] def verify(key: PublicKey[RSA], data: Slice, sig: Signature[RSA], scheme: Scheme[RSA]): Eff[SignatureRejected, Unit] =
      opE {
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

  // aws-lc's EVP_PKEY_derive treats an output buffer smaller than the field as a silent truncation
  // rather than an error, so the capacity is the curve's exact secret length and a short return is
  // raised as a defect.
  private def agreementOf[A <: AgreementAlgorithm](secretLength: Int): Agreement[A] = new Agreement[A]:
    private[kufuli] def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEff[SharedSecret] = op {
      priv.material { der =>
        withHandle(parsePriv(der)) { privH =>
          withHandle(parsePub(Slice.of(keyBytes(pub.repr)))) { pubH =>
            val secret = collect(secretLength)((o, l) => kufuli_pkey_derive(privH, pubH, o, l, secretLength.toCSize))
            require1(if secret.length == secretLength then 1 else 0)
            SharedSecret.unsafe(secret)
          }
        }
      }
    }

  private inline val KemSecretMax = 32

  private def kemOf[K <: KemAlgorithm](kem: CInt, spec: KemSpec[K]): KEM[K] = new KEM[K]:
    private[kufuli] def encapsulate(pub: PublicKey[K]): UEff[Encapsulated[K]] = op {
      val pubBytes = keyBytes(pub.repr)
      val ctBuf = new Array[Byte](spec.ciphertextLength)
      val ctLen = stackalloc[CSize]()
      val secret = collect(KemSecretMax) { (o, l) =>
        kufuli_kem_encapsulate(kem,
                               Slice.of(pubBytes).unsafePtr,
                               pubBytes.length.toCSize,
                               Slice.of(ctBuf).unsafePtr,
                               ctLen,
                               spec.ciphertextLength.toCSize,
                               o,
                               l,
                               KemSecretMax.toCSize
        )
      }
      Encapsulated(SharedSecret.unsafe(secret), KemCiphertext.unsafe(ctBuf.take((!ctLen).toInt)))
    }
    private[kufuli] def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEff[SharedSecret] = op {
      priv.material { p =>
        SharedSecret.unsafe(
          collect(KemSecretMax)((o, l) =>
            kufuli_kem_decapsulate(kem,
                                   p.unsafePtr,
                                   p.length.toCSize,
                                   Slice.of(ct.repr).unsafePtr,
                                   ct.repr.length.toCSize,
                                   o,
                                   l,
                                   KemSecretMax.toCSize
            )
          )
        )
      }
    }

  private def wrapOf[W <: WrapAlgorithm](padded: Boolean): Wrap[W] = new Wrap[W]:
    private[kufuli] def wrap(kek: SecretKey[W], target: Slice): UEff[Slice] = op {
      kek.material { k =>
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
    private[kufuli] def unwrap(kek: SecretKey[W], wrapped: Slice): Eff[UnwrapFailed, Slice] = opE {
      kek.material { k =>
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

  private[kufuli] val kdf: KDF = new KDF:
    private[kufuli] def extract(hash: Sha2, salt: Slice, ikm: Slice): UEff[PRK] = op {
      PRK.unsafe(
        collect(64)((o, l) => kufuli_hkdf_extract(o, l, mdCode(hash), salt.unsafePtr, salt.length.toCSize, ikm.unsafePtr, ikm.length.toCSize))
      )
    }
    private[kufuli] def expand(hash: Sha2, prk: PRK, info: Slice, length: Int): UEff[Slice] = op {
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
    private[kufuli] def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEff[Slice] = blockingOp {
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
    private[kufuli] def digest(data: Slice): UEff[Digest] = op {
      val out = new Array[Byte](length)
      require1(kufuli_digest(md, data.unsafePtr, data.length.toCSize, Slice.of(out).unsafePtr))
      Digest.unsafe(out)
    }
  private def hashingOf[D <: HashAlgorithm](md: CInt, length: Int): Hashing[D] = new Hashing[D]:
    private[kufuli] def hasher: Resource[IO, Hasher] =
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

  private[kufuli] val oaep: OAEP = new OAEP:
    private[kufuli] def encrypt(key: PublicKey[RSA], plaintext: Slice, scheme: RsaOaep): UEff[Slice] = op {
      val spki = keyBytes(key.repr)
      val capacity = spki.length
      withHandle(parsePub(Slice.of(spki))) { pkey =>
        Slice.of(
          collect(capacity)((o, l) =>
            kufuli_pkey_oaep_encrypt(pkey, mdCode(scheme.hash), plaintext.unsafePtr, plaintext.length.toCSize, o, l, capacity.toCSize)
          )
        )
      }
    }
    private[kufuli] def decrypt(key: PrivateKey[RSA], ciphertext: Slice, scheme: RsaOaep): Eff[AuthFailed, Slice] = opE {
      key.material { der =>
        val capacity = der.length
        withHandle(parsePriv(der)) { pkey =>
          collectE(capacity, AuthFailed)((o, l) =>
            kufuli_pkey_oaep_decrypt(pkey, mdCode(scheme.hash), ciphertext.unsafePtr, ciphertext.length.toCSize, o, l, capacity.toCSize)
          ).map(Slice.of(_))
        }
      }
    }

  // Public keys are stored as SPKI, private keys as PKCS#8 (ML-KEM excepted, which travels raw).
  // These are the COMMON-CASE staging sizes, not caps: the marshal reports the length it needs and
  // `marshalled` re-runs at that size, so an RSA-8192 PrivateKeyInfo (4678 octets) stores here
  // exactly as it does on the other backends.
  private inline val SpkiMax = 2048
  private inline val Pkcs8Max = 4096

  private def genPkey(tpe: CInt, rsaBits: CInt): (pub: Array[Byte], priv: Array[Byte]) =
    val h = kufuli_pkey_generate(tpe, rsaBits)
    requirePresent(h)
    try
      val pub = marshalled(SpkiMax)((o, l, m) => kufuli_pkey_spki(h, o, l, m.toCSize))
      val priv = marshalled(Pkcs8Max)((o, l, m) => kufuli_pkey_pkcs8(h, o, l, m.toCSize))
      (pub = pub, priv = priv)
    finally kufuli_pkey_free(h)

  private[kufuli] val edKeys: EdKeys = new EdKeys:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = op {
      val kp = genPkey(PkeyEd25519, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[Ed25519]] =
      opE(
        storePub(kufuli_pkey_from_raw_public(PkeyEd25519, bytes.unsafePtr, bytes.length.toCSize), SpkiMax, DER.Alg.Ed)
          .map(b => PublicKey.unsafe(keyRepr(b)))
      )
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[Ed25519]] =
      opE(storePub(parsePub(der), SpkiMax, DER.Alg.Ed).map(b => PublicKey.unsafe(keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[Ed25519]] =
      opE(storePriv(parsePriv(der), Pkcs8Max, DER.Alg.Ed).map(PrivateKey.unsafe))
    private[kufuli] def raw(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h => IArray.from(collect(32)((o, l) => kufuli_pkey_raw_public(h, o, l, 32.toCSize))))
      )
    private[kufuli] def spki(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(exported)))

  private[kufuli] val xKeys: XKeys = new XKeys:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = op {
      val kp = genPkey(PkeyX25519, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[X25519]] =
      opE(
        storePub(kufuli_pkey_from_raw_public(PkeyX25519, bytes.unsafePtr, bytes.length.toCSize), SpkiMax, DER.Alg.X)
          .map(b => PublicKey.unsafe(keyRepr(b)))
      )
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[X25519]] =
      opE(storePub(parsePub(der), SpkiMax, DER.Alg.X).map(b => PublicKey.unsafe(keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[X25519]] =
      opE(storePriv(parsePriv(der), Pkcs8Max, DER.Alg.X).map(PrivateKey.unsafe))
    private[kufuli] def raw(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h => IArray.from(collect(32)((o, l) => kufuli_pkey_raw_public(h, o, l, 32.toCSize))))
      )
    private[kufuli] def spki(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[X25519]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(exported)))

  private def ecKeysOf[C <: EcCurve](tpe: CInt, curve: DER.Alg, fieldLength: Int): EcKeys[C] = new EcKeys[C]:
    private val pointLength = 1 + 2 * fieldLength
    private[kufuli] def generate: UEff[KeyPair[PublicKey[C], PrivateKey[C]]] = op {
      val kp = genPkey(tpe, 0)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    private[kufuli] def fromSec1(point: Slice): Eff[Refused, PublicKey[C]] = opE {
      val h = kufuli_pkey_from_ec_point(tpe, point.unsafePtr, point.length.toCSize)
      if present(h) then storePub(h, SpkiMax, curve).map(b => PublicKey.unsafe(keyRepr(b))) else Left(Refused)
    }
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[C]] =
      opE(storePub(parsePub(der), SpkiMax, curve).map(b => PublicKey.unsafe(keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[C]] =
      opE(storePriv(parsePriv(der), Pkcs8Max, curve).map(PrivateKey.unsafe))
    private[kufuli] def sec1(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]] =
      op(
        withHandle(parsePub(Slice.of(keyBytes(key.repr))))(h =>
          IArray.from(collect(pointLength)((o, l) => kufuli_pkey_ec_point(h, o, l, pointLength.toCSize)))
        )
      )
    private[kufuli] def spki(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[C]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(exported)))

  private[kufuli] val rsaKeys: RsaKeys = new RsaKeys:
    private[kufuli] def generate(size: RSA.Size): UEff[KeyPair[PublicKey[RSA], PrivateKey[RSA]]] = blockingOp {
      val kp = genPkey(PkeyRsa, size.bits)
      KeyPair(PublicKey.unsafe(keyRepr(kp.pub)), PrivateKey.unsafe(kp.priv))
    }
    private[kufuli] def fromComponents(modulus: Slice, exponent: Slice): Eff[Refused, PublicKey[RSA]] = opE {
      storePub(kufuli_pkey_from_rsa_components(modulus.unsafePtr, modulus.length.toCSize, exponent.unsafePtr, exponent.length.toCSize),
               SpkiMax,
               DER.Alg.Rsa
      ).map(b => PublicKey.unsafe(keyRepr(b)))
    }
    private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[RSA]] =
      opE(storePub(parsePub(der), SpkiMax, DER.Alg.Rsa).map(b => PublicKey.unsafe(keyRepr(b))))
    private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[RSA]] =
      opE(storePriv(parsePriv(der), Pkcs8Max, DER.Alg.Rsa).map(PrivateKey.unsafe))
    private[kufuli] def components(key: PublicKey[RSA]): Eff[KeyNotExportable, RSA.Components] = op {
      val spki = keyBytes(key.repr)
      val capacity = spki.length
      withHandle(parsePub(Slice.of(spki))) { h =>
        val nBuf = new Array[Byte](capacity)
        val eBuf = new Array[Byte](capacity)
        val nLen = stackalloc[CSize]()
        val eLen = stackalloc[CSize]()
        require1(
          kufuli_pkey_rsa_components(h, Slice.of(nBuf).unsafePtr, nLen, capacity.toCSize, Slice.of(eBuf).unsafePtr, eLen, capacity.toCSize)
        )
        RSA.Components(IArray.from(nBuf.take((!nLen).toInt)), IArray.from(eBuf.take((!eLen).toInt)))
      }
    }
    private[kufuli] def spki(key: PublicKey[RSA]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def pkcs8(key: PrivateKey[RSA]): Eff[KeyNotExportable, IArray[Byte]] =
      Eff.defer(op(key.material(exported)))

  private def kemKeysOf[K <: KemAlgorithm](kem: CInt, spec: KemSpec[K], privLength: Int): KemKeys[K] = new KemKeys[K]:
    private[kufuli] def generate: UEff[KeyPair[PublicKey[K], PrivateKey[K]]] = op {
      val pubBuf = new Array[Byte](spec.publicKeyLength)
      val pubLen = stackalloc[CSize]()
      val priv = collect(privLength)((o, l) =>
        kufuli_kem_keypair(kem, Slice.of(pubBuf).unsafePtr, pubLen, spec.publicKeyLength.toCSize, o, l, privLength.toCSize)
      )
      KeyPair(PublicKey.unsafe(keyRepr(pubBuf.take((!pubLen).toInt))), PrivateKey.unsafe(priv))
    }
    private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[K]] = opE {
      // FIPS 203 section 7.2's encapsulation-key check: a peer key is adversarial input, so it
      // belongs in the typed channel at import rather than in a failure inside encapsulation.
      if kufuli_kem_public_valid(kem, bytes.unsafePtr, bytes.length.toCSize) != 1 then Left(Refused)
      else Right(PublicKey.unsafe(keyRepr(bytes.toArray)))
    }
    private[kufuli] def raw(key: PublicKey[K]): Eff[KeyNotExportable, IArray[Byte]] = op(IArray.from(keyBytes(key.repr)))
    private[kufuli] def fromSeed(seed: Slice): Eff[InvalidKey, KeyPair[PublicKey[K], PrivateKey[K]]] = opE {
      if seed.length != 64 then Left(InvalidKey.WrongLength(64, seed.length))
      else
        val pubBuf = new Array[Byte](spec.publicKeyLength)
        val pubLen = stackalloc[CSize]()
        val priv = collect(privLength)((o, l) =>
          kufuli_kem_keypair_from_seed(kem,
                                       seed.unsafePtr,
                                       seed.length.toCSize,
                                       Slice.of(pubBuf).unsafePtr,
                                       pubLen,
                                       spec.publicKeyLength.toCSize,
                                       o,
                                       l,
                                       privLength.toCSize
          )
        )
        Right(KeyPair(PublicKey.unsafe(keyRepr(pubBuf.take((!pubLen).toInt))), PrivateKey.unsafe(priv)))
    }

  // Capability bundles the Native platform table wires each companion into.
  private[kufuli] trait RandomDefault:
    given Random = random
  private[kufuli] trait AeadUniversal:
    given AEAD[AesGcm128] = aeadOf(AesGcm128, AeadAesGcm128)
    given AEAD[AesGcm192] = aeadOf(AesGcm192, AeadAesGcm192)
    given AEAD[AesGcm256] = aeadOf(AesGcm256, AeadAesGcm256)
    given AEAD[A128CbcHs256] = cbcHs(A128CbcHs256, MdSha256)
    given AEAD[A256CbcHs512] = cbcHs(A256CbcHs512, MdSha512)
  private[kufuli] trait AeadChaCha:
    given AEAD[ChaCha20Poly1305] = aeadOf(ChaCha20Poly1305, AeadChaCha)
  private[kufuli] trait AeadMisuseResistant:
    given AEAD[XChaCha20Poly1305] = aeadOf(XChaCha20Poly1305, AeadXChaCha)
    given AEAD[AesGcmSiv256] = aeadOf(AesGcmSiv256, AeadGcmSiv256)
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
    given MAC[HmacSha256] = macOf(MdSha256)
    given MAC[HmacSha384] = macOf(MdSha384)
    given MAC[HmacSha512] = macOf(MdSha512)
    given MAC[HmacSha1] = macOf(MdSha1)
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
    given Agreement[X25519] = agreementOf(32)
    given Agreement[P256] = agreementOf(32)
    given Agreement[P384] = agreementOf(48)
    given Agreement[P521] = agreementOf(66)
  private[kufuli] trait KemAll:
    given KEM[MlKem768] = kemOf(KemMlKem768, MlKem768)
    given KEM[MlKem1024] = kemOf(KemMlKem1024, MlKem1024)
  private[kufuli] trait WrapKw:
    given Wrap[AesKw128] = wrapOf(padded = false)
    given Wrap[AesKw256] = wrapOf(padded = false)
  private[kufuli] trait WrapKwp:
    given Wrap[AesKwp128] = wrapOf(padded = true)
    given Wrap[AesKwp256] = wrapOf(padded = true)
  private[kufuli] trait KdfDefault:
    given KDF = kdf
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
    given OAEP = oaep
  private[kufuli] trait EdKeysBytes:
    given EdKeys = edKeys
  private[kufuli] trait XKeysBytes:
    given XKeys = xKeys
  private[kufuli] trait EcKeysBytes:
    given EcKeys[P256] = ecKeysOf(PkeyP256, DER.Alg.EcP256, 32)
    given EcKeys[P384] = ecKeysOf(PkeyP384, DER.Alg.EcP384, 48)
    given EcKeys[P521] = ecKeysOf(PkeyP521, DER.Alg.EcP521, 66)
  private[kufuli] trait RsaKeysBytes:
    given RsaKeys = rsaKeys
  private[kufuli] trait KemKeysAll:
    given KemKeys[MlKem768] = kemKeysOf(KemMlKem768, MlKem768, 2400)
    given KemKeys[MlKem1024] = kemKeysOf(KemMlKem1024, MlKem1024, 3168)
end awslc
