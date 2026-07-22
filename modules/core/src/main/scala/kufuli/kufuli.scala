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
package kufuli

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

import scala.annotation.implicitNotFound
import scala.annotation.tailrec
import scala.annotation.targetName
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import cats.effect.IO
import cats.effect.Resource

// Data-dependent failures are values; programmer errors (nonce lengths, buffer arithmetic,
// nonsense limits) are DEFECTS via require; a misbehaving backend is a raised, sanitised
// `Unexpected` defect - never a wrong success, never secret-echoing.

sealed abstract class KufuliError(message: String) extends Exception(message) with NoStackTrace derives CanEqual

sealed abstract class AuthFailed private[kufuli] () extends KufuliError("authentication failed")
case object AuthFailed extends AuthFailed
sealed abstract class SignatureRejected private[kufuli] () extends KufuliError("signature rejected")
case object SignatureRejected extends SignatureRejected
sealed abstract class BudgetExhausted private[kufuli] () extends KufuliError("AEAD usage budget exhausted")
case object BudgetExhausted extends BudgetExhausted
sealed abstract class UnwrapFailed private[kufuli] () extends KufuliError("key unwrap failed")
case object UnwrapFailed extends UnwrapFailed
sealed abstract class NotWrappable private[kufuli] () extends KufuliError("key length not a multiple of 8: use an AES-KWP algorithm")
case object NotWrappable extends NotWrappable
sealed abstract class Malformed private[kufuli] () extends KufuliError("malformed encoding")
case object Malformed extends Malformed
sealed abstract class DuplicateKeyId private[kufuli] () extends KufuliError("keyring ids must be unique")
case object DuplicateKeyId extends DuplicateKeyId
sealed abstract class KeyNotExportable private[kufuli] () extends KufuliError("key material is not exportable on this backend")
case object KeyNotExportable extends KeyNotExportable

enum InvalidKey(message: String) extends KufuliError(message):
  case WrongLength(expected: Int, got: Int) extends InvalidKey(s"expected $expected bytes, got $got")
  case Malformed extends InvalidKey("malformed key encoding")
  case NotOnCurve extends InvalidKey("point not on curve")
  case WeakPoint extends InvalidKey("small-order or otherwise weak public point")
  case Unsupported extends InvalidKey("algorithm not supported here")

/** The FFI/backend-failure channel: a genuine backend anomaly is wrapped idempotently and RAISED as
  * a defect. The message is generic - the cause (which may echo key or plaintext material) never
  * reaches `getMessage`.
  */
final class Unexpected private (val cause: Throwable) extends KufuliError("unexpected backend failure")
object Unexpected:
  def apply(cause: Throwable): KufuliError = cause match
    case e: KufuliError => e
    case t              => new Unexpected(t)
  def unapply(u: Unexpected): Some[Throwable] = Some(u.cause)

/** Every backend (FFI) call routes through `guard`: a raw backend throwable becomes a raised
  * `Unexpected` - a crypto op can never return a wrong success because a backend glitched.
  */
private[kufuli] def guard[A](io: IO[A]): IO[A] =
  io.handleErrorWith(t => IO.raiseError(Unexpected(t)))

// The one place secret-byte zeroisation and liveness live; mutable backing is what makes `wipe`
// possible (best-effort on managed runtimes per `Slice.wipe`).
final private[kufuli] class Secret(bytes: Array[Byte]):
  private val live = new AtomicBoolean(true)

  // Use-after-destroy is a programmer error and raises.
  private[kufuli] def read[A](f: Slice => A): A =
    if !live.get then throw new IllegalStateException("secret already destroyed") // scalafix:ok DisableSyntax.throw
    f(Slice.of(bytes))
  private[kufuli] def wipe(): Unit =
    if live.compareAndSet(true, false) then Slice.of(bytes).wipe()

// The trait is the TYPE-level tag (`SecretKey[AesGcm256]`); the co-named object is the VALUE
// (metadata + generation). MAKE names the algorithm (`AesGcm256.generate`, `P256.generate`,
// `Sha256.hasher`); PARSE names the encoding (`PublicKey.fromSec1(P256)(...)`). P-curves genuinely
// serve both signing and agreement; Ed25519/X25519 stay structurally disjoint.

sealed trait Algorithm
sealed trait SymmetricAlgorithm extends Algorithm
sealed trait AeadAlgorithm extends SymmetricAlgorithm
sealed trait MacAlgorithm extends SymmetricAlgorithm
sealed trait WrapAlgorithm extends SymmetricAlgorithm
sealed trait SignatureAlgorithm extends Algorithm
sealed trait AgreementAlgorithm extends Algorithm
sealed trait KemAlgorithm extends Algorithm
sealed trait HashAlgorithm extends Algorithm
sealed trait EcCurve extends SignatureAlgorithm, AgreementAlgorithm

sealed abstract class SymmetricSpec[A <: SymmetricAlgorithm](val keyLength: Int):
  private[kufuli] def validate(n: Int): Either[InvalidKey, Unit] =
    if n == keyLength then Right(()) else Left(InvalidKey.WrongLength(keyLength, n))

  // Shared generation body (CSPRNG + wiped intermediate); the PUBLIC `generate` lives on each
  // spec subtype and demands the family's operational instance as evidence, so a key the backend
  // cannot operate is UNGENERATABLE - the error lands at the earliest possible point.
  final private[kufuli] def generateUnchecked(using r: Random): UEffIO[SecretKey[A]] =
    r.bytes(keyLength).map { s =>
      val b = s.toArray
      s.wipe()
      SecretKey.unsafe[A](b)
    }
end SymmetricSpec

sealed abstract class AeadSpec[A <: AeadAlgorithm](keyLength: Int, val nonceLength: Int, val tagLength: Int, val defaultLimits: AeadLimits)
    extends SymmetricSpec[A](keyLength):
  /** A fresh key from the backend CSPRNG; requires the algorithm to be OPERABLE here. */
  final def generate(using a: Aead[A], r: Random): UEffIO[SecretKey[A]] =
    val _ = a // operability evidence: an unusable key is ungeneratable
    generateUnchecked(using r)
object AeadSpec:
  given AeadSpec[AesGcm128] = AesGcm128
  given AeadSpec[AesGcm192] = AesGcm192
  given AeadSpec[AesGcm256] = AesGcm256
  given AeadSpec[ChaCha20Poly1305] = ChaCha20Poly1305
  given AeadSpec[XChaCha20Poly1305] = XChaCha20Poly1305
  given AeadSpec[AesGcmSiv256] = AesGcmSiv256
  given AeadSpec[A128CbcHs256] = A128CbcHs256
  given AeadSpec[A256CbcHs512] = A256CbcHs512

// HMAC accepts variable-length keys; the outLength..128 window is the RFC 2104 floor + JOSE cap.
sealed abstract class MacSpec[H <: MacAlgorithm](val outLength: Int) extends SymmetricSpec[H](outLength):
  override private[kufuli] def validate(n: Int): Either[InvalidKey, Unit] =
    if n >= outLength && n <= 128 then Right(()) else Left(InvalidKey.WrongLength(outLength, n))

  /** A fresh key from the backend CSPRNG; requires the algorithm to be OPERABLE here. */
  final def generate(using m: Mac[H], r: Random): UEffIO[SecretKey[H]] =
    val _ = m // operability evidence: an unusable key is ungeneratable
    generateUnchecked(using r)

sealed abstract class WrapSpec[W <: WrapAlgorithm](keyLength: Int, val padded: Boolean) extends SymmetricSpec[W](keyLength):
  /** A fresh key-encryption key from the backend CSPRNG; requires the algorithm to be OPERABLE
    * here.
    */
  final def generate(using w: Wrap[W], r: Random): UEffIO[SecretKey[W]] =
    val _ = w // operability evidence: an unusable key is ungeneratable
    generateUnchecked(using r)
object WrapSpec:
  given WrapSpec[AesKw128] = AesKw128
  given WrapSpec[AesKw256] = AesKw256
  given WrapSpec[AesKwp128] = AesKwp128
  given WrapSpec[AesKwp256] = AesKwp256

sealed abstract class EcSpec[C <: EcCurve](val fieldLength: Int, val hash: Sha2):
  /** Generate a fresh keypair on this curve. */
  final def generate(using k: EcKeys[C]): UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]] = k.generate
object EcSpec:
  given EcSpec[P256] = P256
  given EcSpec[P384] = P384
  given EcSpec[P521] = P521

sealed abstract class HashSpec[D <: HashAlgorithm](val length: Int):
  /** One-shot digest - `Sha256.digest(data)`. Universal (async-capable on every backend). */
  final def digest(data: Slice)(using h: Hash[D]): UEffIO[Digest] = h.digest(data)

  /** A Resource-scoped incremental hasher - `Sha256.hasher`. Synchronous; its absence on the
    * async-only browser backend is the compile fact (no `Hashing` instance there).
    */
  final def hasher(using h: Hashing[D]): Resource[IO, Hasher] = h.hasher

sealed abstract class KemSpec[K <: KemAlgorithm](val publicKeyLength: Int, val ciphertextLength: Int):
  final def generate(using k: KemKeys[K]): UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]] = k.generate

sealed trait AesGcm128 extends AeadAlgorithm
case object AesGcm128 extends AeadSpec[AesGcm128](16, 12, 16, AeadLimits.default) with AesGcm128
sealed trait AesGcm192 extends AeadAlgorithm
case object AesGcm192 extends AeadSpec[AesGcm192](24, 12, 16, AeadLimits.default) with AesGcm192
sealed trait AesGcm256 extends AeadAlgorithm
case object AesGcm256 extends AeadSpec[AesGcm256](32, 12, 16, AeadLimits.default) with AesGcm256
sealed trait ChaCha20Poly1305 extends AeadAlgorithm
case object ChaCha20Poly1305 extends AeadSpec[ChaCha20Poly1305](32, 12, 16, AeadLimits.chaCha) with ChaCha20Poly1305
// Misuse-resistant tier (capability-gated): XChaCha's 192-bit nonce makes random-nonce sealing
// safe at any realistic volume; GCM-SIV survives nonce repetition outright. Prefer these for
// `seal` at volume where present; rotation + GCM's documented 2^32 bound elsewhere.
sealed trait XChaCha20Poly1305 extends AeadAlgorithm
case object XChaCha20Poly1305 extends AeadSpec[XChaCha20Poly1305](32, 24, 16, AeadLimits.chaCha) with XChaCha20Poly1305
sealed trait AesGcmSiv256 extends AeadAlgorithm
case object AesGcmSiv256 extends AeadSpec[AesGcmSiv256](32, 12, 16, AeadLimits.default) with AesGcmSiv256
// JOSE composite AEADs (RFC 7518 section 5.2 names): key is MAC||ENC, tag is truncated HMAC.
sealed trait A128CbcHs256 extends AeadAlgorithm
case object A128CbcHs256 extends AeadSpec[A128CbcHs256](32, 16, 16, AeadLimits.default) with A128CbcHs256
sealed trait A256CbcHs512 extends AeadAlgorithm
case object A256CbcHs512 extends AeadSpec[A256CbcHs512](64, 16, 32, AeadLimits.default) with A256CbcHs512

sealed trait HmacSha256 extends MacAlgorithm
case object HmacSha256 extends MacSpec[HmacSha256](32) with HmacSha256
sealed trait HmacSha384 extends MacAlgorithm
case object HmacSha384 extends MacSpec[HmacSha384](48) with HmacSha384
sealed trait HmacSha512 extends MacAlgorithm
case object HmacSha512 extends MacSpec[HmacSha512](64) with HmacSha512

sealed trait AesKw128 extends WrapAlgorithm
case object AesKw128 extends WrapSpec[AesKw128](16, padded = false) with AesKw128
sealed trait AesKw256 extends WrapAlgorithm
case object AesKw256 extends WrapSpec[AesKw256](32, padded = false) with AesKw256
sealed trait AesKwp128 extends WrapAlgorithm
case object AesKwp128 extends WrapSpec[AesKwp128](16, padded = true) with AesKwp128
sealed trait AesKwp256 extends WrapAlgorithm
case object AesKwp256 extends WrapSpec[AesKwp256](32, padded = true) with AesKwp256

sealed trait P256 extends EcCurve
case object P256 extends EcSpec[P256](32, Sha256) with P256
sealed trait P384 extends EcCurve
case object P384 extends EcSpec[P384](48, Sha384) with P384
sealed trait P521 extends EcCurve
case object P521 extends EcSpec[P521](66, Sha512) with P521

sealed trait Ed25519 extends SignatureAlgorithm
case object Ed25519 extends Ed25519:
  def generate(using k: EdKeys): UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = k.generate
sealed trait X25519 extends AgreementAlgorithm
case object X25519 extends X25519:
  def generate(using k: XKeys): UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = k.generate

sealed trait Rsa extends SignatureAlgorithm

/** RSA parameters: [[Rsa.bits]] validates a modulus size (nonsense sizes are programmer error);
  * [[Rsa.Components]] carries the public modulus and exponent (the JWK `n`/`e` pair).
  */
object Rsa:
  final class Size private[Rsa] (val bits: Int)
  def bits(n: Int): Size =
    require(n >= 2048 && n % 8 == 0, s"RSA modulus must be >= 2048 and a multiple of 8, got $n")
    new Size(n)
  final case class Components(modulus: IArray[Byte], exponent: IArray[Byte])
  def generate(size: Size)(using k: RsaKeys): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]] = k.generate(size)
  def fromPkcs8(der: Slice)(using k: RsaKeys): EffIO[InvalidKey, PrivateKey[Rsa]] = k.fromPkcs8(der)

sealed trait MlKem768 extends KemAlgorithm
case object MlKem768 extends KemSpec[MlKem768](1184, 1088) with MlKem768
sealed trait MlKem1024 extends KemAlgorithm
case object MlKem1024 extends KemSpec[MlKem1024](1568, 1568) with MlKem1024

sealed trait Sha1 extends HashAlgorithm
case object Sha1 extends HashSpec[Sha1](20) with Sha1 // one-shot digests only (e.g. the JOSE x5t thumbprint)
sealed trait Sha256 extends HashAlgorithm
case object Sha256 extends HashSpec[Sha256](32) with Sha256
sealed trait Sha384 extends HashAlgorithm
case object Sha384 extends HashSpec[Sha384](48) with Sha384
sealed trait Sha512 extends HashAlgorithm
case object Sha512 extends HashSpec[Sha512](64) with Sha512

/** The SHA-2 hashes admissible in signatures and KDFs. Sha1 is excluded by construction - weak-hash
  * use is a type error (Sha1 exists for thumbprint-class digests only). Named for what it governs:
  * signatures AND key derivation.
  */
type Sha2 = Sha256.type | Sha384.type | Sha512.type

/** The computation a signature performs over key algorithm `A`. Extensions default it - EdDSA is
  * parameterless, ECDSA defaults to the curve-paired hash - so a scheme value is written only where
  * the choice is real: RSA padding (no safe default exists), and cross-paired legacy X.509.
  */
sealed trait Scheme[A <: SignatureAlgorithm]
object Scheme:
  given [A <: SignatureAlgorithm]: CanEqual[Scheme[A], Scheme[A]] = CanEqual.derived
case object EdDsa extends Scheme[Ed25519]
final case class Ecdsa[C <: EcCurve](hash: Sha2) extends Scheme[C]
final case class RsaPss(hash: Sha2) extends Scheme[Rsa]
final case class RsaPkcs1(hash: Sha2) extends Scheme[Rsa] // certificates, JOSE RS256

/** RSA-OAEP parameters. */
final case class RsaOaep(hash: Sha2) derives CanEqual

// Public keys are opaque over the PLATFORM-DEFINED KeyRepr (per-unit source sets; the browser
// holds live CryptoKey handles) - shared code never sees the representation, which is why export
// is uniformly effectful and typed-failable. Secret material is opaque over the wipeable carrier.
// All tags INVARIANT: a key of one algorithm cannot be used with another.

final case class KeyPair[+Pub, +Priv](publicKey: Pub, privateKey: Priv)

opaque type PublicKey[A <: Algorithm] = KeyRepr
object PublicKey:
  private[kufuli] def unsafe[A <: Algorithm](r: KeyRepr): PublicKey[A] = r
  extension [A <: Algorithm](k: PublicKey[A]) private[kufuli] def repr: KeyRepr = k

  // PARSE names the encoding. Imports are effectful and typed: real validation (on-curve,
  // small-order, full-encoding) is backend work - and what makes `agree` TOTAL.
  def fromRaw(alg: Ed25519)(bytes: Slice)(using k: EdKeys): EffIO[InvalidKey, PublicKey[Ed25519]] =
    val _ = alg
    k.fromRaw(bytes)
  @targetName("fromRawX")
  def fromRaw(alg: X25519)(bytes: Slice)(using k: XKeys): EffIO[InvalidKey, PublicKey[X25519]] =
    val _ = alg
    k.fromRaw(bytes)

  /** ML-KEM encapsulation key from the wire (the hybrid KeyShare carries it verbatim). */
  @targetName("fromRawKem")
  def fromRaw[K <: KemAlgorithm](alg: KemSpec[K])(bytes: Slice)(using k: KemKeys[K]): EffIO[InvalidKey, PublicKey[K]] =
    val _ = alg
    k.fromRaw(bytes)

  /** SEC1 point (uncompressed or compressed) - the TLS KeyShare wire form. */
  def fromSec1[C <: EcCurve](curve: EcSpec[C])(point: Slice)(using k: EcKeys[C]): EffIO[InvalidKey, PublicKey[C]] =
    val _ = curve
    k.fromSec1(point)

  /** RSA public key from its JWK components. */
  def fromComponents(modulus: Slice, exponent: Slice)(using k: RsaKeys): EffIO[InvalidKey, PublicKey[Rsa]] =
    k.fromComponents(modulus, exponent)

  /** SPKI of UNKNOWN algorithm: the shared bounded DER peek dispatches the WHOLE blob to the right
    * family; the caller matches the enum and the bound type flows into every later op.
    */
  def fromSpki(der: Slice)(using
    ed: EdKeys,
    x: XKeys,
    p256: EcKeys[P256],
    p384: EcKeys[P384],
    p521: EcKeys[P521],
    rsa: RsaKeys
  ): EffIO[InvalidKey, ImportedPublicKey] =
    EffIO.from(Der.peekSpki(der)).flatMap {
      case Der.Alg.Ed     => ed.fromSpki(der).map(ImportedPublicKey.Ed(_))
      case Der.Alg.X      => x.fromSpki(der).map(ImportedPublicKey.X(_))
      case Der.Alg.EcP256 => p256.fromSpki(der).map(ImportedPublicKey.EcP256(_))
      case Der.Alg.EcP384 => p384.fromSpki(der).map(ImportedPublicKey.EcP384(_))
      case Der.Alg.EcP521 => p521.fromSpki(der).map(ImportedPublicKey.EcP521(_))
      case Der.Alg.OfRsa  => rsa.fromSpki(der).map(ImportedPublicKey.OfRsa(_))
    }
end PublicKey

opaque type PrivateKey[A <: Algorithm] = Secret
object PrivateKey:
  private[kufuli] def unsafe[A <: Algorithm](bytes: Array[Byte]): PrivateKey[A] = new Secret(bytes)
  extension [A <: Algorithm](k: PrivateKey[A])
    private[kufuli] def read[B](f: Slice => B): B = k.read(f)

    /** Erase the key material in place; further use raises. Best-effort on managed runtimes. */
    def destroy: UEffIO[Unit] = EffIO.suspend(k.wipe())

  def fromPkcs8(alg: Ed25519)(der: Slice)(using k: EdKeys): EffIO[InvalidKey, PrivateKey[Ed25519]] =
    val _ = alg
    k.fromPkcs8(der)
  @targetName("fromPkcs8X")
  def fromPkcs8(alg: X25519)(der: Slice)(using k: XKeys): EffIO[InvalidKey, PrivateKey[X25519]] =
    val _ = alg
    k.fromPkcs8(der)
  @targetName("fromPkcs8Ec")
  def fromPkcs8[C <: EcCurve](curve: EcSpec[C])(der: Slice)(using k: EcKeys[C]): EffIO[InvalidKey, PrivateKey[C]] =
    val _ = curve
    k.fromPkcs8(der)

  /** PKCS#8 of UNKNOWN algorithm (server key loading); enum dispatch as for SPKI. */
  def fromPkcs8(der: Slice)(using
    ed: EdKeys,
    x: XKeys,
    p256: EcKeys[P256],
    p384: EcKeys[P384],
    p521: EcKeys[P521],
    rsa: RsaKeys
  ): EffIO[InvalidKey, ImportedPrivateKey] =
    EffIO.from(Der.peekPkcs8(der)).flatMap {
      case Der.Alg.Ed     => ed.fromPkcs8(der).map(ImportedPrivateKey.Ed(_))
      case Der.Alg.X      => x.fromPkcs8(der).map(ImportedPrivateKey.X(_))
      case Der.Alg.EcP256 => p256.fromPkcs8(der).map(ImportedPrivateKey.EcP256(_))
      case Der.Alg.EcP384 => p384.fromPkcs8(der).map(ImportedPrivateKey.EcP384(_))
      case Der.Alg.EcP521 => p521.fromPkcs8(der).map(ImportedPrivateKey.EcP521(_))
      case Der.Alg.OfRsa  => rsa.fromPkcs8(der).map(ImportedPrivateKey.OfRsa(_))
    }
end PrivateKey

opaque type SecretKey[A <: Algorithm] = Secret
object SecretKey:
  private[kufuli] def unsafe[A <: Algorithm](bytes: Array[Byte]): SecretKey[A] = new Secret(bytes)

  /** Import raw key material: length-validated, pure (no backend), defensive copy into the wipeable
    * carrier.
    */
  def of[A <: SymmetricAlgorithm](spec: SymmetricSpec[A])(bytes: Array[Byte]): Either[InvalidKey, SecretKey[A]] =
    spec.validate(bytes.length).map(_ => unsafe(bytes.clone))
  extension [A <: Algorithm](k: SecretKey[A])
    private[kufuli] def read[B](f: Slice => B): B = k.read(f)
    @targetName("destroySecretKey")
    def destroy: UEffIO[Unit] = EffIO.suspend(k.wipe())
end SecretKey

// Inspect-form import results - flat arms, one per family/curve. There is deliberately NO Kem
// arm: ML-KEM keys travel raw in v1 wire protocols, and excluding them keeps `fromSpki`/
// `fromPkcs8` available on every platform (a Kem arm would demand KemKeys instances the browser
// cannot provide). Revisit trigger: ML-KEM certificate/SPKI interop.
enum ImportedPublicKey:
  case Ed(key: PublicKey[Ed25519])
  case X(key: PublicKey[X25519])
  case EcP256(key: PublicKey[P256])
  case EcP384(key: PublicKey[P384])
  case EcP521(key: PublicKey[P521])
  case OfRsa(key: PublicKey[Rsa])
enum ImportedPrivateKey:
  case Ed(key: PrivateKey[Ed25519])
  case X(key: PrivateKey[X25519])
  case EcP256(key: PrivateKey[P256])
  case EcP384(key: PrivateKey[P384])
  case EcP521(key: PrivateKey[P521])
  case OfRsa(key: PrivateKey[Rsa])

/** A nonce for AEAD algorithm `A`. [[Nonce.random]] is the ONLY public constructor - hand-rolled
  * nonces are the classic misuse and are unrepresentable. Random nonces are safe by construction
  * for large-nonce algorithms (prefer XChaCha at volume); GCM's random-nonce bound is the
  * documented 2^32 with rotation as the answer. The record tier does not use this type at all: it
  * derives raw per-record nonces with [[Nonce.xorInto]].
  */
opaque type Nonce[A <: AeadAlgorithm] = Array[Byte]
object Nonce:
  private[kufuli] def unsafe[A <: AeadAlgorithm](b: Array[Byte]): Nonce[A] = b
  extension [A <: AeadAlgorithm](n: Nonce[A]) private[kufuli] def repr: Array[Byte] = n

  /** A fresh random nonce for one seal. */
  def random[A <: AeadAlgorithm](spec: AeadSpec[A])(using r: Random): UEffIO[Nonce[A]] =
    r.bytes(spec.nonceLength).map(s => unsafe(s.toArray))

  /** RFC 8446 section 5.3 per-record nonce derivation: the static IV XORed with the big-endian
    * record sequence number in its low-order bytes, written to `dst`'s start (`iv.length` bytes).
    * Owned here so the byte layout is KAT-verified once; the record tier consumes raw slices.
    */
  def xorInto(iv: Slice, sequence: Long, dst: Slice): Unit =
    require(iv.length >= 8 && dst.length >= iv.length, "xorInto bounds")
    val _ = iv.copyInto(dst)
    @tailrec def go(i: Int): Unit =
      if i < 8 then
        val j = iv.length - 1 - i
        dst(j) = (dst(j) ^ ((sequence >>> (8 * i)) & 0xff).toByte).toByte
        go(i + 1)
    go(0)
end Nonce

/** Immutable digest bytes; construct via a backend digest or parse foreign bytes with `of`. */
opaque type Digest = Array[Byte]
object Digest:
  private[kufuli] def unsafe(bytes: Array[Byte]): Digest = bytes
  def of(bytes: Array[Byte]): Either[Malformed, Digest] =
    if Set(20, 28, 32, 48, 64).contains(bytes.length) then Right(bytes.clone) else Left(Malformed)
  extension (d: Digest)
    def bytes: IArray[Byte] = IArray.from(d: Array[Byte])
    def hex: String = (d: Array[Byte]).map(b => f"$b%02x").mkString

    /** Constant-time over equal lengths (a length mismatch is not itself secret). */
    def constantTimeEquals(o: Digest): Boolean = Slice.of(d).constantTimeEquals(Slice.of(o))

/** A signature (or MAC tag) over algorithm `A`: 64 raw bytes for Ed25519, fixed-width `r || s` for
  * ECDSA (the JOSE-native form), the signature octets for RSA, the tag for HMAC. Parse wire bytes
  * via `fromRaw`; DER interop via `fromDer`/`der`.
  */
opaque type Signature[A <: Algorithm] = Array[Byte]
object Signature:
  private[kufuli] def unsafe[A <: Algorithm](bytes: Array[Byte]): Signature[A] = bytes
  def fromRaw(alg: Ed25519)(bytes: Array[Byte]): Either[Malformed, Signature[Ed25519]] =
    val _ = alg
    if bytes.length == 64 then Right(bytes.clone) else Left(Malformed)
  @targetName("fromRawEc")
  def fromRaw[C <: EcCurve](curve: EcSpec[C])(bytes: Array[Byte]): Either[Malformed, Signature[C]] =
    if bytes.length == 2 * curve.fieldLength then Right(bytes.clone) else Left(Malformed)
  @targetName("fromRawMac")
  def fromRaw[H <: MacAlgorithm](alg: MacSpec[H])(bytes: Array[Byte]): Either[Malformed, Signature[H]] =
    if bytes.length == alg.outLength then Right(bytes.clone) else Left(Malformed)

  /** RSA signature octets (length is validated against the modulus at verify, by the backend). */
  @targetName("fromRawRsa")
  def fromRaw(alg: Rsa.type)(bytes: Array[Byte]): Either[Malformed, Signature[Rsa]] =
    val _ = alg
    if bytes.nonEmpty then Right(bytes.clone) else Left(Malformed)

  /** DER <-> raw conversion for the ECDSA wire forms (TLS/X.509 carry the DER
    * `SEQUENCE { INTEGER r, INTEGER s }`; JOSE and this library carry fixed-width `r || s`). Pure,
    * bounded, and strict: a trailing byte, an out-of-range integer, or a non-minimal length is
    * [[Malformed]].
    */
  def fromDer[C <: EcCurve](curve: EcSpec[C])(der: Array[Byte]): Either[Malformed, Signature[C]] =
    ecdsaDerToRaw(Slice.of(der), curve.fieldLength).map(unsafe[C]).left.map(_ => Malformed)

  private[kufuli] def ecdsaDerToRaw(der: Slice, fieldLength: Int): Either[InvalidKey, Array[Byte]] =
    for
      seq <- Der.read(der, 0, 0x30)
      r <- Der.read(der, seq.contentOff, 0x02)
      s <- Der.read(der, r.next, 0x02)
      _ <- if s.next == seq.next then Right(()) else Left(InvalidKey.Malformed)
      rb <- ecdsaField(der, r, fieldLength)
      sb <- ecdsaField(der, s, fieldLength)
    yield rb ++ sb

  // One DER INTEGER (r or s) to a fixed-width big-endian field: drop the sign byte / leading zeros,
  // reject an over-length or negative value, left-pad to `fieldLength`.
  private def ecdsaField(der: Slice, tlv: Der.Tlv, fieldLength: Int): Either[InvalidKey, Array[Byte]] =
    val raw = der.slice(tlv.contentOff, tlv.next).toArray
    if raw.isEmpty || (raw(0) & 0x80) != 0 then Left(InvalidKey.Malformed)
    else
      @tailrec def firstNonZero(i: Int): Int = if i < raw.length - 1 && (raw(i) & 0xff) == 0 then firstNonZero(i + 1) else i
      val i = firstNonZero(0)
      val magLen = raw.length - i
      if magLen > fieldLength then Left(InvalidKey.Malformed)
      else
        val out = new Array[Byte](fieldLength)
        Array.copy(raw, i, out, fieldLength - magLen, magLen)
        Right(out)
  end ecdsaField

  // Fixed-width big-endian `r || s` to `SEQUENCE { INTEGER r, INTEGER s }` with minimal integers.
  private[kufuli] def ecdsaRawToDer(raw: Array[Byte]): Array[Byte] =
    val fieldLength = raw.length / 2
    Der.sequence(minimalInteger(raw, 0, fieldLength), minimalInteger(raw, fieldLength, fieldLength))

  private def minimalInteger(raw: Array[Byte], off: Int, length: Int): Array[Byte] =
    @tailrec def firstNonZero(i: Int): Int = if i < length - 1 && (raw(off + i) & 0xff) == 0 then firstNonZero(i + 1) else i
    val i = firstNonZero(0)
    val magLen = length - i
    val body =
      if (raw(off + i) & 0x80) != 0 then
        val b = new Array[Byte](magLen + 1)
        Array.copy(raw, off + i, b, 1, magLen)
        b
      else raw.slice(off + i, off + length)
    Der.tlv(0x02, body)

  /** A resource-scoped handle for signing many messages under one prepared key. */
  trait Signer[A <: Algorithm]:
    def sign(data: Slice): UEffIO[Signature[A]]

  /** A resource-scoped handle for verifying many messages under one prepared key. */
  trait Verifier[A <: Algorithm]:
    def verify(data: Slice, sig: Signature[A]): EffIO[SignatureRejected, Unit]

  extension [A <: Algorithm](sig: Signature[A])
    private[kufuli] def repr: Array[Byte] = sig

    /** The signature octets, copied out. */
    def bytes: IArray[Byte] = IArray.from(sig: Array[Byte])
  extension [C <: EcCurve](sig: Signature[C])
    /** The DER form of an ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }` with minimal
      * integers (TLS/X.509 wire form).
      */
    def der: IArray[Byte] = IArray.from(ecdsaRawToDer(sig: Array[Byte]))
end Signature

/** A KEM ciphertext of scheme `K`; length is validated at construction, which makes `decapsulate`
  * total (FIPS 203 implicit rejection: a forged ciphertext yields a pseudorandom secret, no error).
  */
opaque type KemCiphertext[K <: KemAlgorithm] = Array[Byte]
object KemCiphertext:
  private[kufuli] def unsafe[K <: KemAlgorithm](bytes: Array[Byte]): KemCiphertext[K] = bytes
  def of[K <: KemAlgorithm](spec: KemSpec[K])(bytes: Array[Byte]): Either[Malformed, KemCiphertext[K]] =
    if bytes.length == spec.ciphertextLength then Right(bytes.clone) else Left(Malformed)
  extension [K <: KemAlgorithm](ct: KemCiphertext[K])
    private[kufuli] def repr: Array[Byte] = ct
    def bytes: IArray[Byte] = IArray.from(ct: Array[Byte])

final case class Encapsulated[K <: KemAlgorithm](secret: SharedSecret, ciphertext: KemCiphertext[K])

/** A self-describing sealed ciphertext, versioned for forward stability: `0x01` is
  * `nonce || ct || tag`; `0x02` is `keyId(4, big-endian) || nonce || ct || tag` (keyring-sealed).
  * The whole header is bound into the AEAD's associated data, so version or id tampering fails
  * authentication DIRECTLY. Parse stored bytes via `of`; `open` cannot be handed a box sealed under
  * another algorithm (invariant tag).
  */
opaque type SealedBox[A <: AeadAlgorithm] = Array[Byte]
object SealedBox:
  private[kufuli] def unsafe[A <: AeadAlgorithm](bytes: Array[Byte]): SealedBox[A] = bytes
  def of[A <: AeadAlgorithm](spec: AeadSpec[A])(bytes: Array[Byte]): Either[Malformed, SealedBox[A]] =
    val min = 1 + spec.nonceLength + spec.tagLength
    if bytes.length >= min && bytes(0) == 1.toByte then Right(bytes.clone)
    else if bytes.length >= min + 4 && bytes(0) == 2.toByte then Right(bytes.clone)
    else Left(Malformed)
  extension [A <: AeadAlgorithm](box: SealedBox[A])
    private[kufuli] def repr: Array[Byte] = box

    /** The stored form, copied out. */
    def bytes: IArray[Byte] = IArray.from(box: Array[Byte])
end SealedBox

/** A shared secret from key agreement or KEM decapsulation. Never exposed raw: `use` borrows a copy
  * that is wiped when `f` returns (copy out via `toArray` only deliberately - the caller then owns,
  * and should wipe, that copy); `destroy` erases the secret itself.
  */
opaque type SharedSecret = Secret
object SharedSecret:
  private[kufuli] def unsafe(bytes: Array[Byte]): SharedSecret = new Secret(bytes)
  extension (z: SharedSecret)
    private[kufuli] def read[A](f: Slice => A): A = z.read(f)
    def use[A](f: Slice => A): UEffIO[A] = EffIO.suspend {
      z.read { s =>
        val copy = s.toArray
        try f(Slice.of(copy))
        finally Slice.of(copy).wipe()
      }
    }
    def destroy: UEffIO[Unit] = EffIO.suspend(z.wipe())

    /** One-shot extract-then-expand to a key of algorithm `A` - the common non-TLS derivation. The
      * intermediate PRK is destroyed before the key is returned.
      */
    def deriveKey[A <: SymmetricAlgorithm](hash: Sha2, salt: Slice, info: Slice, as: SymmetricSpec[A])(using
      Kdf
    ): UEffIO[SecretKey[A]] =
      HKDF.extractFrom(hash, salt, z).flatMap(prk => HKDF.expandKey(hash, prk, info, as).flatMap(k => prk.destroy.map(_ => k)))
  end extension
end SharedSecret

/** An HKDF pseudo-random key; wipeable and scoped like [[SharedSecret]]. */
opaque type Prk = Secret
object Prk:
  private[kufuli] def unsafe(bytes: Array[Byte]): Prk = new Secret(bytes)
  extension (p: Prk)
    private[kufuli] def read[A](f: Slice => A): A = p.read(f)
    @targetName("usePrk")
    def use[A](f: Slice => A): UEffIO[A] = EffIO.suspend {
      p.read { s =>
        val copy = s.toArray
        try f(Slice.of(copy))
        finally Slice.of(copy).wipe()
      }
    }
    @targetName("destroyPrk")
    def destroy: UEffIO[Unit] = EffIO.suspend(p.wipe())
  end extension
end Prk

// One typeclass per family. Instances live in the per-unit platform trait each companion extends
// (implicit scope, zero imports); instance PRESENCE is the backend's capability truth, and the
// @implicitNotFound message names it.

/** The backend CSPRNG. */
@implicitNotFound("this kufuli backend provides no CSPRNG (report this artifact pairing as a bug)")
trait Random:
  def bytes(n: Int): UEffIO[Slice]
  def fill(dst: Slice): UEffIO[Unit]
object Random extends RandomPlatform:
  /** Fresh CSPRNG bytes (PKCE verifiers, salts, ids). */
  def bytes(n: Int)(using r: Random): UEffIO[Slice] = r.bytes(n)

  /** Zero-allocation fill of a caller buffer. */
  def fill(dst: Slice)(using r: Random): UEffIO[Unit] = r.fill(dst)

@implicitNotFound("${A} is not provided by this kufuli backend (XChaCha and GCM-SIV are Native-only; the browser lacks ChaCha)")
trait Aead[A <: AeadAlgorithm]:
  def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEffIO[Slice]
  def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): EffIO[AuthFailed, Slice]
object Aead extends AeadPlatform

/** Whole-message AEAD over the key: the protocol-shaped tier (PASETO-class constructions own their
  * wire layout, so the versioned [[SealedBox]] does not fit them). The nonce can only be
  * [[Nonce.random]]; the zero-copy, budget-tracked record path is the [[Cipher]] handle.
  */
extension [A <: AeadAlgorithm](key: SecretKey[A])
  def seal(nonce: Nonce[A], aad: Slice, plaintext: Slice)(using a: Aead[A]): UEffIO[Slice] =
    a.seal(key, nonce, aad, plaintext)
  def open(nonce: Nonce[A], aad: Slice, ciphertext: Slice)(using a: Aead[A]): EffIO[AuthFailed, Slice] =
    a.open(key, nonce, aad, ciphertext)

@implicitNotFound("HMAC ${H} is not provided by this kufuli backend")
trait Mac[H <: MacAlgorithm]:
  /** Compute the tag. Verification is SHARED code (recompute + the one audited constant-time
    * compare) - never a backend op, so no backend can get the no-oracle rule wrong.
    */
  def sign(key: SecretKey[H], data: Slice): UEffIO[Signature[H]]

  /** A prepared-key handle; the default wraps [[sign]] at zero cost - a backend overrides it where
    * key preparation is genuinely expensive (JCA key objects, WebCrypto imports).
    */
  def prepared(key: SecretKey[H]): Resource[IO, Signature.Signer[H]] =
    Resource.pure(
      new Signature.Signer[H]:
        def sign(data: Slice): UEffIO[Signature[H]] = Mac.this.sign(key, data)
    )
end Mac
object Mac extends MacPlatform

// The ONE audited constant-time comparison site, shared by every MAC-verify surface (key, ring,
// and prepared handles). (Signature is transparently Array[Byte] in this file.)
private def ctCheck[A <: Algorithm](computed: Signature[A], sig: Signature[A]): EffIO[SignatureRejected, Unit] =
  EffIO.raiseUnless(Slice.of(computed).constantTimeEquals(Slice.of(sig)))(SignatureRejected)

private def macVerify[H <: MacAlgorithm](m: Mac[H], key: SecretKey[H], data: Slice, sig: Signature[H]): EffIO[SignatureRejected, Unit] =
  m.sign(key, data).flatMap(ctCheck(_, sig))

extension [H <: MacAlgorithm](key: SecretKey[H])
  @targetName("macSign")
  def sign(data: Slice)(using m: Mac[H]): UEffIO[Signature[H]] = m.sign(key, data)

  /** Constant-time verification through the shared compare site. */
  @targetName("macVerifyOp")
  def verify(data: Slice, sig: Signature[H])(using m: Mac[H]): EffIO[SignatureRejected, Unit] =
    macVerify(m, key, data, sig)
  @targetName("macSigner")
  def signer(using m: Mac[H]): Resource[IO, Signature.Signer[H]] = m.prepared(key)
  @targetName("macVerifier")
  def verifier(using m: Mac[H]): Resource[IO, Signature.Verifier[H]] =
    m.prepared(key).map { s =>
      new Signature.Verifier[H]:
        def verify(data: Slice, sig: Signature[H]): EffIO[SignatureRejected, Unit] =
          s.sign(data).flatMap(ctCheck(_, sig))
    }
end extension

@implicitNotFound("signing for ${A} is not provided by this kufuli backend")
trait Signer[A <: SignatureAlgorithm]:
  def sign(key: PrivateKey[A], data: Slice, scheme: Scheme[A]): UEffIO[Signature[A]]
  def prepared(key: PrivateKey[A], scheme: Scheme[A]): Resource[IO, Signature.Signer[A]] =
    Resource.pure(
      new Signature.Signer[A]:
        def sign(data: Slice): UEffIO[Signature[A]] = Signer.this.sign(key, data, scheme)
    )
object Signer extends SignerPlatform

@implicitNotFound("signature verification for ${A} is not provided by this kufuli backend")
trait Verifier[A <: SignatureAlgorithm]:
  def verify(key: PublicKey[A], data: Slice, sig: Signature[A], scheme: Scheme[A]): EffIO[SignatureRejected, Unit]
  def prepared(key: PublicKey[A], scheme: Scheme[A]): Resource[IO, Signature.Verifier[A]] =
    Resource.pure(
      new Signature.Verifier[A]:
        def verify(data: Slice, sig: Signature[A]): EffIO[SignatureRejected, Unit] =
          Verifier.this.verify(key, data, sig, scheme)
    )
object Verifier extends VerifierPlatform

extension (k: PrivateKey[Ed25519])
  @targetName("edSign")
  def sign(data: Slice)(using s: Signer[Ed25519]): UEffIO[Signature[Ed25519]] = s.sign(k, data, EdDsa)
  @targetName("edSigner")
  def signer(using s: Signer[Ed25519]): Resource[IO, Signature.Signer[Ed25519]] = s.prepared(k, EdDsa)
extension (k: PublicKey[Ed25519])
  @targetName("edVerify")
  def verify(data: Slice, sig: Signature[Ed25519])(using v: Verifier[Ed25519]): EffIO[SignatureRejected, Unit] =
    v.verify(k, data, sig, EdDsa)
  @targetName("edVerifier")
  def verifier(using v: Verifier[Ed25519]): Resource[IO, Signature.Verifier[Ed25519]] = v.prepared(k, EdDsa)

extension [C <: EcCurve](k: PrivateKey[C])
  /** Sign with the curve's paired hash (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 - the JOSE/TLS
    * pairing).
    */
  @targetName("ecSign")
  def sign(data: Slice)(using s: Signer[C], spec: EcSpec[C]): UEffIO[Signature[C]] =
    s.sign(k, data, Ecdsa(spec.hash))

  /** Sign under an explicit hash (cross-paired legacy interop). */
  @targetName("ecSignHash")
  def sign(data: Slice, hash: Sha2)(using s: Signer[C]): UEffIO[Signature[C]] =
    s.sign(k, data, Ecdsa(hash))
  @targetName("ecSigner")
  def signer(using s: Signer[C], spec: EcSpec[C]): Resource[IO, Signature.Signer[C]] = s.prepared(k, Ecdsa(spec.hash))
  @targetName("ecSignerHash")
  def signer(hash: Sha2)(using s: Signer[C]): Resource[IO, Signature.Signer[C]] = s.prepared(k, Ecdsa(hash))
end extension
extension [C <: EcCurve](k: PublicKey[C])
  @targetName("ecVerify")
  def verify(data: Slice, sig: Signature[C])(using v: Verifier[C], spec: EcSpec[C]): EffIO[SignatureRejected, Unit] =
    v.verify(k, data, sig, Ecdsa(spec.hash))

  /** Verify under an explicit hash - the X.509 case where the certificate names a hash the curve
    * pairing would not choose.
    */
  @targetName("ecVerifyHash")
  def verify(data: Slice, sig: Signature[C], hash: Sha2)(using v: Verifier[C]): EffIO[SignatureRejected, Unit] =
    v.verify(k, data, sig, Ecdsa(hash))
  @targetName("ecVerifier")
  def verifier(using v: Verifier[C], spec: EcSpec[C]): Resource[IO, Signature.Verifier[C]] = v.prepared(k, Ecdsa(spec.hash))
  @targetName("ecVerifierHash")
  def verifier(hash: Sha2)(using v: Verifier[C]): Resource[IO, Signature.Verifier[C]] = v.prepared(k, Ecdsa(hash))
end extension

extension (k: PrivateKey[Rsa])
  /** Sign under the named padding (PSS or PKCS#1 v1.5). RSA has no safe default - the choice is
    * explicit, always.
    */
  @targetName("rsaSign")
  def sign(data: Slice, scheme: Scheme[Rsa])(using s: Signer[Rsa]): UEffIO[Signature[Rsa]] =
    s.sign(k, data, scheme)
  @targetName("rsaSigner")
  def signer(scheme: Scheme[Rsa])(using s: Signer[Rsa]): Resource[IO, Signature.Signer[Rsa]] = s.prepared(k, scheme)
extension (k: PublicKey[Rsa])
  @targetName("rsaVerify")
  def verify(data: Slice, sig: Signature[Rsa], scheme: Scheme[Rsa])(using v: Verifier[Rsa]): EffIO[SignatureRejected, Unit] =
    v.verify(k, data, sig, scheme)
  @targetName("rsaVerifier")
  def verifier(scheme: Scheme[Rsa])(using v: Verifier[Rsa]): Resource[IO, Signature.Verifier[Rsa]] = v.prepared(k, scheme)

@implicitNotFound("key agreement for ${A} is not provided by this kufuli backend")
trait Agreement[A <: AgreementAlgorithm]:
  /** Total: peer keys are validated at import and generated keys are valid by construction. */
  def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEffIO[SharedSecret]
object Agreement extends AgreementPlatform

extension [A <: AgreementAlgorithm](k: PrivateKey[A])
  def agree(peer: PublicKey[A])(using a: Agreement[A]): UEffIO[SharedSecret] = a.agree(k, peer)

@implicitNotFound("${K} is not provided by this kufuli backend (ML-KEM is JVM >= 25 and Native, not Node or browser)")
trait Kem[K <: KemAlgorithm]:
  def encapsulate(pub: PublicKey[K]): UEffIO[Encapsulated[K]]

  /** Total: FIPS 203 implicit rejection returns a pseudorandom secret for a forged ciphertext. */
  def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEffIO[SharedSecret]
object Kem extends KemPlatform

extension [K <: KemAlgorithm](pub: PublicKey[K]) def encapsulate(using k: Kem[K]): UEffIO[Encapsulated[K]] = k.encapsulate(pub)
extension [K <: KemAlgorithm](priv: PrivateKey[K])
  def decapsulate(ct: KemCiphertext[K])(using k: Kem[K]): UEffIO[SharedSecret] = k.decapsulate(priv, ct)

@implicitNotFound("key wrapping for ${W} is not provided by this kufuli backend (the browser lacks AES-KWP)")
trait Wrap[W <: WrapAlgorithm]:
  /** Backend primitive over pre-validated bytes; the typed surface is the SecretKey extension. */
  def wrap(kek: SecretKey[W], target: Slice): UEffIO[Slice]
  def unwrap(kek: SecretKey[W], wrapped: Slice): EffIO[UnwrapFailed, Slice]
object Wrap extends WrapPlatform

extension [W <: WrapAlgorithm](kek: SecretKey[W])
  /** Wrap `target` under this key-encryption key. Plain AES-KW rejects lengths that are not a
    * multiple of 8 with `NotWrappable` (reachable via variable-length HMAC keys); a KWP algorithm
    * accepts any length. RFC 3394 blobs carry no algorithm binding - binding wrapped material to
    * its algorithm is the caller's storage schema. Escrow goes through here, never raw bytes.
    */
  def wrap[A <: SymmetricAlgorithm](target: SecretKey[A])(using w: Wrap[W], spec: WrapSpec[W]): EffIO[NotWrappable, Slice] =
    EffIO.defer {
      target.read { t =>
        if !spec.padded && t.length % 8 != 0 then EffIO.fail(NotWrappable)
        else w.wrap(kek, t)
      }
    }

  /** Unwrap to a key of the named algorithm; the unwrapped length is validated against the spec
    * (the typed channel is sound: both arms are proper classes).
    */
  def unwrap[A <: SymmetricAlgorithm](wrapped: Slice, as: SymmetricSpec[A])(using
    w: Wrap[W]
  ): EffIO[UnwrapFailed | InvalidKey, SecretKey[A]] =
    w.unwrap(kek, wrapped).flatMap { pt =>
      val bytes = pt.toArray
      pt.wipe()
      EffIO.from(as.validate(bytes.length).map(_ => SecretKey.unsafe[A](bytes)))
    }
end extension

@implicitNotFound("HKDF/PBKDF2 is not provided by this kufuli backend")
trait Kdf:
  def extract(hash: Sha2, salt: Slice, ikm: Slice): UEffIO[Prk]
  def expand(hash: Sha2, prk: Prk, info: Slice, length: Int): UEffIO[Slice]
  def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEffIO[Slice]
object Kdf extends KdfPlatform

/** HKDF (RFC 5869) with Extract and Expand exposed SEPARATELY, as the TLS/QUIC key schedule needs.
  * Label layouts are owned here (shared, KAT-verified once); backends provide only the primitives.
  */
object HKDF:
  def extract(hash: Sha2, salt: Slice, ikm: Slice)(using k: Kdf): UEffIO[Prk] = k.extract(hash, salt, ikm)

  /** Extract from a [[SharedSecret]] without exposing it - the agree-then-derive path. */
  @targetName("extractSecret")
  def extract(hash: Sha2, salt: Slice, ikm: SharedSecret)(using Kdf): UEffIO[Prk] = extractFrom(hash, salt, ikm)

  // The SharedSecret-extract body, non-overloaded: internal callers route through it so no
  // same-file reference names the overloaded `extract` whose sibling carries @targetName, which
  // Scaladoc cannot resolve at TASTy read.
  private[kufuli] def extractFrom(hash: Sha2, salt: Slice, ikm: SharedSecret)(using k: Kdf): UEffIO[Prk] =
    EffIO.defer(ikm.read(s => k.extract(hash, salt, s)))
  def expand(hash: Sha2, prk: Prk, info: Slice, length: Int)(using k: Kdf): UEffIO[Slice] =
    require(length > 0 && length <= 255 * hash.length, "HKDF output length out of range")
    k.expand(hash, prk, info, length)

  /** Target-typed expansion: the algorithm fixes the length - no `len` to get wrong - and the raw
    * intermediate is wiped.
    */
  def expandKey[A <: SymmetricAlgorithm](hash: Sha2, prk: Prk, info: Slice, as: SymmetricSpec[A])(using
    k: Kdf
  ): UEffIO[SecretKey[A]] =
    k.expand(hash, prk, info, as.keyLength).map { out =>
      val bytes = out.toArray
      out.wipe()
      SecretKey.unsafe[A](bytes)
    }

  /** HKDF-Expand-Label (RFC 8446 section 7.1, also QUIC RFC 9001), owned here so the byte layout is
    * KAT-verified once, never hand-rolled per protocol. QUIC version constants stay downstream.
    */
  def expandLabel(hash: Sha2, prk: Prk, label: String, context: Slice, length: Int)(using Kdf): UEffIO[Slice] =
    require(label.length <= 249 && context.length <= 255, "expand-label bounds")
    expand(hash, prk, hkdfLabel(label, context, length), length)
  def expandLabelKey[A <: SymmetricAlgorithm](hash: Sha2, prk: Prk, label: String, context: Slice, as: SymmetricSpec[A])(using
    Kdf
  ): UEffIO[SecretKey[A]] =
    require(label.length <= 249 && context.length <= 255, "expand-label bounds")
    expandKey(hash, prk, hkdfLabel(label, context, as.keyLength), as)

  // RFC 8446 s7.1 HkdfLabel: uint16 length; opaque label<7..255> = "tls13 " ++ label; context<0..255>.
  private[kufuli] def hkdfLabel(label: String, context: Slice, length: Int): Slice =
    val full = ("tls13 " + label).getBytes("US-ASCII")
    val out = new Array[Byte](2 + 1 + full.length + 1 + context.length)
    val s = Slice.of(out)
    s.writeBE[Short](0, length.toShort)
    out(2) = full.length.toByte
    val _ = Slice.of(full).copyInto(s.drop(3))
    out(3 + full.length) = context.length.toByte
    val _ = context.copyInto(s.drop(4 + full.length))
    s
end HKDF

/** PBKDF2-HMAC (RFC 8018) - protocol interop (SCRAM `Hi`, legacy formats), NEVER new password
  * storage (kufuli.password owns that). Iteration counts are a `require`: SCRAM protocol code
  * validates wire-received counts before kufuli sees them.
  */
object PBKDF2:
  def derive(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int)(using k: Kdf): UEffIO[Slice] =
    require(iterations >= 1 && length > 0 && length <= 255 * hash.length, "PBKDF2 parameters")
    k.pbkdf2(hash, password, salt, iterations, length)
  def deriveKey[A <: SymmetricAlgorithm](hash: Sha2, password: Slice, salt: Slice, iterations: Int, as: SymmetricSpec[A])(using
    k: Kdf
  ): UEffIO[SecretKey[A]] =
    require(iterations >= 1, "PBKDF2 iterations")
    k.pbkdf2(hash, password, salt, iterations, as.keyLength).map { out =>
      val bytes = out.toArray
      out.wipe()
      SecretKey.unsafe[A](bytes)
    }
end PBKDF2

@implicitNotFound("${D} is not provided by this kufuli backend")
trait Hash[D <: HashAlgorithm]:
  def digest(data: Slice): UEffIO[Digest]
object Hash extends HashPlatform

@implicitNotFound(
  "this kufuli backend cannot hash synchronously (WebCrypto is async-only): incremental hashing is unavailable in the browser artifact"
)
trait Hashing[D <: HashAlgorithm]:
  def hasher: Resource[IO, Hasher]
object Hashing extends HashingPlatform

/** A synchronous, single-fibre incremental hash. `digest` SNAPSHOTS without consuming the context -
  * the TLS transcript shape.
  */
trait Hasher:
  def update(data: Slice): Unit
  def digest: Digest

@implicitNotFound("RSA-OAEP is not provided by this kufuli backend")
trait Oaep:
  def encrypt(key: PublicKey[Rsa], plaintext: Slice, scheme: RsaOaep): UEffIO[Slice]
  def decrypt(key: PrivateKey[Rsa], ciphertext: Slice, scheme: RsaOaep): EffIO[AuthFailed, Slice]
object Oaep extends OaepPlatform

extension (k: PublicKey[Rsa])
  /** RSA-OAEP encrypt. Total: an oversized plaintext is static arithmetic - a defect, not data. */
  @targetName("rsaEncrypt")
  def encrypt(plaintext: Slice, scheme: RsaOaep)(using o: Oaep): UEffIO[Slice] = o.encrypt(k, plaintext, scheme)
extension (k: PrivateKey[Rsa])
  /** RSA-OAEP decrypt. The error is deliberately opaque and failure timing uniform (the Manger
    * countermeasure) - a backend contract. There is no PKCS#1 decryption anywhere.
    */
  @targetName("rsaDecrypt")
  def decrypt(ciphertext: Slice, scheme: RsaOaep)(using o: Oaep): EffIO[AuthFailed, Slice] =
    o.decrypt(k, ciphertext, scheme)

// Shared box assembly: header || aad is the associated data, so a box's version and routing are
// AUTHENTICATED, not advisory (executed: re-heading a valid box refuses to open).

private def sealBox[A <: AeadAlgorithm](key: SecretKey[A], id: Option[KeyId], aad: Slice, plaintext: Slice)(using
  a: Aead[A],
  r: Random,
  spec: AeadSpec[A]
): UEffIO[SealedBox[A]] =
  Nonce.random(spec).flatMap { nonce =>
    val header = id match
      case None    => Array[Byte](1)
      case Some(i) =>
        val h = new Array[Byte](5)
        h(0) = 2
        Slice.of(h).writeBE[Int](1, i) // KeyId is transparently Int here
        h
    val bound = new Array[Byte](header.length + aad.length)
    val _ = Slice.of(header).copyInto(Slice.of(bound))
    val _ = aad.copyInto(Slice.of(bound).drop(header.length))
    a.seal(key, nonce, Slice.of(bound), plaintext).map { ct =>
      val out = new Array[Byte](header.length + spec.nonceLength + ct.length)
      val s = Slice.of(out)
      val _ = Slice.of(header).copyInto(s)
      val _ = Slice.of(nonce).copyInto(s.drop(header.length)) // Nonce is transparently Array[Byte] here
      val _ = ct.copyInto(s.drop(header.length + spec.nonceLength))
      SealedBox.unsafe(out)
    }
  }

private def openBox[A <: AeadAlgorithm](key: SecretKey[A], box: SealedBox[A], aad: Slice)(using
  a: Aead[A],
  spec: AeadSpec[A]
): EffIO[AuthFailed, Slice] =
  val b: Array[Byte] = box // transparent in the defining file
  val headerLen = if b(0) == 2.toByte then 5 else 1
  val bound = new Array[Byte](headerLen + aad.length)
  val _ = Slice.of(b, 0, headerLen).copyInto(Slice.of(bound))
  val _ = aad.copyInto(Slice.of(bound).drop(headerLen))
  val nonce = Nonce.unsafe[A](Slice.of(b, headerLen, spec.nonceLength).toArray)
  a.open(key, nonce, Slice.of(bound), Slice.of(b).drop(headerLen + spec.nonceLength))

extension [A <: AeadAlgorithm](key: SecretKey[A])
  /** Seal into a versioned self-describing box; the nonce is generated internally - never in the
    * caller's hands. The misuse-resistant at-rest tier.
    */
  def seal(plaintext: Slice)(using Aead[A], Random, AeadSpec[A]): UEffIO[SealedBox[A]] = key.seal(plaintext, Slice.empty)
  def seal(plaintext: Slice, aad: Slice)(using Aead[A], Random, AeadSpec[A]): UEffIO[SealedBox[A]] =
    sealBox(key, None, aad, plaintext)
  def open(box: SealedBox[A])(using Aead[A], AeadSpec[A]): EffIO[AuthFailed, Slice] = key.open(box, Slice.empty)
  def open(box: SealedBox[A], aad: Slice)(using Aead[A], AeadSpec[A]): EffIO[AuthFailed, Slice] =
    openBox(key, box, aad)

/** Per-key AEAD usage limits, INCLUDING the decrypt-failure budget (RFC 9001 forgery limit
  * mirroring the confidentiality limit). Non-positive limits are a defect.
  */
final case class AeadLimits(encryptions: Long, bytes: Long, decryptFailures: Long):
  require(encryptions > 0 && bytes > 0 && decryptFailures > 0, "AEAD limits must be positive")
object AeadLimits:
  /** The floor shared by the 96-bit-nonce tier (AES-GCM, GCM-SIV, CBC-HS): SP 800-38D section 8.3
    * caps invocations at 2^32 for a random 96-bit IV; the forgery limit is the smallest across the
    * tier (RFC 9001 section 6.6 Poly1305).
    */
  val default: AeadLimits = AeadLimits(1L << 32, 1L << 50, 1L << 36)

  /** ChaCha20-Poly1305 and XChaCha20-Poly1305: RFC 9001 section 6.6 lifts the confidentiality limit
    * beyond any realistic message count (2^62); the forgery limit stays the Poly1305 bound.
    */
  val chaCha: AeadLimits = AeadLimits(1L << 62, 1L << 62, 1L << 36)

/** Remaining budget, observable for PROACTIVE key update ahead of the limit (RFC 9001 section 6). */
final case class AeadBudget(encryptions: Long, bytes: Long, decryptFailures: Long) derives CanEqual

/** The per-record AEAD machine: SYNCHRONOUS `Either` ops, so a loop-thread codec calls them inline
  * (`EffIO.delay` lifts into the typed effect for free); buffers are borrowed `Slice`s, never
  * retained; the nonce is explicit in BOTH directions, derived per record with [[Nonce.xorInto]] -
  * a TLS/QUIC nonce is never on the wire. One vocabulary, no raw offsets:
  * `c.encrypt(out, plaintext, aad, nonce).map(n => socket.write(out.take(n)))`. Budget accounting
  * is SHARED code over a backend [[Cipher.Engine]] - no backend can mis-count a limit. Single-fibre
  * like [[Hasher]]; `budget` reads are safe from any fibre.
  */
trait Cipher[A <: AeadAlgorithm]:
  /** Seals `src`, writing `ct || tag` at `dst`'s start; returns the bytes written. */
  def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[BudgetExhausted, Int]

  /** Opens `src` (`ct || tag`), writing the plaintext at `dst`'s start; returns the bytes written. */
  def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed | BudgetExhausted, Int]

  /** Remaining budget, for a proactive key update ahead of the limit. */
  def budget: AeadBudget

object Cipher:
  /** The backend's raw per-key synchronous engine (on aws-lc: one const `EVP_AEAD_CTX` for the
    * handle's lifetime). No budgets and no argument validation - both are shared code in the
    * [[Cipher]] wrapper, which pre-validates every buffer.
    */
  trait Engine[A <: AeadAlgorithm]:
    def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int
    def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int]

@implicitNotFound("a synchronous record engine for ${A} is not provided by this kufuli backend (WebCrypto is async-only: the record Cipher is unavailable in the browser artifact)")
trait Ciphering[A <: AeadAlgorithm]:
  def engine(key: SecretKey[A]): Resource[IO, Cipher.Engine[A]]
object Ciphering extends CipheringPlatform

// The one audited accounting site. Encrypt charges the confidentiality budgets (invocations AND
// bytes) up front; decrypt charges only FAILURES (the forgery limit) and refuses once spent.
final private class Budgeted[A <: AeadAlgorithm](engine: Cipher.Engine[A], spec: AeadSpec[A], limits: AeadLimits) extends Cipher[A]:
  private val encrypts = new AtomicLong(limits.encryptions)
  private val octets = new AtomicLong(limits.bytes)
  private val failures = new AtomicLong(limits.decryptFailures)
  def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[BudgetExhausted, Int] =
    require(nonce.length == spec.nonceLength, "nonce length")
    require(dst.length >= src.length + spec.tagLength, "dst capacity")
    if encrypts.get() <= 0 || octets.get() < src.length then Left(BudgetExhausted)
    else
      val _ = encrypts.decrementAndGet()
      val _ = octets.addAndGet(-src.length.toLong)
      Right(engine.encrypt(dst, src, aad, nonce))
  def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed | BudgetExhausted, Int] =
    require(nonce.length == spec.nonceLength, "nonce length")
    if failures.get() <= 0 then Left(BudgetExhausted)
    else if src.length < spec.tagLength then
      val _ = failures.decrementAndGet()
      Left(AuthFailed)
    else
      require(dst.length >= src.length - spec.tagLength, "dst capacity")
      engine.decrypt(dst, src, aad, nonce) match
        case l @ Left(_) =>
          val _ = failures.decrementAndGet()
          l
        case r => r
  end decrypt
  def budget: AeadBudget =
    AeadBudget(math.max(0L, encrypts.get()), math.max(0L, octets.get()), math.max(0L, failures.get()))
end Budgeted

extension [A <: AeadAlgorithm](key: SecretKey[A])
  /** Acquire a per-record [[Cipher]] with the algorithm's default limits. */
  def cipher(using c: Ciphering[A], spec: AeadSpec[A]): Resource[IO, Cipher[A]] = key.cipher(spec.defaultLimits)

  /** Acquire a per-record [[Cipher]] with explicit limits. */
  def cipher(limits: AeadLimits)(using c: Ciphering[A], spec: AeadSpec[A]): Resource[IO, Cipher[A]] =
    c.engine(key).map(e => new Budgeted(e, spec, limits))

/** An identifier for a key within a [[Keyring]]. Ids come from configuration - data - so ring
  * construction returns `Either` and uniqueness is the only rule.
  */
opaque type KeyId = Int
object KeyId:
  def of(value: Int): KeyId = value
  extension (id: KeyId) def value: Int = id
  given CanEqual[KeyId, KeyId] = CanEqual.derived

/** An immutable ring of keys of ONE algorithm, making rotation a value: seal/sign under the
  * primary, open/verify anything the ring still holds. A bare carrier over any key family - the
  * per-family operations are presence-gated top-level extensions. There is deliberately no
  * ring-level `destroy`: rings share key instances across rotations - keys retire individually.
  */
final class Keyring[A <: Algorithm] private (
  private[kufuli] val primaryId: KeyId,
  private[kufuli] val primary: SecretKey[A],
  private[kufuli] val others: List[(KeyId, SecretKey[A])]
):
  /** A ring with `newPrimary` as primary; its id must be new. The old primary stays held. */
  def rotated(newPrimary: (KeyId, SecretKey[A])): Either[DuplicateKeyId, Keyring[A]] =
    if all.exists(_._1 == newPrimary._1) then Left(DuplicateKeyId)
    else Right(new Keyring(newPrimary._1, newPrimary._2, (primaryId, primary) :: others))
  private[kufuli] def all: List[(KeyId, SecretKey[A])] = (primaryId, primary) :: others
  private[kufuli] def find(id: KeyId): Option[SecretKey[A]] =
    all.collectFirst { case (i, k) if i == id => k }
end Keyring
object Keyring:
  def of[A <: Algorithm](primary: (KeyId, SecretKey[A]), others: (KeyId, SecretKey[A])*): Either[DuplicateKeyId, Keyring[A]] =
    val ids = primary._1 :: others.map(_._1).toList
    if ids.distinct.length != ids.length then Left(DuplicateKeyId)
    else Right(new Keyring(primary._1, primary._2, others.toList))

// Ring operations live at the top level with every other family extension (companion-nested ring
// ops would shadow the same-named key extensions).
extension [A <: AeadAlgorithm](ring: Keyring[A])
  @targetName("ringSeal")
  def seal(plaintext: Slice)(using Aead[A], Random, AeadSpec[A]): UEffIO[SealedBox[A]] = ring.seal(plaintext, Slice.empty)
  @targetName("ringSealAad")
  def seal(plaintext: Slice, aad: Slice)(using Aead[A], Random, AeadSpec[A]): UEffIO[SealedBox[A]] =
    sealBox(ring.primary, Some(ring.primaryId), aad, plaintext)

  /** Opens a ring (version 2) box by its AUTHENTICATED key id; a pre-ring (version 1) box opens by
    * bounded trial - the AEAD tag is the check - so adopting a ring needs no re-encryption. An
    * unknown id is indistinguishable from a forgery, by design.
    */
  @targetName("ringOpen")
  def open(box: SealedBox[A])(using Aead[A], AeadSpec[A]): EffIO[AuthFailed, Slice] = ring.open(box, Slice.empty)
  @targetName("ringOpenAad")
  def open(box: SealedBox[A], aad: Slice)(using Aead[A], AeadSpec[A]): EffIO[AuthFailed, Slice] =
    val b: Array[Byte] = box
    if b(0) == 2.toByte then
      ring.find(KeyId.of(Slice.of(b).readBE[Int](1))) match
        case Some(k) => openBox(k, box, aad)
        case None    => EffIO.fail(AuthFailed)
    else ring.all.map((_, k) => openBox(k, box, aad)).reduce((acc, next) => acc.catchAll(_ => next))
end extension

extension [H <: MacAlgorithm](ring: Keyring[H])
  /** Tag under the primary key - the session/CSRF issuance path. */
  @targetName("ringSign")
  def sign(data: Slice)(using m: Mac[H]): UEffIO[Signature[H]] = m.sign(ring.primary, data)

  /** Verify against any key the ring holds, primary first: tags issued under a retired-but-held key
    * still verify - session rotation without a flag day. Every attempt goes through the one audited
    * constant-time compare.
    */
  @targetName("ringVerify")
  def verify(data: Slice, sig: Signature[H])(using m: Mac[H]): EffIO[SignatureRejected, Unit] =
    ring.all.map((_, k) => macVerify(m, k, data, sig)).reduce((acc, next) => acc.catchAll(_ => next))
end extension

// Split per KEY FAMILY: signatures genuinely differ (parameters, wire forms, encodings), so a
// uniform trait would force GADT ceremony on every backend for no consumer benefit. Backends
// consume and emit WHOLE encoded blobs (JCA KeySpec / WebCrypto importKey / aws-lc EVP_parse_*
// all validate the full encoding); exports are effectful and typed - a browser-GENERATED key is
// non-extractable and fails with [[KeyNotExportable]]; an IMPORTED key always exports.

@implicitNotFound("Ed25519 key lifecycle is not provided by this kufuli backend")
trait EdKeys:
  def generate: UEffIO[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]]
  def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[Ed25519]]
  def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Ed25519]]
  def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Ed25519]]
  def raw(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]]
  def spki(key: PublicKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]]
  def pkcs8(key: PrivateKey[Ed25519]): EffIO[KeyNotExportable, IArray[Byte]]
object EdKeys extends EdKeysPlatform

@implicitNotFound("X25519 key lifecycle is not provided by this kufuli backend")
trait XKeys:
  def generate: UEffIO[KeyPair[PublicKey[X25519], PrivateKey[X25519]]]
  def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[X25519]]
  def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[X25519]]
  def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[X25519]]
  def raw(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]]
  def spki(key: PublicKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]]
  def pkcs8(key: PrivateKey[X25519]): EffIO[KeyNotExportable, IArray[Byte]]
object XKeys extends XKeysPlatform

@implicitNotFound("key lifecycle for curve ${C} is not provided by this kufuli backend")
trait EcKeys[C <: EcCurve]:
  def generate: UEffIO[KeyPair[PublicKey[C], PrivateKey[C]]]
  def fromSec1(point: Slice): EffIO[InvalidKey, PublicKey[C]]
  def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[C]]
  def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[C]]
  def sec1(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]]
  def spki(key: PublicKey[C]): EffIO[KeyNotExportable, IArray[Byte]]
  def pkcs8(key: PrivateKey[C]): EffIO[KeyNotExportable, IArray[Byte]]
object EcKeys extends EcKeysPlatform

@implicitNotFound("RSA key lifecycle is not provided by this kufuli backend")
trait RsaKeys:
  def generate(size: Rsa.Size): UEffIO[KeyPair[PublicKey[Rsa], PrivateKey[Rsa]]]
  def fromComponents(modulus: Slice, exponent: Slice): EffIO[InvalidKey, PublicKey[Rsa]]
  def fromSpki(der: Slice): EffIO[InvalidKey, PublicKey[Rsa]]
  def fromPkcs8(der: Slice): EffIO[InvalidKey, PrivateKey[Rsa]]
  def components(key: PublicKey[Rsa]): EffIO[KeyNotExportable, Rsa.Components]
  def spki(key: PublicKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]]
  def pkcs8(key: PrivateKey[Rsa]): EffIO[KeyNotExportable, IArray[Byte]]
object RsaKeys extends RsaKeysPlatform

// KEM keys travel raw in v1 protocols (TLS KeyShare); SPKI/PKCS#8 interop is post-v1.
@implicitNotFound("${K} key lifecycle is not provided by this kufuli backend (ML-KEM is JVM >= 25 and Native)")
trait KemKeys[K <: KemAlgorithm]:
  def generate: UEffIO[KeyPair[PublicKey[K], PrivateKey[K]]]
  def fromRaw(bytes: Slice): EffIO[InvalidKey, PublicKey[K]]
  def raw(key: PublicKey[K]): EffIO[KeyNotExportable, IArray[Byte]]
object KemKeys extends KemKeysPlatform

// Exports - effectful and typed. Symmetric raw export is deliberately ABSENT (compile fact).
extension (pub: PublicKey[Ed25519])
  @targetName("rawEd") def raw(using k: EdKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.raw(pub)
  @targetName("spkiEd") def spki(using k: EdKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.spki(pub)
extension (pub: PublicKey[X25519])
  @targetName("rawX") def raw(using k: XKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.raw(pub)
  @targetName("spkiX") def spki(using k: XKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.spki(pub)
extension [C <: EcCurve](pub: PublicKey[C])
  def sec1(using k: EcKeys[C]): EffIO[KeyNotExportable, IArray[Byte]] = k.sec1(pub)
  @targetName("spkiEc") def spki(using k: EcKeys[C]): EffIO[KeyNotExportable, IArray[Byte]] = k.spki(pub)
extension (pub: PublicKey[Rsa])
  def components(using k: RsaKeys): EffIO[KeyNotExportable, Rsa.Components] = k.components(pub)
  @targetName("spkiRsa") def spki(using k: RsaKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.spki(pub)
extension [K <: KemAlgorithm](pub: PublicKey[K])
  @targetName("rawKem") def raw(using k: KemKeys[K]): EffIO[KeyNotExportable, IArray[Byte]] = k.raw(pub)
extension (priv: PrivateKey[Ed25519])
  @targetName("pkcs8Ed") def pkcs8(using k: EdKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.pkcs8(priv)
extension (priv: PrivateKey[X25519]) @targetName("pkcs8X") def pkcs8(using k: XKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.pkcs8(priv)
extension [C <: EcCurve](priv: PrivateKey[C])
  @targetName("pkcs8Ec") def pkcs8(using k: EcKeys[C]): EffIO[KeyNotExportable, IArray[Byte]] = k.pkcs8(priv)
extension (priv: PrivateKey[Rsa]) @targetName("pkcs8Rsa") def pkcs8(using k: RsaKeys): EffIO[KeyNotExportable, IArray[Byte]] = k.pkcs8(priv)
