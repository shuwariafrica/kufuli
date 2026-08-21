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

import scala.annotation.implicitNotFound
import scala.annotation.tailrec
import scala.annotation.targetName
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.TypedError
import boilerplate.codec
import boilerplate.effect.Eff
import boilerplate.effect.EffResource
import boilerplate.effect.UEff
import cats.effect.IO
import cats.effect.Resource

// Data-dependent failures are values; programmer errors (nonce lengths, buffer arithmetic,
// nonsense limits) are DEFECTS via require; a misbehaving backend is a raised, sanitised
// `Unexpected` defect - never a wrong success, never secret-echoing.

sealed abstract class KufuliError(message: String, cause: Option[Throwable]) extends TypedError(message, cause):
  def this(message: String) = this(message, None)

// Payload-free arms are a class plus a co-named object, and type positions name the CLASS: a union
// of singleton types does not survive the TypeTest reification `either`/`catchAll` rely on, so the
// FIRST arm of such a union raises a ClassCastException through every reifying observer. Re-tested
// at each toolchain adoption, last at Scala 3.9.0-RC5 on JVM and Native: still broken. Drop the
// class+object shape for plain case objects when the erasure defect is fixed.
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

/** Why an import door refused key material. The arm is chosen in SHARED code from the form the door
  * was handed, never by a backend, so one input yields one arm on every platform:
  *   - `WrongLength(expected, got)` - the material's length is not the algorithm's;
  *   - `Malformed` - an encoding kufuli failed to read;
  *   - `NotOnCurve` - a structurally sound point the backend refused;
  *   - `WeakPoint` - a blocklisted small-order point (refused above every backend);
  *   - `Unsupported` - a WELL-FORMED input kufuli declines: an algorithm it lacks, an encoding
  *     variant it does not serve (compressed SEC1), or a strength below its floor (RSA 2048).
  */
enum InvalidKey(message: String) extends KufuliError(message):
  case WrongLength(expected: Int, got: Int) extends InvalidKey(s"expected $expected bytes, got $got")
  case Malformed extends InvalidKey("malformed key encoding")
  case NotOnCurve extends InvalidKey("point not on curve")
  case WeakPoint extends InvalidKey("small-order or otherwise weak public point")
  case Unsupported extends InvalidKey("not supported here")

// A backend's refusal of a key encoding: a BINARY verdict with no arm of its own. The public arm
// is chosen by the companion door from the form it was handed, so three backends cannot drift
// into three classifications of one input.
sealed abstract private[kufuli] class Refused private[kufuli] ()
    extends Exception("the backend refused this key encoding")
    with NoStackTrace
private[kufuli] case object Refused extends Refused

/** The FFI/backend-failure channel: a genuine backend anomaly is wrapped idempotently and RAISED as
  * a defect. The message is generic - the cause (which may echo key or plaintext material) never
  * reaches `getMessage`.
  */
final class Unexpected private (val cause: Throwable) extends KufuliError("unexpected backend failure", Some(cause))
object Unexpected:
  def apply(cause: Throwable): KufuliError = TypedError.idempotent[KufuliError, Unexpected](cause)(new Unexpected(_))
  def unapply(u: Unexpected): Some[Throwable] = Some(u.cause)

/** Every backend (FFI) call routes through `guard`: a raw backend throwable becomes a raised
  * `Unexpected` - a crypto op can never return a wrong success because a backend glitched.
  */
private[kufuli] def guard[A](io: IO[A]): IO[A] =
  io.handleErrorWith(t => IO.raiseError(Unexpected(t)))

// A backend that hands back an unusable value where the call was already made total (a parsed key,
// a validated length) is anomalous, and on a path producing a key, a signature, a digest or a
// ciphertext the only sound outcome is a raise: any value of the right shape is a success the
// caller cannot tell from a real one. The same holds of an invariant a construction door already
// established. Where the path routes through `guard`, the raise is sanitised into a defect.
private[kufuli] def demand[A](result: Either[?, A]): A = result match
  case Right(a) => a
  case Left(_) => throw new IllegalStateException("a value this call had already established is unusable") // scalafix:ok DisableSyntax.throw

// Secret bytes live in `boilerplate.Secret`, whose single atomic cell makes a destroy concurrent
// with a read raise on the destroying side rather than erase mid-read; each platform's `SecretRepr`
// widens that to the representations its backend can hold. Custody splits two ways: `secretAdopt`
// transfers a kufuli-internal transient (copy in, wipe the source), `secretCopy` copies a
// caller-owned buffer whose hygiene stays the caller's.

// The trait is the TYPE-level tag (`SecretKey[AesGcm256]`); the co-named object is the VALUE
// (metadata + generation). MAKE names the algorithm (`AesGcm256.generate`, `P256.generate`,
// `Sha256.hasher`); `parse` reads a serialisation, typed by the owned format it claims
// (`PublicKey.parse(P256)(point: SEC1)`). P-curves genuinely serve both signing and agreement;
// Ed25519/X25519 stay structurally disjoint.

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
  final private[kufuli] def generateUnchecked(using r: Random): UEff[SecretKey[A]] =
    r.bytes(keyLength).map { s =>
      val b = s.toArray
      s.wipe()
      SecretKey.unsafe[A](b)
    }
end SymmetricSpec

sealed abstract class AeadSpec[A <: AeadAlgorithm](keyOctets: Int, val nonceLength: Int, val tagLength: Int, val defaultLimits: AeadLimits)
    extends SymmetricSpec[A](keyOctets):
  /** A fresh key from the backend CSPRNG; requires the algorithm to be OPERABLE here. */
  final def generate(using a: AEAD[A], r: Random): UEff[SecretKey[A]] =
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
  final def generate(using m: MAC[H], r: Random): UEff[SecretKey[H]] =
    val _ = m // operability evidence: an unusable key is ungeneratable
    generateUnchecked(using r)
object MacSpec:
  given MacSpec[HmacSha1] = HmacSha1
  given MacSpec[HmacSha256] = HmacSha256
  given MacSpec[HmacSha384] = HmacSha384
  given MacSpec[HmacSha512] = HmacSha512

sealed abstract class WrapSpec[W <: WrapAlgorithm](keyOctets: Int, val padded: Boolean) extends SymmetricSpec[W](keyOctets):
  /** A fresh key-encryption key from the backend CSPRNG; requires the algorithm to be OPERABLE
    * here.
    */
  final def generate(using w: Wrap[W], r: Random): UEff[SecretKey[W]] =
    val _ = w // operability evidence: an unusable key is ungeneratable
    generateUnchecked(using r)
object WrapSpec:
  given WrapSpec[AesKw128] = AesKw128
  given WrapSpec[AesKw256] = AesKw256
  given WrapSpec[AesKwp128] = AesKwp128
  given WrapSpec[AesKwp256] = AesKwp256

sealed abstract class EcSpec[C <: EcCurve](val fieldLength: Int, val hash: Sha2):
  /** Generate a fresh keypair on this curve. */
  final def generate(using k: EcKeys[C]): UEff[KeyPair[PublicKey[C], PrivateKey[C]]] = k.generate
object EcSpec:
  given EcSpec[P256] = P256
  given EcSpec[P384] = P384
  given EcSpec[P521] = P521

sealed abstract class HashSpec[D <: HashAlgorithm](val length: Int):
  /** One-shot digest - `Sha256.digest(data)`. Universal (async-capable on every backend). */
  final def digest(data: Slice)(using h: Hash[D]): UEff[Digest] = h.digest(data)

  /** A Resource-scoped incremental hasher - `Sha256.hasher`. Synchronous; its absence on the
    * async-only browser backend is the compile fact (no `Hashing` instance there).
    */
  final def hasher(using h: Hashing[D]): EffResource[Nothing, Hasher] = h.hasher
object HashSpec:
  given HashSpec[Sha1] = Sha1
  given HashSpec[Sha256] = Sha256
  given HashSpec[Sha384] = Sha384
  given HashSpec[Sha512] = Sha512

sealed abstract class KemSpec[K <: KemAlgorithm](val publicKeyLength: Int, val ciphertextLength: Int):
  final def generate(using k: KemKeys[K]): UEff[KeyPair[PublicKey[K], PrivateKey[K]]] = k.generate
object KemSpec:
  given KemSpec[MlKem768] = MlKem768
  given KemSpec[MlKem1024] = MlKem1024

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
// HMAC-SHA1 exists for OATH HOTP/TOTP interop only (RFC 6238's default; the dominant authenticator
// apps ignore the algorithm parameter). HMAC is unaffected by SHA-1 collision weakness, and the
// sealed JWS algorithm set plus Sha2-bounded KDFs keep it out of every signing and derivation
// position.
sealed trait HmacSha1 extends MacAlgorithm
case object HmacSha1 extends MacSpec[HmacSha1](20) with HmacSha1

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
  def generate(using k: EdKeys): UEff[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]] = k.generate
sealed trait X25519 extends AgreementAlgorithm
case object X25519 extends X25519:
  def generate(using k: XKeys): UEff[KeyPair[PublicKey[X25519], PrivateKey[X25519]]] = k.generate

sealed trait RSA extends SignatureAlgorithm

/** RSA parameters: [[RSA.bits]] validates a modulus size (nonsense sizes are programmer error);
  * [[RSA.Components]] carries the public modulus and exponent (the JWK `n`/`e` pair).
  */
object RSA:
  final class Size private[RSA] (val bits: Int)
  // The generation range is the IMPORT range: a library that minted a key its own doors refuse, or
  // that no backend can verify with, would be handing the caller a key it cannot use.
  def bits(n: Int): Size =
    require(
      n >= minimumModulusBits && n <= maximumModulusBits && n % 8 == 0,
      s"RSA modulus must be between $minimumModulusBits and $maximumModulusBits bits and a multiple of 8, got $n"
    )
    new Size(n)

  // The import floor, shared by every backend's key lifecycle so the generation floor above cannot
  // be walked around by importing a weaker modulus. Below it the parameter class is one kufuli
  // declines rather than one it failed to read, so the arm is `Unsupported`, not `Malformed`.
  private[kufuli] val minimumModulusBits: Int = 2048

  // The ceiling, in the same arm as the floor, because above it NO engine kufuli ships can verify
  // with the key. The JDK refuses it at import ("RSA keys must be no longer than 16384 bits"),
  // aws-lc refuses it at import (crypto/fipsmodule/rsa/rsa.c:1090), and OpenSSL imports it and then
  // returns false from every operation - executed on node 26, where a 32768-bit key imports and its
  // verification returns in 0.14 ms against 2.1 ms for a real one, which is not a computation.
  // Declining it here is what stops that third case, where a key nothing can use is reported as a
  // valid key and its every signature as a forgery. Cost is the second and independent reason for
  // the same number: 0.38 ms per verification at 2048 bits against 3.45 ms at 16384 on JDK 25, and
  // the growth is superlinear, so whoever chooses the size chooses what a verification costs.
  private[kufuli] val maximumModulusBits: Int = 16384

  // Bit length of a big-endian unsigned magnitude, so padding in an encoding cannot inflate a
  // modulus past the floor.
  private[kufuli] def modulusBits(modulus: Slice): Int =
    @tailrec def firstSet(i: Int): Int = if i < modulus.length && modulus(i) == 0.toByte then firstSet(i + 1) else i
    val i = firstSet(0)
    if i == modulus.length then 0 else (modulus.length - i - 1) * 8 + (32 - Integer.numberOfLeadingZeros(modulus(i) & 0xff))

  private[kufuli] def floored(modulus: Slice): Either[InvalidKey, Unit] =
    val bits = modulusBits(modulus)
    if bits >= minimumModulusBits && bits <= maximumModulusBits then Right(()) else Left(InvalidKey.Unsupported)

  // RFC 7518 section 6.3.1.1 fixes the modulus at the minimum octets needed to represent the value.
  // The backends do not read a leading zero alike: node's JWK importer takes the octets verbatim
  // where the JVM and aws-lc normalise them away.
  private[kufuli] def flooredComponents(modulus: Slice): Either[InvalidKey, Unit] =
    if modulus.length > 1 && modulus(0) == 0.toByte then Left(InvalidKey.Malformed) else floored(modulus)

  // The floor over the SubjectPublicKeyInfo every byte-backed backend stores for an imported key.
  // Each element is bounded by the one containing it: a modulus INTEGER claiming more length than its
  // RSAPublicKey SEQUENCE declares would otherwise count octets towards the floor that the encoding
  // does not carry.
  private[kufuli] def flooredSpki(spki: Slice): Either[InvalidKey, Unit] =
    for
      bits <- DER.spkiPublicBits(spki)
      inner <- DER.read(bits, 0, 0x30)
      n <- DER.within(bits, inner.contentOff, 0x02, inner.next)
      _ <- floored(bits.slice(n.contentOff, n.next))
    yield ()

  // The PrivateKeyInfo's privateKey OCTET STRING carries an RSAPrivateKey (RFC 8017 appendix A.1.2)
  // whose second field is the modulus.
  private[kufuli] def flooredPkcs8(pkcs8: Slice): Either[InvalidKey, Unit] =
    for
      outer <- DER.read(pkcs8, 0, 0x30)
      version <- DER.within(pkcs8, outer.contentOff, 0x02, outer.next)
      algId <- DER.within(pkcs8, version.next, 0x30, outer.next)
      octets <- DER.within(pkcs8, algId.next, 0x04, outer.next)
      key <- DER.within(pkcs8, octets.contentOff, 0x30, octets.next)
      keyVersion <- DER.within(pkcs8, key.contentOff, 0x02, key.next)
      n <- DER.within(pkcs8, keyVersion.next, 0x02, key.next)
      _ <- floored(pkcs8.slice(n.contentOff, n.next))
    yield ()
  final case class Components(modulus: IArray[Byte], exponent: IArray[Byte])
  def generate(size: Size)(using k: RsaKeys): UEff[KeyPair[PublicKey[RSA], PrivateKey[RSA]]] = k.generate(size)
end RSA

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
case object Ed extends Scheme[Ed25519]
final case class ECDSA[C <: EcCurve](hash: Sha2) extends Scheme[C]
final case class RsaPss(hash: Sha2) extends Scheme[RSA]
final case class RsaPkcs1(hash: Sha2) extends Scheme[RSA] // certificates, JOSE RS256

/** RSA-OAEP parameters. */
final case class RsaOaep(hash: Sha2) derives CanEqual

// Public keys are opaque over the PLATFORM-DEFINED KeyRepr (per-unit source sets; the browser
// holds live CryptoKey handles) - shared code never sees the representation, which is why export
// is uniformly effectful and typed-failable. Secret material is opaque over the wipeable carrier.
// All tags INVARIANT: a key of one algorithm cannot be used with another.

final case class KeyPair[+Pub, +Priv](publicKey: Pub, privateKey: Priv)

// The arm a BACKEND refusal carries is fixed by the DOOR, from the FORM it was handed - never by
// the backend, which reports only `Refused`. A point-bearing form has passed kufuli's own
// structural walk by the time the backend sees it, so the only thing left to be wrong is the
// point; every other form fails as an encoding.
private def onPoint[A](e: Eff[Refused, A]): Eff[InvalidKey, A] = e.mapError(_ => InvalidKey.NotOnCurve)
private def onEncoding[A](e: Eff[Refused, A]): Eff[InvalidKey, A] = e.mapError(_ => InvalidKey.Malformed)
private def sized[A](expected: Int, got: Int)(e: => Eff[InvalidKey, A]): Eff[InvalidKey, A] =
  if expected == got then e else Eff.fail(InvalidKey.WrongLength(expected, got))
private def ecAlg(curve: EcSpec[?]): DER.Alg = curve match
  case _: P256.type => DER.Alg.EcP256
  case _: P384.type => DER.Alg.EcP384
  case _: P521.type => DER.Alg.EcP521

opaque type PublicKey[A <: Algorithm] = KeyRepr
object PublicKey:
  private[kufuli] def unsafe[A <: Algorithm](r: KeyRepr): PublicKey[A] = r
  extension [A <: Algorithm](k: PublicKey[A]) private[kufuli] def repr: KeyRepr = k

  // The seven low-order Curve25519 points (RFC 7748 section 6.1) whose scalar product is all-zero;
  // rejecting them at the shared import keeps a small-order peer unconstructible through the public
  // surface, so `agree` stays total. Byte 31's top bit is masked (the u-coordinate ignores it, RFC
  // 7748 section 5), so a non-canonical encoding of a blocklisted point cannot slip past.
  private val x25519LowOrder: List[IArray[Byte]] =
    List(
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ).map(h => IArray.from(h.grouped(2).map(b => Integer.parseInt(b, 16).toByte)))

  private def isX25519LowOrder(point: Array[Byte]): Boolean =
    point.length == 32 && x25519LowOrder.exists(entry =>
      (0 until 31).forall(i => point(i) == entry(i)) && (point(31) & 0x7f) == (entry(31) & 0x7f)
    )

  // The blocklist is only meaningful over the point the backend will actually import, so the point
  // is located by walking the encoding, and an X25519 SPKI this walk cannot reduce to exactly 32
  // subjectPublicKey octets is refused: any encoding a permissive backend accepts but kufuli cannot
  // position is one where the check reads different bytes from the import.
  private def x25519Spki(der: Slice): Either[InvalidKey, Unit] =
    DER.spkiPublicBits(der, 32).flatMap(point => if isX25519LowOrder(point.toArray) then Left(InvalidKey.WeakPoint) else Right(()))

  /** Raw Ed25519 public key (RFC 8032). */
  def parse(alg: Ed25519)(raw: Raw)(using k: EdKeys): Eff[InvalidKey, PublicKey[Ed25519]] =
    val _ = alg
    sized(32, raw.bytes.length)(onPoint(k.fromRaw(raw.slice)))

  /** Raw X25519 public key (RFC 7748); the small-order set is refused HERE, before any backend. */
  @targetName("parseRawX")
  def parse(alg: X25519)(raw: Raw)(using k: XKeys): Eff[InvalidKey, PublicKey[X25519]] =
    val _ = alg
    sized(32, raw.bytes.length):
      if isX25519LowOrder(Array.from(raw.bytes.iterator)) then Eff.fail(InvalidKey.WeakPoint)
      else onPoint(k.fromRaw(raw.slice))

  /** ML-KEM encapsulation key from the wire (the hybrid KeyShare carries it verbatim). */
  @targetName("parseRawKem")
  def parse[K <: KemAlgorithm](alg: KemSpec[K])(raw: Raw)(using k: KemKeys[K]): Eff[InvalidKey, PublicKey[K]] =
    sized(alg.publicKeyLength, raw.bytes.length)(onEncoding(k.fromRaw(raw.slice)))

  // ONE classification for an EC point wherever it appears - a bare SEC1 claim or the
  // subjectPublicKey inside an SPKI - so one encoding variant cannot earn two arms across doors.
  private def ecPointForm(curve: EcSpec[?], length: Int, prefix: Byte): Either[InvalidKey, Unit] =
    val uncompressed = 1 + 2 * curve.fieldLength
    if length == 1 + curve.fieldLength && (prefix == 2.toByte || prefix == 3.toByte) then Left(InvalidKey.Unsupported)
    else if length != uncompressed then Left(InvalidKey.WrongLength(uncompressed, length))
    else if prefix != 4.toByte then Left(InvalidKey.Malformed)
    else Right(())

  /** SEC1 point - the TLS KeyShare wire form. Uncompressed only: a well-formed COMPRESSED point is
    * a variant kufuli declines, which is [[InvalidKey.Unsupported]] and not a malformed input.
    */
  def parse[C <: EcCurve](curve: EcSpec[C])(point: SEC1)(using k: EcKeys[C]): Eff[InvalidKey, PublicKey[C]] =
    val b = point.bytes
    Eff
      .from(ecPointForm(curve, b.length, if b.length > 0 then b(0) else 0))
      .flatMap(_ => onPoint(k.fromSec1(point.slice)))

  /** RSA public key from its JWK components - the one key door built from COMPONENTS, so the one
    * that keeps `of`. The 2048-bit floor applies here, above every backend.
    */
  def of(components: RSA.Components)(using k: RsaKeys): Eff[InvalidKey, PublicKey[RSA]] =
    val n = Slice.of(Array.from(components.modulus.iterator))
    Eff.from(RSA.flooredComponents(n)).flatMap(_ => onEncoding(k.fromComponents(n, Slice.of(Array.from(components.exponent.iterator)))))

  /** SubjectPublicKeyInfo of a KNOWN family - the JwkSet, certificate-pinning and configuration
    * paths, where the algorithm is fixed by the protocol rather than discovered from the blob. The
    * blob must name that family and nothing else, exactly as the dispatching overload requires.
    */
  @targetName("parseSpkiEd")
  def parse(alg: Ed25519)(der: SPKI)(using k: EdKeys): Eff[InvalidKey, PublicKey[Ed25519]] =
    val _ = alg
    val s = der.slice
    Eff
      .from(DER.requireSpki(s, DER.Alg.Ed).flatMap(_ => DER.spkiPublicBits(s, 32)))
      .flatMap(_ => onPoint(k.fromSpki(s)))
  @targetName("parseSpkiX")
  def parse(alg: X25519)(der: SPKI)(using k: XKeys): Eff[InvalidKey, PublicKey[X25519]] =
    val _ = alg
    Eff
      .from(DER.requireSpki(der.slice, DER.Alg.X).flatMap(_ => x25519Spki(der.slice)))
      .flatMap(_ => onPoint(k.fromSpki(der.slice)))
  @targetName("parseSpkiEc")
  def parse[C <: EcCurve](curve: EcSpec[C])(der: SPKI)(using k: EcKeys[C]): Eff[InvalidKey, PublicKey[C]] =
    val s = der.slice
    Eff
      .from(
        DER
          .requireSpki(s, ecAlg(curve))
          .flatMap(_ => DER.spkiPublicBits(s).flatMap(bits => ecPointForm(curve, bits.length, if bits.length > 0 then bits(0) else 0)))
      )
      .flatMap(_ => onPoint(k.fromSpki(s)))
  @targetName("parseSpkiRsa")
  def parse(alg: RSA.type)(der: SPKI)(using k: RsaKeys): Eff[InvalidKey, PublicKey[RSA]] =
    val _ = alg
    Eff
      .from(DER.requireSpki(der.slice, DER.Alg.Rsa).flatMap(_ => RSA.flooredSpki(der.slice)))
      .flatMap(_ => onEncoding(k.fromSpki(der.slice)))

  /** SPKI of UNKNOWN algorithm: the shared bounded DER peek dispatches the WHOLE blob through the
    * TYPED doors above (one set of pre-checks, structurally shared); the caller matches the enum
    * and the bound type flows into every later op.
    */
  def parse(der: SPKI)(using
    ed: EdKeys,
    x: XKeys,
    p256: EcKeys[P256],
    p384: EcKeys[P384],
    p521: EcKeys[P521],
    rsa: RsaKeys
  ): Eff[InvalidKey, ImportedPublicKey] =
    Eff.from(DER.peekSpki(der.slice)).flatMap {
      case DER.Alg.Ed     => parse(Ed25519)(der).map(ImportedPublicKey.Ed(_))
      case DER.Alg.X      => parse(X25519)(der).map(ImportedPublicKey.X(_))
      case DER.Alg.EcP256 => parse(P256)(der).map(ImportedPublicKey.EcP256(_))
      case DER.Alg.EcP384 => parse(P384)(der).map(ImportedPublicKey.EcP384(_))
      case DER.Alg.EcP521 => parse(P521)(der).map(ImportedPublicKey.EcP521(_))
      case DER.Alg.Rsa    => parse(RSA)(der).map(ImportedPublicKey.Rsa(_))
    }
end PublicKey

opaque type PrivateKey[A <: Algorithm] = SecretRepr
object PrivateKey:
  private[kufuli] def unsafe[A <: Algorithm](bytes: Array[Byte]): PrivateKey[A] = secretAdopt(bytes)
  private[kufuli] def unsafeRepr[A <: Algorithm](r: SecretRepr): PrivateKey[A] = r
  extension [A <: Algorithm](k: PrivateKey[A])
    // The shared byte VIEW: it raises on a representation that has no bytes, so shared code can
    // never assume a key is byte-backed.
    private[kufuli] def read[B](f: Slice => B): B = secretRead(k)(f)

    // The BACKEND door: an operation reaches the key material through here whatever the
    // representation holds, exactly as a WebCrypto op reaches a CryptoKey's internal material.
    private[kufuli] def material[B](f: Slice => B): B = secretMaterial(k)(f)
    private[kufuli] def exportable: Boolean = secretExportable(k)

    /** Erase the key material in place; further use raises. Best-effort on managed runtimes. */
    def destroy: UEff[Unit] = Eff.suspend(secretDestroy(k))
  end extension

  /** PrivateKeyInfo of a KNOWN family (configuration paths where the protocol fixes it). The family
    * is bound HERE, in shared code, exactly as the SPKI doors bind it - so a family mismatch and
    * trailing bytes fail identically on every backend.
    */
  def parse(alg: Ed25519)(der: PKCS8)(using k: EdKeys): Eff[InvalidKey, PrivateKey[Ed25519]] =
    val _ = alg
    val s = der.slice
    Eff.from(DER.requirePkcs8(s, DER.Alg.Ed)).flatMap(_ => onEncoding(k.fromPkcs8(s)))
  @targetName("parsePkcs8X")
  def parse(alg: X25519)(der: PKCS8)(using k: XKeys): Eff[InvalidKey, PrivateKey[X25519]] =
    val _ = alg
    val s = der.slice
    Eff.from(DER.requirePkcs8(s, DER.Alg.X)).flatMap(_ => onEncoding(k.fromPkcs8(s)))
  @targetName("parsePkcs8Rsa")
  def parse(alg: RSA.type)(der: PKCS8)(using k: RsaKeys): Eff[InvalidKey, PrivateKey[RSA]] =
    val _ = alg
    val s = der.slice
    Eff
      .from(DER.requirePkcs8(s, DER.Alg.Rsa).flatMap(_ => RSA.flooredPkcs8(s)))
      .flatMap(_ => onEncoding(k.fromPkcs8(s)))
  @targetName("parsePkcs8Ec")
  def parse[C <: EcCurve](curve: EcSpec[C])(der: PKCS8)(using k: EcKeys[C]): Eff[InvalidKey, PrivateKey[C]] =
    val s = der.slice
    Eff.from(DER.requirePkcs8(s, ecAlg(curve))).flatMap(_ => onEncoding(k.fromPkcs8(s)))

  /** PKCS#8 of UNKNOWN algorithm (server key loading); enum dispatch through the TYPED doors,
    * exactly as for SPKI.
    */
  def parse(der: PKCS8)(using
    ed: EdKeys,
    x: XKeys,
    p256: EcKeys[P256],
    p384: EcKeys[P384],
    p521: EcKeys[P521],
    rsa: RsaKeys
  ): Eff[InvalidKey, ImportedPrivateKey] =
    Eff.from(DER.peekPkcs8(der.slice)).flatMap {
      case DER.Alg.Ed     => parse(Ed25519)(der).map(ImportedPrivateKey.Ed(_))
      case DER.Alg.X      => parse(X25519)(der).map(ImportedPrivateKey.X(_))
      case DER.Alg.EcP256 => parse(P256)(der).map(ImportedPrivateKey.EcP256(_))
      case DER.Alg.EcP384 => parse(P384)(der).map(ImportedPrivateKey.EcP384(_))
      case DER.Alg.EcP521 => parse(P521)(der).map(ImportedPrivateKey.EcP521(_))
      case DER.Alg.Rsa    => parse(RSA)(der).map(ImportedPrivateKey.Rsa(_))
    }
end PrivateKey

opaque type SecretKey[A <: SymmetricAlgorithm] = SecretRepr
object SecretKey:
  private[kufuli] def unsafe[A <: SymmetricAlgorithm](bytes: Array[Byte]): SecretKey[A] = secretAdopt(bytes)

  /** Import raw key material: length-validated, pure (no backend), copied into the guarded carrier.
    * The caller's buffer stays the caller's to wipe.
    */
  def of[A <: SymmetricAlgorithm](spec: SymmetricSpec[A])(bytes: Array[Byte]): Either[InvalidKey, SecretKey[A]] =
    spec.validate(bytes.length).map(_ => secretCopy(bytes))
  extension [A <: SymmetricAlgorithm](k: SecretKey[A])
    private[kufuli] def read[B](f: Slice => B): B = secretRead(k)(f)

    // The read guard of `read` spans the CALL alone, so a continuation that only BUILDS an effect
    // hands the view on to a runtime the guard has already released; this holds it across the
    // effect, which is what keeps a concurrent `destroy` from erasing the bytes mid-operation.
    private[kufuli] def readEff[E <: Throwable, B](f: Slice => Eff[E, B]): Eff[E, B] = secretReadEff(k)(f)
    private[kufuli] def material[B](f: Slice => B): B = secretMaterial(k)(f)
    private[kufuli] def exportable: Boolean = secretExportable(k)
    @targetName("destroySecretKey")
    def destroy: UEff[Unit] = Eff.suspend(secretDestroy(k))
end SecretKey

// Inspect-form import results - flat arms, one per family/curve. There is deliberately NO KEM
// arm: ML-KEM keys travel raw in v1 wire protocols, and excluding them keeps the dispatching
// SPKI/PKCS#8 doors available on every platform (a KEM arm would demand KemKeys instances the
// browser cannot provide). Revisit trigger: ML-KEM certificate/SPKI interop.
enum ImportedPublicKey:
  case Ed(key: PublicKey[Ed25519])
  case X(key: PublicKey[X25519])
  case EcP256(key: PublicKey[P256])
  case EcP384(key: PublicKey[P384])
  case EcP521(key: PublicKey[P521])
  case Rsa(key: PublicKey[RSA])
enum ImportedPrivateKey:
  case Ed(key: PrivateKey[Ed25519])
  case X(key: PrivateKey[X25519])
  case EcP256(key: PrivateKey[P256])
  case EcP384(key: PrivateKey[P384])
  case EcP521(key: PrivateKey[P521])
  case Rsa(key: PrivateKey[RSA])

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
  def random[A <: AeadAlgorithm](spec: AeadSpec[A])(using r: Random): UEff[Nonce[A]] =
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
    bytes.length match
      case 20 | 32 | 48 | 64 => Right(bytes.clone)
      case _                 => Left(Malformed)
  extension (d: Digest)
    def bytes: IArray[Byte] = IArray.from(d: Array[Byte])
    def hex: String = codec.Hex.encode(d: Array[Byte])

    /** Constant-time over equal lengths (a length mismatch is not itself secret). */
    def constantTimeEquals(o: Digest): Boolean = Slice.of(d).constantTimeEquals(Slice.of(o))
end Digest

/** A signature (or MAC tag) over algorithm `A`: 64 raw bytes for Ed25519, fixed-width `r || s` for
  * ECDSA (the JOSE-native form), the signature octets for RSA, the tag for HMAC. Construct from the
  * primary octets via `of`; ECDSA DER interop via `parse`/`der` over [[Signature.Der]].
  */
opaque type Signature[A <: Algorithm] = Array[Byte]
object Signature:
  private[kufuli] def unsafe[A <: Algorithm](bytes: Array[Byte]): Signature[A] = bytes

  /** The DER form of an ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) as a CLAIM about
    * bytes in hand - the one two-encoding family gets the one marked signature format, so key
    * exports cannot feed signature doors and the DER round trip is typed. Nested here: "the DER
    * encoding of a signature" means nothing outside the family.
    */
  opaque type Der = IArray[Byte]
  object Der:
    def apply(bytes: IArray[Byte]): Der = bytes
    def apply(bytes: Slice): Der = IArray.unsafeFromArray(bytes.toArray)
    extension (d: Der) def bytes: IArray[Byte] = d

  def of(alg: Ed25519)(bytes: Array[Byte]): Either[Malformed, Signature[Ed25519]] =
    val _ = alg
    if bytes.length == 64 then Right(bytes.clone) else Left(Malformed)
  @targetName("ofEc")
  def of[C <: EcCurve](curve: EcSpec[C])(bytes: Array[Byte]): Either[Malformed, Signature[C]] =
    if bytes.length == 2 * curve.fieldLength then Right(bytes.clone) else Left(Malformed)
  @targetName("ofMac")
  def of[H <: MacAlgorithm](alg: MacSpec[H])(bytes: Array[Byte]): Either[Malformed, Signature[H]] =
    if bytes.length == alg.outLength then Right(bytes.clone) else Left(Malformed)

  /** RSA signature octets (length is validated against the modulus at verify, by the backend). */
  @targetName("ofRsa")
  def of(alg: RSA.type)(bytes: Array[Byte]): Either[Malformed, Signature[RSA]] =
    val _ = alg
    if bytes.nonEmpty then Right(bytes.clone) else Left(Malformed)

  /** DER to raw conversion for the ECDSA wire forms (TLS and X.509 carry the DER
    * `SEQUENCE { INTEGER r, INTEGER s }`; JOSE and this library carry fixed-width `r || s`). Pure,
    * bounded, and strict, so one signature has exactly one accepted encoding: a trailing byte, a
    * length or INTEGER not in its shortest form, a negative INTEGER, or a value wider than the
    * field is [[Malformed]].
    */
  def parse[C <: EcCurve](curve: EcSpec[C])(der: Der): Either[Malformed, Signature[C]] =
    ecdsaDerToRaw(Slice.of(IArray.genericWrapArray(der: IArray[Byte]).toArray), curve.fieldLength).map(unsafe[C]).left.map(_ => Malformed)

  private[kufuli] def ecdsaDerToRaw(der: Slice, fieldLength: Int): Either[InvalidKey, Array[Byte]] =
    for
      seq <- DER.read(der, 0, 0x30)
      // Bytes after the SEQUENCE, or between `s` and the SEQUENCE's end, would give one signature
      // many DER spellings - forgeable identity wherever a consumer keys a replay cache or an audit
      // fingerprint on the encoded form.
      _ <- if seq.next == der.length then Right(()) else Left(InvalidKey.Malformed)
      r <- DER.read(der, seq.contentOff, 0x02)
      s <- DER.read(der, r.next, 0x02)
      _ <- if s.next == seq.next then Right(()) else Left(InvalidKey.Malformed)
      rb <- ecdsaField(der, r, fieldLength)
      sb <- ecdsaField(der, s, fieldLength)
    yield rb ++ sb

  // One DER INTEGER (r or s) to a fixed-width big-endian field. DER admits exactly one encoding of
  // a value: no empty content, no leading 0x00 except to clear a set sign bit, and a magnitude
  // within the field.
  private def ecdsaField(der: Slice, tlv: DER.Tlv, fieldLength: Int): Either[InvalidKey, Array[Byte]] =
    val raw = der.slice(tlv.contentOff, tlv.next).toArray
    val padded = raw.length > 1 && (raw(0) & 0xff) == 0x00
    if raw.isEmpty || (raw(0) & 0x80) != 0 || (padded && (raw(1) & 0x80) == 0) then Left(InvalidKey.Malformed)
    else
      val magLen = if padded then raw.length - 1 else raw.length
      if magLen > fieldLength then Left(InvalidKey.Malformed)
      else
        val out = new Array[Byte](fieldLength)
        Array.copy(raw, raw.length - magLen, out, fieldLength - magLen, magLen)
        Right(out)
  end ecdsaField

  // Fixed-width big-endian `r || s` to `SEQUENCE { INTEGER r, INTEGER s }` with minimal integers.
  private[kufuli] def ecdsaRawToDer(raw: Array[Byte]): Array[Byte] =
    val fieldLength = raw.length / 2
    DER.sequence(minimalInteger(raw, 0, fieldLength), minimalInteger(raw, fieldLength, fieldLength))

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
    DER.tlv(0x02, body)

  /** A resource-scoped handle for signing many messages under one prepared key. */
  trait Signer[A <: Algorithm]:
    def sign(data: Slice): UEff[Signature[A]]

  /** A resource-scoped handle for verifying many messages under one prepared key. */
  trait Verifier[A <: Algorithm]:
    def verify(data: Slice, sig: Signature[A]): Eff[SignatureRejected, Unit]

  extension [A <: Algorithm](sig: Signature[A])
    private[kufuli] def repr: Array[Byte] = sig

    /** The signature octets, copied out. */
    def bytes: IArray[Byte] = IArray.from(sig: Array[Byte])
  extension [C <: EcCurve](sig: Signature[C])
    /** The DER form of an ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }` with minimal
      * integers (TLS/X.509 wire form). Feeds `parse` for the typed round trip.
      */
    def der: Der = Der(IArray.from(ecdsaRawToDer(sig: Array[Byte])))
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
  def parse[A <: AeadAlgorithm](spec: AeadSpec[A])(bytes: Array[Byte]): Either[Malformed, SealedBox[A]] =
    val min = 1 + spec.nonceLength + spec.tagLength
    if bytes.length >= min && bytes(0) == 1.toByte then Right(bytes.clone)
    else if bytes.length >= min + 4 && bytes(0) == 2.toByte then Right(bytes.clone)
    else Left(Malformed)
  extension [A <: AeadAlgorithm](box: SealedBox[A])
    private[kufuli] def repr: Array[Byte] = box

    /** The stored form, copied out. */
    def bytes: IArray[Byte] = IArray.from(box: Array[Byte])
end SealedBox

// One typeclass per family. Instances live in the per-unit platform trait each companion extends
// (implicit scope, zero imports); instance PRESENCE is the backend's capability truth, and the
// @implicitNotFound message names it.
//
// Each family trait is a public TYPE with a `private[kufuli]` METHOD surface: a using-clause still
// names it and a consumer can still summon and pass the instance, but the primitive is callable
// only from inside kufuli. Every invariant kufuli advertises lives in the shared wrapper above the
// primitive - budgets, the HKDF counter bound, the RFC 3394 length rule, the X25519 blocklist - so
// making the wrapper the sole public path is what makes those invariants unbypassable rather than
// merely present. Terminal consumer handles (`Signature.Signer`/`Signature.Verifier`, `Hasher`, `Cipher`) are
// NOT part of this seam: they carry no wrapper and sealing them would remove a capability.
// A backend override must repeat the qualifier - a plain `def` widens the member back to public
// through that instance's own type.

/** The backend CSPRNG. */
@implicitNotFound("this kufuli backend provides no CSPRNG (report this artifact pairing as a bug)")
trait Random:
  private[kufuli] def bytes(n: Int): UEff[Slice]
  private[kufuli] def fill(dst: Slice): UEff[Unit]
object Random extends RandomPlatform:
  /** Fresh CSPRNG bytes (PKCE verifiers, salts, ids). */
  def bytes(n: Int)(using r: Random): UEff[Slice] = r.bytes(n)

  /** Fills a caller-owned buffer with CSPRNG bytes. */
  def fill(dst: Slice)(using r: Random): UEff[Unit] = r.fill(dst)

@implicitNotFound("${A} is not provided by this kufuli backend (XChaCha and GCM-SIV are Native-only; the browser lacks ChaCha)")
trait AEAD[A <: AeadAlgorithm]:
  private[kufuli] def seal(key: SecretKey[A], nonce: Nonce[A], aad: Slice, plaintext: Slice): UEff[Slice]
  private[kufuli] def open(key: SecretKey[A], nonce: Nonce[A], aad: Slice, ciphertext: Slice): Eff[AuthFailed, Slice]
object AEAD extends AeadPlatform

/** Whole-message AEAD over the key: the protocol-shaped tier (PASETO-class constructions own their
  * wire layout, so the versioned [[SealedBox]] does not fit them). The nonce can only be
  * [[Nonce.random]]; the zero-copy, budget-tracked record path is the [[Cipher]] handle.
  */
extension [A <: AeadAlgorithm](key: SecretKey[A])
  def seal(nonce: Nonce[A], aad: Slice, plaintext: Slice)(using a: AEAD[A]): UEff[Slice] =
    a.seal(key, nonce, aad, plaintext)
  def open(nonce: Nonce[A], aad: Slice, ciphertext: Slice)(using a: AEAD[A]): Eff[AuthFailed, Slice] =
    a.open(key, nonce, aad, ciphertext)

@implicitNotFound("HMAC ${H} is not provided by this kufuli backend")
trait MAC[H <: MacAlgorithm]:
  // There is deliberately no backend verify: verification is recompute plus the one audited
  // constant-time compare, in shared code, so no backend can get the no-oracle rule wrong.
  private[kufuli] def sign(key: SecretKey[H], data: Slice): UEff[Signature[H]]

  // The default costs nothing; a backend overrides it where key preparation is genuinely expensive
  // (JCA key objects, WebCrypto imports). The three `prepared` defaults are named apart because the
  // browser's KeyRepr is a union: its members erase to one signature, and the JS linker then
  // dispatches one trait's default body for another's.
  @targetName("preparedMac")
  private[kufuli] def prepared(key: SecretKey[H]): EffResource[Nothing, Signature.Signer[H]] =
    Resource.pure(
      new Signature.Signer[H]:
        def sign(data: Slice): UEff[Signature[H]] = MAC.this.sign(key, data)
    )
end MAC
object MAC extends MacPlatform

// The ONE audited constant-time comparison site, shared by every MAC-verify surface (key, ring,
// and prepared handles). (Signature is transparently Array[Byte] in this file.)
private def ctCheck[A <: Algorithm](computed: Signature[A], sig: Signature[A]): Eff[SignatureRejected, Unit] =
  Eff.raiseUnless(Slice.of(computed).constantTimeEquals(Slice.of(sig)))(SignatureRejected)

private def macVerify[H <: MacAlgorithm](m: MAC[H], key: SecretKey[H], data: Slice, sig: Signature[H]): Eff[SignatureRejected, Unit] =
  m.sign(key, data).flatMap(ctCheck(_, sig))

extension [H <: MacAlgorithm](key: SecretKey[H])
  @targetName("macSign")
  def sign(data: Slice)(using m: MAC[H]): UEff[Signature[H]] = m.sign(key, data)

  /** Constant-time verification through the shared compare site. */
  @targetName("macVerifyOp")
  def verify(data: Slice, sig: Signature[H])(using m: MAC[H]): Eff[SignatureRejected, Unit] =
    macVerify(m, key, data, sig)
  @targetName("macSigner")
  def signer(using m: MAC[H]): EffResource[Nothing, Signature.Signer[H]] = m.prepared(key)
  @targetName("macVerifier")
  def verifier(using m: MAC[H]): EffResource[Nothing, Signature.Verifier[H]] =
    m.prepared(key).map { s =>
      new Signature.Verifier[H]:
        def verify(data: Slice, sig: Signature[H]): Eff[SignatureRejected, Unit] =
          s.sign(data).flatMap(ctCheck(_, sig))
    }
end extension

@implicitNotFound("signing for ${A} is not provided by this kufuli backend")
trait Signing[A <: SignatureAlgorithm]:
  private[kufuli] def sign(key: PrivateKey[A], data: Slice, scheme: Scheme[A]): UEff[Signature[A]]
  @targetName("preparedSigning")
  private[kufuli] def prepared(key: PrivateKey[A], scheme: Scheme[A]): EffResource[Nothing, Signature.Signer[A]] =
    Resource.pure(
      new Signature.Signer[A]:
        def sign(data: Slice): UEff[Signature[A]] = Signing.this.sign(key, data, scheme)
    )
object Signing extends SigningPlatform

@implicitNotFound("signature verification for ${A} is not provided by this kufuli backend")
trait Verifying[A <: SignatureAlgorithm]:
  private[kufuli] def verify(key: PublicKey[A], data: Slice, sig: Signature[A], scheme: Scheme[A]): Eff[SignatureRejected, Unit]
  @targetName("preparedVerifying")
  private[kufuli] def prepared(key: PublicKey[A], scheme: Scheme[A]): EffResource[Nothing, Signature.Verifier[A]] =
    Resource.pure(
      new Signature.Verifier[A]:
        def verify(data: Slice, sig: Signature[A]): Eff[SignatureRejected, Unit] =
          Verifying.this.verify(key, data, sig, scheme)
    )
object Verifying extends VerifyingPlatform

extension (k: PrivateKey[Ed25519])
  @targetName("edSign")
  def sign(data: Slice)(using s: Signing[Ed25519]): UEff[Signature[Ed25519]] = s.sign(k, data, Ed)
  @targetName("edSigner")
  def signer(using s: Signing[Ed25519]): EffResource[Nothing, Signature.Signer[Ed25519]] = s.prepared(k, Ed)
extension (k: PublicKey[Ed25519])
  @targetName("edVerify")
  def verify(data: Slice, sig: Signature[Ed25519])(using v: Verifying[Ed25519]): Eff[SignatureRejected, Unit] =
    v.verify(k, data, sig, Ed)
  @targetName("edVerifier")
  def verifier(using v: Verifying[Ed25519]): EffResource[Nothing, Signature.Verifier[Ed25519]] = v.prepared(k, Ed)

extension [C <: EcCurve](k: PrivateKey[C])
  /** Sign with the curve's paired hash (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 - the JOSE/TLS
    * pairing).
    */
  @targetName("ecSign")
  def sign(data: Slice)(using s: Signing[C], spec: EcSpec[C]): UEff[Signature[C]] =
    s.sign(k, data, ECDSA(spec.hash))

  /** Sign under an explicit hash (cross-paired legacy interop). */
  @targetName("ecSignHash")
  def sign(data: Slice, hash: Sha2)(using s: Signing[C]): UEff[Signature[C]] =
    s.sign(k, data, ECDSA(hash))
  @targetName("ecSigner")
  def signer(using s: Signing[C], spec: EcSpec[C]): EffResource[Nothing, Signature.Signer[C]] = s.prepared(k, ECDSA(spec.hash))
  @targetName("ecSignerHash")
  def signer(hash: Sha2)(using s: Signing[C]): EffResource[Nothing, Signature.Signer[C]] = s.prepared(k, ECDSA(hash))
end extension
extension [C <: EcCurve](k: PublicKey[C])
  @targetName("ecVerify")
  def verify(data: Slice, sig: Signature[C])(using v: Verifying[C], spec: EcSpec[C]): Eff[SignatureRejected, Unit] =
    v.verify(k, data, sig, ECDSA(spec.hash))

  /** Verify under an explicit hash - the X.509 case where the certificate names a hash the curve
    * pairing would not choose.
    */
  @targetName("ecVerifyHash")
  def verify(data: Slice, sig: Signature[C], hash: Sha2)(using v: Verifying[C]): Eff[SignatureRejected, Unit] =
    v.verify(k, data, sig, ECDSA(hash))
  @targetName("ecVerifier")
  def verifier(using v: Verifying[C], spec: EcSpec[C]): EffResource[Nothing, Signature.Verifier[C]] = v.prepared(k, ECDSA(spec.hash))
  @targetName("ecVerifierHash")
  def verifier(hash: Sha2)(using v: Verifying[C]): EffResource[Nothing, Signature.Verifier[C]] = v.prepared(k, ECDSA(hash))
end extension

extension (k: PrivateKey[RSA])
  /** Sign under the named padding (PSS or PKCS#1 v1.5). RSA has no safe default - the choice is
    * explicit, always.
    */
  @targetName("rsaSign")
  def sign(data: Slice, scheme: Scheme[RSA])(using s: Signing[RSA]): UEff[Signature[RSA]] =
    s.sign(k, data, scheme)
  @targetName("rsaSigner")
  def signer(scheme: Scheme[RSA])(using s: Signing[RSA]): EffResource[Nothing, Signature.Signer[RSA]] = s.prepared(k, scheme)
extension (k: PublicKey[RSA])
  @targetName("rsaVerify")
  def verify(data: Slice, sig: Signature[RSA], scheme: Scheme[RSA])(using v: Verifying[RSA]): Eff[SignatureRejected, Unit] =
    v.verify(k, data, sig, scheme)
  @targetName("rsaVerifier")
  def verifier(scheme: Scheme[RSA])(using v: Verifying[RSA]): EffResource[Nothing, Signature.Verifier[RSA]] = v.prepared(k, scheme)

@implicitNotFound("key agreement for ${A} is not provided by this kufuli backend")
trait Agreement[A <: AgreementAlgorithm]:
  // Total: peer keys are validated at import and generated keys are valid by construction.
  private[kufuli] def agree(priv: PrivateKey[A], pub: PublicKey[A]): UEff[SharedSecret]
object Agreement extends AgreementPlatform

extension [A <: AgreementAlgorithm](k: PrivateKey[A])
  def agree(peer: PublicKey[A])(using a: Agreement[A]): UEff[SharedSecret] = a.agree(k, peer)

@implicitNotFound("${K} is not provided by this kufuli backend (ML-KEM is JVM >= 25, Native, and Node >= 24; the browser lacks it)")
trait KEM[K <: KemAlgorithm]:
  private[kufuli] def encapsulate(pub: PublicKey[K]): UEff[Encapsulated[K]]

  // Total: FIPS 203 implicit rejection returns a pseudorandom secret for a forged ciphertext.
  private[kufuli] def decapsulate(priv: PrivateKey[K], ct: KemCiphertext[K]): UEff[SharedSecret]
object KEM extends KemPlatform

extension [K <: KemAlgorithm](pub: PublicKey[K]) def encapsulate(using k: KEM[K]): UEff[Encapsulated[K]] = k.encapsulate(pub)
extension [K <: KemAlgorithm](priv: PrivateKey[K])
  def decapsulate(ct: KemCiphertext[K])(using k: KEM[K]): UEff[SharedSecret] = k.decapsulate(priv, ct)

@implicitNotFound("key wrapping for ${W} is not provided by this kufuli backend (the browser lacks AES-KWP)")
trait Wrap[W <: WrapAlgorithm]:
  private[kufuli] def wrap(kek: SecretKey[W], target: Slice): UEff[Slice]
  private[kufuli] def unwrap(kek: SecretKey[W], wrapped: Slice): Eff[UnwrapFailed, Slice]
object Wrap extends WrapPlatform

extension [W <: WrapAlgorithm](kek: SecretKey[W])
  /** Wrap `target` under this key-encryption key. Plain AES-KW rejects lengths that are not a
    * multiple of 8 with `NotWrappable` (reachable via variable-length HMAC keys); a KWP algorithm
    * accepts any length. RFC 3394 blobs carry no algorithm binding - binding wrapped material to
    * its algorithm is the caller's storage schema. Escrow goes through here, never raw bytes.
    */
  def wrap[A <: SymmetricAlgorithm](target: SecretKey[A])(using w: Wrap[W], spec: WrapSpec[W]): Eff[NotWrappable, Slice] =
    SecretKey.readEff(target) { t =>
      if !spec.padded && t.length % 8 != 0 then Eff.fail(NotWrappable)
      else w.wrap(kek, t)
    }

  /** Unwrap to a key of the named algorithm; the unwrapped length is validated against the spec
    * (the typed channel is sound: both arms are proper classes).
    */
  def unwrap[A <: SymmetricAlgorithm](wrapped: Slice, as: SymmetricSpec[A])(using
    w: Wrap[W]
  ): Eff[UnwrapFailed | InvalidKey, SecretKey[A]] =
    w.unwrap(kek, wrapped).flatMap { pt =>
      val bytes = pt.toArray
      pt.wipe()
      // The material is genuinely unwrapped by this point: a length the spec refuses ends the
      // operation but does not un-recover the bytes, so the copy is erased on that arm too.
      val validated: Eff[UnwrapFailed | InvalidKey, SecretKey[A]] =
        Eff.from(as.validate(bytes.length) match
          case Right(_) => Right(SecretKey.unsafe[A](bytes))
          case Left(e)  =>
            Slice.of(bytes).wipe()
            Left(e))
      validated
    }
end extension

@implicitNotFound("HKDF/PBKDF2 is not provided by this kufuli backend")
trait KDF:
  private[kufuli] def extract(hash: Sha2, salt: Slice, ikm: Slice): UEff[PRK]
  private[kufuli] def expand(hash: Sha2, prk: PRK, info: Slice, length: Int): UEff[Slice]
  private[kufuli] def pbkdf2(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int): UEff[Slice]
object KDF extends KdfPlatform

/** HKDF (RFC 5869) with Extract and Expand exposed SEPARATELY, as the TLS/QUIC key schedule needs.
  * Label layouts are owned here (shared, KAT-verified once); backends provide only the primitives.
  */
object HKDF:
  def extract(hash: Sha2, salt: Slice, ikm: Slice)(using k: KDF): UEff[PRK] = k.extract(hash, salt, ikm)

  /** Extract from a [[SharedSecret]] without exposing it - the agree-then-derive path. */
  @targetName("extractSecret")
  def extract(hash: Sha2, salt: Slice, ikm: SharedSecret)(using KDF): UEff[PRK] = extractFrom(hash, salt, ikm)

  // The SharedSecret-extract body, non-overloaded: internal callers route through it so no
  // same-file reference names the overloaded `extract` whose sibling carries @targetName, which
  // Scaladoc cannot resolve at TASTy read.
  private[kufuli] def extractFrom(hash: Sha2, salt: Slice, ikm: SharedSecret)(using k: KDF): UEff[PRK] =
    ikm.useEff(s => k.extract(hash, salt, s))

  /** Expand to `length` raw octets. The result is derived key material in an owned buffer the
    * CALLER erases when it is done with it; [[expandKey]] and [[expandLabelKey]] hand it to the
    * guarded carrier instead and need no such care.
    */
  def expand(hash: Sha2, prk: PRK, info: Slice, length: Int)(using k: KDF): UEff[Slice] =
    require(length > 0 && length <= 255 * hash.length, "HKDF output length out of range")
    k.expand(hash, prk, info, length)

  /** Target-typed expansion: the algorithm fixes the length - no `len` to get wrong - and the raw
    * intermediate is wiped.
    */
  def expandKey[A <: SymmetricAlgorithm](hash: Sha2, prk: PRK, info: Slice, as: SymmetricSpec[A])(using
    k: KDF
  ): UEff[SecretKey[A]] =
    k.expand(hash, prk, info, as.keyLength).map { out =>
      val bytes = out.toArray
      out.wipe()
      SecretKey.unsafe[A](bytes)
    }

  /** HKDF-Expand-Label (RFC 8446 section 7.1, also QUIC RFC 9001), owned here so the byte layout is
    * KAT-verified once, never hand-rolled per protocol. QUIC version constants stay downstream.
    */
  def expandLabel(hash: Sha2, prk: PRK, label: String, context: Slice, length: Int)(using KDF): UEff[Slice] =
    require(label.length <= 249 && context.length <= 255, "expand-label bounds")
    expand(hash, prk, hkdfLabel(label, context, length), length)
  def expandLabelKey[A <: SymmetricAlgorithm](hash: Sha2, prk: PRK, label: String, context: Slice, as: SymmetricSpec[A])(using
    KDF
  ): UEff[SecretKey[A]] =
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
  def derive(hash: Sha2, password: Slice, salt: Slice, iterations: Int, length: Int)(using k: KDF): UEff[Slice] =
    require(iterations >= 1 && length > 0 && length <= 255 * hash.length, "PBKDF2 parameters")
    k.pbkdf2(hash, password, salt, iterations, length)
  def deriveKey[A <: SymmetricAlgorithm](hash: Sha2, password: Slice, salt: Slice, iterations: Int, as: SymmetricSpec[A])(using
    k: KDF
  ): UEff[SecretKey[A]] =
    require(iterations >= 1, "PBKDF2 iterations")
    k.pbkdf2(hash, password, salt, iterations, as.keyLength).map { out =>
      val bytes = out.toArray
      out.wipe()
      SecretKey.unsafe[A](bytes)
    }
end PBKDF2

@implicitNotFound("${D} is not provided by this kufuli backend")
trait Hash[D <: HashAlgorithm]:
  private[kufuli] def digest(data: Slice): UEff[Digest]
object Hash extends HashPlatform

@implicitNotFound(
  "this kufuli backend cannot hash synchronously (WebCrypto is async-only): incremental hashing is unavailable in the browser artifact"
)
trait Hashing[D <: HashAlgorithm]:
  private[kufuli] def hasher: EffResource[Nothing, Hasher]
object Hashing extends HashingPlatform

/** A synchronous, single-fibre incremental hash. `digest` SNAPSHOTS without consuming the context -
  * the TLS transcript shape.
  */
trait Hasher:
  def update(data: Slice): Unit
  def digest: Digest

@implicitNotFound("RSA-OAEP is not provided by this kufuli backend")
trait OAEP:
  private[kufuli] def encrypt(key: PublicKey[RSA], plaintext: Slice, scheme: RsaOaep): UEff[Slice]
  private[kufuli] def decrypt(key: PrivateKey[RSA], ciphertext: Slice, scheme: RsaOaep): Eff[AuthFailed, Slice]
object OAEP extends OaepPlatform

extension (k: PublicKey[RSA])
  /** RSA-OAEP encrypt. Total: an oversized plaintext is static arithmetic - a defect, not data. */
  @targetName("rsaEncrypt")
  def encrypt(plaintext: Slice, scheme: RsaOaep)(using o: OAEP): UEff[Slice] = o.encrypt(k, plaintext, scheme)
extension (k: PrivateKey[RSA])
  /** RSA-OAEP decrypt. The error is deliberately opaque and failure timing uniform (the Manger
    * countermeasure) - a backend contract. There is no PKCS#1 decryption anywhere.
    */
  @targetName("rsaDecrypt")
  def decrypt(ciphertext: Slice, scheme: RsaOaep)(using o: OAEP): Eff[AuthFailed, Slice] =
    o.decrypt(k, ciphertext, scheme)

// Shared box assembly: header || aad is the associated data, so a box's version and routing are
// AUTHENTICATED, not advisory (executed: re-heading a valid box refuses to open).

private def sealBox[A <: AeadAlgorithm](key: SecretKey[A], id: Option[KeyId], aad: Slice, plaintext: Slice)(using
  a: AEAD[A],
  r: Random,
  spec: AeadSpec[A]
): UEff[SealedBox[A]] =
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
  a: AEAD[A],
  spec: AeadSpec[A]
): Eff[AuthFailed, Slice] =
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
  def seal(plaintext: Slice)(using AEAD[A], Random, AeadSpec[A]): UEff[SealedBox[A]] = key.seal(plaintext, Slice.empty)
  def seal(plaintext: Slice, aad: Slice)(using AEAD[A], Random, AeadSpec[A]): UEff[SealedBox[A]] =
    sealBox(key, None, aad, plaintext)
  def open(box: SealedBox[A])(using AEAD[A], AeadSpec[A]): Eff[AuthFailed, Slice] = key.open(box, Slice.empty)
  def open(box: SealedBox[A], aad: Slice)(using AEAD[A], AeadSpec[A]): Eff[AuthFailed, Slice] =
    openBox(key, box, aad)

/** Per-key AEAD usage limits, INCLUDING the decrypt-failure budget (RFC 9001 forgery limit
  * mirroring the confidentiality limit). Non-positive limits are a defect.
  */
final case class AeadLimits(encryptions: Long, bytes: Long, decryptFailures: Long) derives CanEqual:
  require(encryptions > 0 && bytes > 0 && decryptFailures > 0, "AEAD limits must be positive")
object AeadLimits:
  /** The floor shared by the 96-bit-nonce tier (AES-GCM, GCM-SIV, CBC-HS): SP 800-38D section 8.3
    * caps invocations at 2^32 for a random 96-bit IV, and the forgery budget sits well inside RFC
    * 9001 section 6.6's AES-GCM integrity limit.
    */
  val default: AeadLimits = AeadLimits(1L << 32, 1L << 50, 1L << 36)

  /** ChaCha20-Poly1305 and XChaCha20-Poly1305: RFC 9001 section 6.6 lifts the confidentiality limit
    * beyond any realistic message count (2^62); the forgery limit stays the Poly1305 bound.
    */
  val chaCha: AeadLimits = AeadLimits(1L << 62, 1L << 62, 1L << 36)

/** Remaining budget, observable for PROACTIVE key update ahead of the limit (RFC 9001 section 6). */
final case class AeadBudget(encryptions: Long, bytes: Long, decryptFailures: Long) derives CanEqual

/** The per-record AEAD machine: synchronous `Either` ops, so a loop-thread codec calls them inline
  * (`Eff.delay` lifts them into the typed effect for free), over borrowed `Slice`s it never
  * retains, with the nonce explicit in both directions and derived per record by [[Nonce.xorInto]]
  *   - a TLS or QUIC nonce is never on the wire.
  *
  * A `Cipher` is a SINGLE-FIBRE handle and concurrent use is unspecified: the engine beneath it is
  * one cipher context per key, which interleaved calls corrupt whatever the budget counters do.
  * [[SecretKey]] and [[Keyring]] are the shareable tier - acquire one `Cipher` per fibre or
  * connection.
  *
  * Budget accounting is shared code over a backend [[Cipher.Engine]], so no backend can mis-count a
  * limit.
  *
  * @example `c.encrypt(out, plaintext, aad, nonce).map(n => socket.write(out.take(n)))`
  */
trait Cipher[A <: AeadAlgorithm]:
  /** Seals `src`, writing `ct || tag` at `dst`'s start; returns the bytes written. */
  def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[BudgetExhausted, Int]

  /** Opens `src` (`ct || tag`), writing the plaintext at `dst`'s start; returns the bytes written.
    * A failure leaves no plaintext in `dst`: the engines decrypt before they authenticate, and a
    * `Left` carries no length with which a caller could tell that the buffer had been touched.
    */
  def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed | BudgetExhausted, Int]

  /** Remaining budget, for a proactive key update ahead of the limit. */
  def budget: AeadBudget
end Cipher

object Cipher:
  /** The backend's raw per-key synchronous engine (on aws-lc: one const `EVP_AEAD_CTX` for the
    * handle's lifetime). No budgets and no argument validation - both are shared code in the
    * [[Cipher]] wrapper, which pre-validates every buffer.
    */
  trait Engine[A <: AeadAlgorithm]:
    private[kufuli] def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Int
    private[kufuli] def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed, Int]

@implicitNotFound("a synchronous record engine for ${A} is not provided by this kufuli backend (WebCrypto is async-only: the record Cipher is unavailable in the browser artifact)")
trait Ciphering[A <: AeadAlgorithm]:
  private[kufuli] def engine(key: SecretKey[A]): EffResource[Nothing, Cipher.Engine[A]]
object Ciphering extends CipheringPlatform

// The one audited accounting site. Encrypt charges the confidentiality budgets (invocations AND
// bytes) up front; decrypt charges only FAILURES (the forgery limit) and refuses once spent.
final private class Budgeted[A <: AeadAlgorithm](engine: Cipher.Engine[A], spec: AeadSpec[A], limits: AeadLimits) extends Cipher[A]:
  // Runs per record on the loop thread; the engine beneath is one cipher context per key, which
  // interleaved calls corrupt whatever the counters do.
  private var encrypts = limits.encryptions // scalafix:ok DisableSyntax.var
  private var octets = limits.bytes // scalafix:ok DisableSyntax.var
  private var failures = limits.decryptFailures // scalafix:ok DisableSyntax.var
  def encrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[BudgetExhausted, Int] =
    require(nonce.length == spec.nonceLength, "nonce length")
    require(dst.length >= src.length + spec.tagLength, "dst capacity")
    if encrypts <= 0 || octets < src.length then Left(BudgetExhausted)
    else
      encrypts -= 1
      octets -= src.length.toLong
      Right(engine.encrypt(dst, src, aad, nonce))
  def decrypt(dst: Slice, src: Slice, aad: Slice, nonce: Slice): Either[AuthFailed | BudgetExhausted, Int] =
    require(nonce.length == spec.nonceLength, "nonce length")
    if failures <= 0 then Left(BudgetExhausted)
    else if src.length < spec.tagLength then
      failures -= 1
      Left(AuthFailed)
    else
      require(dst.length >= src.length - spec.tagLength, "dst capacity")
      engine.decrypt(dst, src, aad, nonce) match
        case l @ Left(_) =>
          failures -= 1
          l
        case r => r
  end decrypt
  def budget: AeadBudget = AeadBudget(math.max(0L, encrypts), math.max(0L, octets), math.max(0L, failures))
end Budgeted

extension [A <: AeadAlgorithm](key: SecretKey[A])
  /** Acquire a per-record [[Cipher]] with the algorithm's default limits. */
  def cipher(using c: Ciphering[A], spec: AeadSpec[A]): EffResource[Nothing, Cipher[A]] = key.cipher(spec.defaultLimits)

  /** Acquire a per-record [[Cipher]] with explicit limits. */
  def cipher(limits: AeadLimits)(using c: Ciphering[A], spec: AeadSpec[A]): EffResource[Nothing, Cipher[A]] =
    c.engine(key).map(e => new Budgeted(e, spec, limits))

/** An identifier for a key within a [[Keyring]]. Ids come from configuration - data - so ring
  * construction returns `Either` and uniqueness is the only rule.
  */
opaque type KeyId = Int
object KeyId:
  def apply(value: Int): KeyId = value
  extension (id: KeyId) def value: Int = id
  given CanEqual[KeyId, KeyId] = CanEqual.derived

/** An immutable ring of keys of ONE algorithm, making rotation a value: seal/sign under the
  * primary, open/verify anything the ring still holds. A bare carrier over any key family - the
  * per-family operations are presence-gated top-level extensions. There is deliberately no
  * ring-level `destroy`: rings share key instances across rotations - keys retire individually.
  */
final class Keyring[A <: SymmetricAlgorithm] private (
  private[kufuli] val primaryId: KeyId,
  private[kufuli] val primary: SecretKey[A],
  private[kufuli] val others: List[(KeyId, SecretKey[A])]
)
object Keyring:
  def of[A <: SymmetricAlgorithm](primary: (KeyId, SecretKey[A]), others: (KeyId, SecretKey[A])*): Either[DuplicateKeyId, Keyring[A]] =
    val ids = primary._1 :: others.map(_._1).toList
    if ids.distinct.length != ids.length then Left(DuplicateKeyId)
    else Right(new Keyring(primary._1, primary._2, others.toList))
  extension [A <: SymmetricAlgorithm](ring: Keyring[A])
    /** A ring with `newPrimary` as primary; its id must be new. The old primary stays held. */
    def rotated(newPrimary: (KeyId, SecretKey[A])): Either[DuplicateKeyId, Keyring[A]] =
      if ring.all.exists(_._1 == newPrimary._1) then Left(DuplicateKeyId)
      else Right(new Keyring(newPrimary._1, newPrimary._2, (ring.primaryId, ring.primary) :: ring.others))
    private[kufuli] def all: List[(KeyId, SecretKey[A])] = (ring.primaryId, ring.primary) :: ring.others
    private[kufuli] def find(id: KeyId): Option[SecretKey[A]] =
      ring.all.collectFirst { case (i, k) if i == id => k }
end Keyring

// Ring operations live at the top level with every other family extension (companion-nested ring
// ops would shadow the same-named key extensions).
extension [A <: AeadAlgorithm](ring: Keyring[A])
  @targetName("ringSeal")
  def seal(plaintext: Slice)(using AEAD[A], Random, AeadSpec[A]): UEff[SealedBox[A]] = ring.seal(plaintext, Slice.empty)
  @targetName("ringSealAad")
  def seal(plaintext: Slice, aad: Slice)(using AEAD[A], Random, AeadSpec[A]): UEff[SealedBox[A]] =
    sealBox(ring.primary, Some(ring.primaryId), aad, plaintext)

  /** Opens a ring (version 2) box by its AUTHENTICATED key id; a pre-ring (version 1) box opens by
    * bounded trial - the AEAD tag is the check - so adopting a ring needs no re-encryption. An
    * unknown id is indistinguishable from a forgery, by design.
    */
  @targetName("ringOpen")
  def open(box: SealedBox[A])(using AEAD[A], AeadSpec[A]): Eff[AuthFailed, Slice] = ring.open(box, Slice.empty)
  @targetName("ringOpenAad")
  def open(box: SealedBox[A], aad: Slice)(using AEAD[A], AeadSpec[A]): Eff[AuthFailed, Slice] =
    val b: Array[Byte] = box
    if b(0) == 2.toByte then
      ring.find(KeyId(Slice.of(b).readBE[Int](1))) match
        case Some(k) => openBox(k, box, aad)
        case None    => Eff.fail(AuthFailed)
    else ring.all.map((_, k) => openBox(k, box, aad)).reduce((acc, next) => acc.catchAll(_ => next))
end extension

extension [H <: MacAlgorithm](ring: Keyring[H])
  /** Tag under the primary key - the session/CSRF issuance path. */
  @targetName("ringSign")
  def sign(data: Slice)(using m: MAC[H]): UEff[Signature[H]] = m.sign(ring.primary, data)

  /** Verify against any key the ring holds, primary first: tags issued under a retired-but-held key
    * still verify - session rotation without a flag day. Every attempt goes through the one audited
    * constant-time compare.
    */
  @targetName("ringVerify")
  def verify(data: Slice, sig: Signature[H])(using m: MAC[H]): Eff[SignatureRejected, Unit] =
    ring.all.map((_, k) => macVerify(m, k, data, sig)).reduce((acc, next) => acc.catchAll(_ => next))
end extension

// Split per KEY FAMILY: signatures genuinely differ (parameters, wire forms, encodings), so a
// uniform trait would force GADT ceremony on every backend for no consumer benefit. Backends
// consume and emit WHOLE encoded blobs (JCA KeySpec / WebCrypto importKey / aws-lc EVP_parse_*
// all validate the full encoding); exports are effectful and typed - a browser-GENERATED key is
// non-extractable and fails with [[KeyNotExportable]]; an IMPORTED key always exports.

@implicitNotFound("Ed25519 key lifecycle is not provided by this kufuli backend")
trait EdKeys:
  private[kufuli] def generate: UEff[KeyPair[PublicKey[Ed25519], PrivateKey[Ed25519]]]
  private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[Ed25519]]
  private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[Ed25519]]
  private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[Ed25519]]
  private[kufuli] def raw(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def spki(key: PublicKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def pkcs8(key: PrivateKey[Ed25519]): Eff[KeyNotExportable, IArray[Byte]]
object EdKeys extends EdKeysPlatform

@implicitNotFound("X25519 key lifecycle is not provided by this kufuli backend")
trait XKeys:
  private[kufuli] def generate: UEff[KeyPair[PublicKey[X25519], PrivateKey[X25519]]]
  private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[X25519]]
  private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[X25519]]
  private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[X25519]]
  private[kufuli] def raw(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def spki(key: PublicKey[X25519]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def pkcs8(key: PrivateKey[X25519]): Eff[KeyNotExportable, IArray[Byte]]
object XKeys extends XKeysPlatform

@implicitNotFound("key lifecycle for curve ${C} is not provided by this kufuli backend")
trait EcKeys[C <: EcCurve]:
  private[kufuli] def generate: UEff[KeyPair[PublicKey[C], PrivateKey[C]]]
  private[kufuli] def fromSec1(point: Slice): Eff[Refused, PublicKey[C]]
  private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[C]]
  private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[C]]
  private[kufuli] def sec1(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def spki(key: PublicKey[C]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def pkcs8(key: PrivateKey[C]): Eff[KeyNotExportable, IArray[Byte]]
object EcKeys extends EcKeysPlatform

@implicitNotFound("RSA key lifecycle is not provided by this kufuli backend")
trait RsaKeys:
  private[kufuli] def generate(size: RSA.Size): UEff[KeyPair[PublicKey[RSA], PrivateKey[RSA]]]
  private[kufuli] def fromComponents(modulus: Slice, exponent: Slice): Eff[Refused, PublicKey[RSA]]
  private[kufuli] def fromSpki(der: Slice): Eff[Refused, PublicKey[RSA]]
  private[kufuli] def fromPkcs8(der: Slice): Eff[Refused, PrivateKey[RSA]]
  private[kufuli] def components(key: PublicKey[RSA]): Eff[KeyNotExportable, RSA.Components]
  private[kufuli] def spki(key: PublicKey[RSA]): Eff[KeyNotExportable, IArray[Byte]]
  private[kufuli] def pkcs8(key: PrivateKey[RSA]): Eff[KeyNotExportable, IArray[Byte]]
object RsaKeys extends RsaKeysPlatform

// KEM keys travel raw in v1 protocols (TLS KeyShare); SPKI/PKCS#8 interop is post-v1.
@implicitNotFound(
  "${K} key lifecycle is not provided by this kufuli backend (ML-KEM is JVM >= 25, Native, and Node >= 24; the browser lacks it)"
)
trait KemKeys[K <: KemAlgorithm]:
  private[kufuli] def generate: UEff[KeyPair[PublicKey[K], PrivateKey[K]]]
  private[kufuli] def fromRaw(bytes: Slice): Eff[Refused, PublicKey[K]]
  private[kufuli] def raw(key: PublicKey[K]): Eff[KeyNotExportable, IArray[Byte]]

  // ML-KEM.KeyGen_internal: FIPS 203 derives a keypair from the 64-byte (d || z) seed and
  // recommends that seed as the stored private-key form.
  private[kufuli] def fromSeed(seed: Slice): Eff[InvalidKey, KeyPair[PublicKey[K], PrivateKey[K]]]
end KemKeys
object KemKeys extends KemKeysPlatform

// Exports - effectful and typed, returning the OWNED format types (the lifecycle traits keep
// IArray[Byte]; the wrapper is the array already produced - zero new copies). Symmetric raw
// export is deliberately ABSENT (compile fact).
extension (pub: PublicKey[Ed25519])
  @targetName("rawEd") def raw(using k: EdKeys): Eff[KeyNotExportable, Raw] = k.raw(pub).map(Raw(_))
  @targetName("spkiEd") def spki(using k: EdKeys): Eff[KeyNotExportable, SPKI] = k.spki(pub).map(SPKI(_))
extension (pub: PublicKey[X25519])
  @targetName("rawX") def raw(using k: XKeys): Eff[KeyNotExportable, Raw] = k.raw(pub).map(Raw(_))
  @targetName("spkiX") def spki(using k: XKeys): Eff[KeyNotExportable, SPKI] = k.spki(pub).map(SPKI(_))
extension [C <: EcCurve](pub: PublicKey[C])
  def sec1(using k: EcKeys[C]): Eff[KeyNotExportable, SEC1] = k.sec1(pub).map(SEC1(_))
  @targetName("spkiEc") def spki(using k: EcKeys[C]): Eff[KeyNotExportable, SPKI] = k.spki(pub).map(SPKI(_))
extension (pub: PublicKey[RSA])
  def components(using k: RsaKeys): Eff[KeyNotExportable, RSA.Components] = k.components(pub)
  @targetName("spkiRsa") def spki(using k: RsaKeys): Eff[KeyNotExportable, SPKI] = k.spki(pub).map(SPKI(_))
extension [K <: KemAlgorithm](pub: PublicKey[K])
  @targetName("rawKem") def raw(using k: KemKeys[K]): Eff[KeyNotExportable, Raw] = k.raw(pub).map(Raw(_))
extension (priv: PrivateKey[Ed25519])
  @targetName("pkcs8Ed") def pkcs8(using k: EdKeys): Eff[KeyNotExportable, PKCS8] = k.pkcs8(priv).map(PKCS8(_))
extension (priv: PrivateKey[X25519])
  @targetName("pkcs8X") def pkcs8(using k: XKeys): Eff[KeyNotExportable, PKCS8] = k.pkcs8(priv).map(PKCS8(_))
extension [C <: EcCurve](priv: PrivateKey[C])
  @targetName("pkcs8Ec") def pkcs8(using k: EcKeys[C]): Eff[KeyNotExportable, PKCS8] = k.pkcs8(priv).map(PKCS8(_))
extension (priv: PrivateKey[RSA])
  @targetName("pkcs8Rsa") def pkcs8(using k: RsaKeys): Eff[KeyNotExportable, PKCS8] = k.pkcs8(priv).map(PKCS8(_))
