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
package kufuli.password

import scala.annotation.targetName

import boilerplate.Slice
import boilerplate.TypedError
import boilerplate.effect.Eff
import boilerplate.effect.UEff

import kufuli.*

sealed abstract class PasswordError(message: String, cause: Option[Throwable]) extends TypedError(message, cause):
  def this(message: String) = this(message, None)
sealed abstract class InvalidParams private[password] () extends PasswordError("invalid Argon2 parameters")
case object InvalidParams extends InvalidParams
sealed abstract class MalformedHash private[password] () extends PasswordError("not a PHC argon2id string")
case object MalformedHash extends MalformedHash

final case class Argon2Params private (memoryKib: Int, iterations: Int, parallelism: Int) derives CanEqual
object Argon2Params:
  val interactive: Argon2Params = Argon2Params(19456, 2, 1) // OWASP interactive floor
  val default: Argon2Params = Argon2Params(65536, 3, 4) // RFC 9106 second recommendation
  val sensitive: Argon2Params = Argon2Params(2097152, 1, 4) // RFC 9106 first recommendation

  /** Params may come from configuration - data, so Either, not require. */
  def of(memoryKib: Int, iterations: Int, parallelism: Int): Either[InvalidParams, Argon2Params] =
    if iterations >= 1 && parallelism >= 1 && parallelism <= 255 && memoryKib >= 8 * parallelism
    then Right(Argon2Params(memoryKib, iterations, parallelism))
    else Left(InvalidParams)

/** A stored password hash in PHC string format; parse stored columns with `of`. */
opaque type PasswordHash = String
object PasswordHash:
  private[password] def unsafe(s: String): PasswordHash = s

  /** Parse a stored PHC string - the public constructor that makes the login flow writable.
    * Corruption surfaces HERE, never inside `verify`.
    */
  def of(stored: String): Either[MalformedHash, PasswordHash] =
    Phc.parse(stored).map(_ => stored)
  extension (h: PasswordHash) def value: String = h
  given CanEqual[PasswordHash, PasswordHash] = CanEqual.derived

enum PasswordCheck derives CanEqual:
  case Rejected

  /** `rehash = Some(policy)` when the stored parameters are weaker than the current policy. */
  case Verified(rehash: Option[Argon2Params])

/** The backend memory-hard primitive; everything else (PHC codec, salt generation, the verify
  * decision, the one constant-time compare) is shared code above it.
  */
@annotation.implicitNotFound("Argon2id is not provided by this kufuli backend (JVM = BouncyCastle, Native = libargon2, Node >= 24.7; the browser ships no password module)")
trait Argon2:
  private[kufuli] def hash(password: Slice, salt: Slice, params: Argon2Params): UEff[Array[Byte]]

// The provider is per-platform (JVM = BouncyCastle, Native = libargon2, Node >= 24.7) but its
// presence is uniform across the module's platforms; the companion extends a per-platform trait
// supplying the instance, exactly as the core operation families do.
object Argon2 extends Argon2Platform

// PHC string codec (one audited site; providers are KAT-verified against it). PHC B64 is the
// STANDARD alphabet, unpadded.
private[password] object Phc:
  // Argon2's own minimum (ARGON2_MIN_SALT_LENGTH): a shorter stored salt cannot have been produced
  // by any conformant hasher, and accepting it would let a tampered column drive verification with
  // a salt an attacker precomputed against.
  private[password] val minimumSaltBytes: Int = 8

  // Every provider here is driven at 32 bytes, so a column of another width could never match a
  // recomputation: it is corruption, and corruption surfaces at parse.
  private[password] val tagBytes: Int = 32

  final case class Parsed(params: Argon2Params, salt: Array[Byte], hash: Array[Byte])

  // `split` drops trailing empty fields, so a column ending in `$` would otherwise read as the same
  // hash without it - one stored value with two spellings.
  def parse(s: String): Either[MalformedHash, Parsed] =
    if s.endsWith("$") then Left(MalformedHash)
    else
      s.split('$') match
        case Array("", "argon2id", "v=19", p, saltB64, hashB64) =>
          (for
            params <- cost(p)
            salt <- b64(saltB64).filter(_.length >= minimumSaltBytes)
            hash <- b64(hashB64).filter(_.length == tagBytes)
          yield Parsed(params, salt, hash)).toRight(MalformedHash)
        case _ => Left(MalformedHash)

  // The three parameters in the order the Argon2 reference emits them. An unknown or reordered
  // field would give one stored hash several spellings, and a repeated one leaves which occurrence
  // governs the cost to whoever reads the column.
  private def cost(text: String): Option[Argon2Params] =
    if text.endsWith(",") then None
    else
      text.split(',') match
        case Array(s"m=$m", s"t=$t", s"p=$parallel") =>
          for
            memory <- decimal(m)
            iterations <- decimal(t)
            lanes <- decimal(parallel)
            params <- Argon2Params.of(memory, iterations, lanes).toOption
          yield params
        case _ => None

  private def decimal(text: String): Option[Int] =
    if text.isEmpty || (text.length > 1 && text.charAt(0) == '0') || !text.forall(c => c >= '0' && c <= '9') then None
    else text.toIntOption
  def emit(params: Argon2Params, salt: Array[Byte], hash: Array[Byte]): String =
    s"$$argon2id$$v=19$$m=${params.memoryKib},t=${params.iterations},p=${params.parallelism}$$${b64e(salt)}$$${b64e(hash)}"
  private def b64(s: String): Option[Array[Byte]] =
    Base64.decode(s, Base64.stdInverse, padded = false).toOption
  private def b64e(b: Array[Byte]): String = Base64.encode(b, Base64.stdAlphabet, pad = false)
end Phc

extension (pw: Array[Byte])
  /** Hash under `params` with a fresh CSPRNG salt; the result is the PHC string for storage. */
  def hash(params: Argon2Params)(using a: Argon2, r: Random): UEff[PasswordHash] =
    r.bytes(16).flatMap { s =>
      val salt = s.toArray
      a.hash(Slice.of(pw), Slice.of(salt), params).map(h => PasswordHash.unsafe(Phc.emit(params, salt, h)))
    }

  /** Recompute against the stored salt/params and compare constant-time. `rehash` recommends the
    * CURRENT policy when the stored parameters are weaker in any dimension.
    */
  def verify(against: PasswordHash, policy: Argon2Params)(using a: Argon2): UEff[PasswordCheck] =
    Eff.defer {
      // Every PasswordHash was parsed at its construction door, so a failure here is a broken
      // invariant: it belongs raised as a defect, never returned as a rejection.
      val p = demand(Phc.parse(against))
      a.hash(Slice.of(pw), Slice.of(p.salt), p.params).map { computed =>
        if !Slice.of(computed).constantTimeEquals(Slice.of(p.hash)) then PasswordCheck.Rejected
        else
          val weaker =
            p.params.memoryKib < policy.memoryKib || p.params.iterations < policy.iterations ||
              p.params.parallelism < policy.parallelism
          PasswordCheck.Verified(Option.when(weaker)(policy))
      }
    }
end extension

// The 99% case arrives as a String; the encoding is pinned (UTF-8, no normalisation - RFC 8265
// OpaqueString is the caller's concern and is documented, not silently applied).
extension (pw: String)
  @targetName("hashString")
  def hash(params: Argon2Params)(using Argon2, Random): UEff[PasswordHash] =
    pw.getBytes(java.nio.charset.StandardCharsets.UTF_8).hash(params)
  @targetName("verifyString")
  def verify(against: PasswordHash, policy: Argon2Params)(using Argon2): UEff[PasswordCheck] =
    pw.getBytes(java.nio.charset.StandardCharsets.UTF_8).verify(against, policy)
