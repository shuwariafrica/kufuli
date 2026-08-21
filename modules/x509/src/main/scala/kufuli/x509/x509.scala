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
// Time is epoch seconds throughout: java.time is JVM-only, so it cannot reach a cross-platform
// signature.
package kufuli.x509

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.TypedError
import boilerplate.ValueCodec
import boilerplate.effect.Eff
import boilerplate.effect.UEff

import kufuli.*

sealed abstract class X509Error(message: String, cause: Option[Throwable]) extends TypedError(message, cause):
  def this(message: String) = this(message, None)

// Payload-free cases are a class plus a co-named object, and type positions name the CLASS: a union
// of singleton types does not survive the TypeTest reification `either`/`catchAll` rely on
// (re-tested at each toolchain adoption, last at Scala 3.9.0-RC5: still broken; drop the
// class+object shape for plain case objects when the erasure defect is fixed).
sealed abstract class PathInvalid(message: String) extends X509Error(message)
object PathInvalid:
  sealed abstract class MalformedChain private[x509] () extends PathInvalid("unparseable certificate in chain")
  case object MalformedChain extends MalformedChain
  sealed abstract class Expired private[x509] () extends PathInvalid("certificate outside validity window")
  case object Expired extends Expired
  sealed abstract class UntrustedAnchor private[x509] () extends PathInvalid("chain does not terminate at a trust anchor")
  case object UntrustedAnchor extends UntrustedAnchor
  sealed abstract class BadSignature private[x509] () extends PathInvalid("chain signature verification failed")
  case object BadSignature extends BadSignature
  sealed abstract class NameMismatch private[x509] () extends PathInvalid("hostname does not match SAN")
  case object NameMismatch extends NameMismatch
  sealed abstract class ConstraintViolated private[x509] () extends PathInvalid("certificate constraints violated")
  case object ConstraintViolated extends ConstraintViolated
  sealed abstract class NameConstraintViolated private[x509] () extends PathInvalid("certificate name outside the issuers' name constraints")
  case object NameConstraintViolated extends NameConstraintViolated
  sealed abstract class LimitExceeded private[x509] () extends PathInvalid("certificate path exceeds a validation resource bound")
  case object LimitExceeded extends LimitExceeded
  sealed abstract class UnsupportedAlgorithm private[x509] () extends PathInvalid("signature algorithm not supported")
  case object UnsupportedAlgorithm extends UnsupportedAlgorithm
  sealed abstract class ResponseMismatch private[x509] () extends PathInvalid("status response does not match the certificate")
  case object ResponseMismatch extends ResponseMismatch
end PathInvalid

// Every GeneralName a certificate presents. The four forms RFC 5280 defines no matching rule for
// are recorded as presence, which is all the fail-closed conjunction reads; URI joins them there
// while keeping its values for the accessor.
final private[x509] case class San(
  dns: List[String],
  ips: List[IpBits],
  emails: List[String],
  uris: List[String],
  dirNames: List[List[List[Ava]]],
  unprocessed: Set[UnprocessedForm]
)

// Everything path validation reads from a certificate, extracted once at construction: `Certificate`
// is opaque over this, so no accessor re-parses. Identity is the DER, with the hash taken in the
// same pass, because the case-class equality over its array fields would be reference equality.
final private[x509] case class Parsed(
  encoded: IArray[Byte],
  hash: Int,
  tbs: Array[Byte],
  serial: Array[Byte],
  spki: Array[Byte],
  issuerDer: Array[Byte],
  subjectDer: Array[Byte],
  subject: List[List[Ava]],
  notBefore: Long,
  notAfter: Long,
  san: Option[San],
  isCa: Option[Boolean],
  maxPathLen: Option[Int],
  ekus: List[String],
  keyCertSign: Option[Boolean],
  constraints: Option[NameConstraints],
  unhandledCritical: Boolean,
  sigScheme: Option[SigScheme],
  signature: Array[Byte]
):
  override def hashCode: Int = hash
  override def equals(that: Any): Boolean =
    that match
      case other: Parsed => hash == other.hash && Parsed.sameBytes(encoded, other.encoded, 0)
      case _             => false
end Parsed

private[x509] object Parsed:
  @tailrec def sameBytes(a: IArray[Byte], b: IArray[Byte], i: Int): Boolean =
    if a.length != b.length then false
    else if i >= a.length then true
    else a(i) == b(i) && sameBytes(a, b, i + 1)

  @tailrec def hashOf(a: IArray[Byte], i: Int, acc: Int): Int =
    if i >= a.length then acc else hashOf(a, i + 1, acc * 31 + a(i))

// The scheme named in a certificate's own signatureAlgorithm - what its ISSUER's key verifies with.
private[x509] enum SigScheme derives CanEqual:
  case Ed
  case Ec(hash: Sha2)
  case RsaPkcs1(hash: Sha2)
  case RsaPss(hash: Sha2)

private[x509] object X509:
  // Signature-algorithm OIDs (content bytes).
  private val ecdsaSha256 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x04, 0x03, 0x02)
  private val ecdsaSha384 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x04, 0x03, 0x03)
  private val ecdsaSha512 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x04, 0x03, 0x04)
  private val ed25519 = Array[Byte](0x2b, 0x65, 0x70)
  private val rsaSha256 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x0b)
  private val rsaSha384 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x0c)
  private val rsaSha512 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x0d)
  private val rsaPss = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x0a)
  // Extension OIDs. Every extension a certificate may mark critical must appear here, or the
  // certificate is rejected: RFC 5280 section 6.1.4 forbids proceeding past one we cannot process.
  private val oidKeyUsage = Array[Byte](0x55, 0x1d, 0x0f)
  private val oidSan = Array[Byte](0x55, 0x1d, 0x11)
  private val oidBasicConstraints = Array[Byte](0x55, 0x1d, 0x13)
  private val oidNameConstraints = Array[Byte](0x55, 0x1d, 0x1e)
  private val oidEku = Array[Byte](0x55, 0x1d, 0x25)
  // The subject-DN attribute RFC 5280 section 4.2.1.10 checks as an rfc822Name when a certificate
  // carries no SAN extension.
  private val oidEmailAddress = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x09, 0x01)
  // Hash and mask-generation OIDs, for RSASSA-PSS parameters.
  private val sha256Oid = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
  private val sha384Oid = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
  private val sha512Oid = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)
  private val mgf1 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x08)
  // EKU purpose OIDs.
  val ekuServerAuth = "1.3.6.1.5.5.7.3.1"
  val ekuClientAuth = "1.3.6.1.5.5.7.3.2"
  val ekuOcspSigning = "1.3.6.1.5.5.7.3.9"

  private def eq(a: Slice, b: Array[Byte]): Boolean = a.contentEquals(Slice.of(b))

  // The whole AlgorithmIdentifier, because RSASSA-PSS carries its digest in the parameters.
  private[x509] def sigScheme(s: Slice, algId: DER.Tlv): Option[SigScheme] =
    read(s, algId.contentOff, 0x06, algId.next).toOption.flatMap { t =>
      val oid = s.slice(t.contentOff, t.next)
      if eq(oid, ed25519) then Some(SigScheme.Ed)
      else if eq(oid, ecdsaSha256) then Some(SigScheme.Ec(Sha256))
      else if eq(oid, ecdsaSha384) then Some(SigScheme.Ec(Sha384))
      else if eq(oid, ecdsaSha512) then Some(SigScheme.Ec(Sha512))
      else if eq(oid, rsaSha256) then Some(SigScheme.RsaPkcs1(Sha256))
      else if eq(oid, rsaSha384) then Some(SigScheme.RsaPkcs1(Sha384))
      else if eq(oid, rsaSha512) then Some(SigScheme.RsaPkcs1(Sha512))
      else if eq(oid, rsaPss) then pssHash(s, t.next, algId.next).map(SigScheme.RsaPss(_))
      else None
    }

  private def hashOid(s: Slice, algId: DER.Tlv): Option[Sha2] =
    read(s, algId.contentOff, 0x06, algId.next).toOption.flatMap[Sha2] { t =>
      val oid = s.slice(t.contentOff, t.next)
      if eq(oid, sha256Oid) then Some(Sha256)
      else if eq(oid, sha384Oid) then Some(Sha384)
      else if eq(oid, sha512Oid) then Some(Sha512)
      else None
    }

  private def hashLength(hash: Sha2): Int =
    hash match
      case _: Sha256.type => 32
      case _: Sha384.type => 48
      case _: Sha512.type => 64

  // RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2],
  // trailerField [3] }, each with a DEFAULT naming SHA-1. kufuli verifies only the three profiles
  // where MGF1 uses the same SHA-2 digest and the salt is that digest's length; every other
  // parameter set - the SHA-1 defaults included - has no scheme here and fails closed.
  private def pssHash(s: Slice, off: Int, limit: Int): Option[Sha2] =
    for
      params <- read(s, off, 0x30, limit).toOption
      _ <- Option.when(params.next == limit)(())
      hashField <- read(s, params.contentOff, 0xa0, params.next).toOption
      hashAlg <- read(s, hashField.contentOff, 0x30, hashField.next).toOption
      hash <- hashOid(s, hashAlg)
      maskField <- read(s, hashField.next, 0xa1, params.next).toOption
      maskAlg <- read(s, maskField.contentOff, 0x30, maskField.next).toOption
      maskOid <- read(s, maskAlg.contentOff, 0x06, maskAlg.next).toOption
      _ <- Option.when(eq(s.slice(maskOid.contentOff, maskOid.next), mgf1))(())
      maskHashAlg <- read(s, maskOid.next, 0x30, maskAlg.next).toOption
      maskHash <- hashOid(s, maskHashAlg)
      _ <- Option.when(hashLength(maskHash) == hashLength(hash))(())
      saltField <- read(s, maskField.next, 0xa2, params.next).toOption
      saltInt <- read(s, saltField.contentOff, 0x02, saltField.next).toOption
      salt <- smallInteger(s, saltInt)
      _ <- Option.when(salt == hashLength(hash))(())
      _ <- trailerIsDefault(s, saltField.next, params.next)
    yield hash

  // trailerField is optional and its only defined value is trailerBCompatible(1).
  private def trailerIsDefault(s: Slice, off: Int, limit: Int): Option[Unit] =
    if off == limit then Some(())
    else
      for
        field <- read(s, off, 0xa3, limit).toOption
        _ <- Option.when(field.next == limit)(())
        value <- read(s, field.contentOff, 0x02, field.next).toOption
        n <- smallInteger(s, value)
        _ <- Option.when(n == 1)(())
      yield ()

  // Civil date (UTC) to epoch seconds without java.time (Howard Hinnant's algorithm).
  private def epoch(y: Int, m: Int, d: Int, hh: Int, mm: Int, ss: Int): Long =
    val yy = if m <= 2 then y - 1 else y
    val era = (if yy >= 0 then yy else yy - 399) / 400
    val yoe = yy - era * 400
    val doy = (153 * (if m > 2 then m - 3 else m + 9) + 2) / 5 + d - 1
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    val days = era.toLong * 146097 + doe - 719468
    days * 86400 + hh * 3600 + mm * 60 + ss

  private def monthLength(year: Int, month: Int): Int =
    month match
      case 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
      case 4 | 6 | 9 | 11              => 30
      case _                           => if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) then 29 else 28

  // RFC 5280 sections 4.1.2.5.1 and 4.1.2.5.2: both forms are Zulu, seconds are mandatory, and
  // UTCTime's two-digit year splits at 50. An offset form or an out-of-range field is a rejection,
  // not a value to salvage - reading it leniently shifts the validity window.
  private[x509] def parseTime(text: String, generalized: Boolean): Option[Long] =
    val width = if generalized then 14 else 12
    def digit(i: Int): Boolean = text.charAt(i) >= '0' && text.charAt(i) <= '9'
    def value(off: Int, n: Int): Int = (off until off + n).foldLeft(0)((a, i) => a * 10 + (text.charAt(i) - '0'))
    if text.length != width + 1 || text.charAt(width) != 'Z' || !(0 until width).forall(digit) then None
    else
      val year = if generalized then value(0, 4) else (if value(0, 2) >= 50 then 1900 else 2000) + value(0, 2)
      val rest = if generalized then 4 else 2
      val month = value(rest, 2)
      val day = value(rest + 2, 2)
      val hour = value(rest + 4, 2)
      val minute = value(rest + 6, 2)
      val second = value(rest + 8, 2)
      if month < 1 || month > 12 || day < 1 || day > monthLength(year, month) || hour > 23 || minute > 59 || second > 59 then None
      else Some(epoch(year, month, day, hour, minute, second))
  end parseTime

  // OID content bytes -> dotted string (for EKU comparison).
  private def oidString(content: Array[Byte]): String =
    if content.isEmpty then ""
    else
      val first = content(0) & 0xff
      val sb = new StringBuilder
      val _ = sb.append(first / 40).append('.').append(first % 40)
      @tailrec def go(i: Int, value: Long): Unit =
        if i < content.length then
          val b = content(i) & 0xff
          val acc = (value << 7) | (b & 0x7f)
          if (b & 0x80) == 0 then
            val _ = sb.append('.').append(acc)
            go(i + 1, 0L)
          else go(i + 1, acc)
      go(1, 0L)
      sb.toString

  private def read(der: Slice, off: Int, tag: Int): Either[PathInvalid, DER.Tlv] =
    DER.read(der, off, tag).left.map(_ => PathInvalid.MalformedChain)

  // The core reader bounds a TLV by the whole buffer, not by the structure that contains it, so a
  // child claiming a length past its parent would otherwise read a sibling's bytes as its own.
  private def read(der: Slice, off: Int, tag: Int, limit: Int): Either[PathInvalid, DER.Tlv] =
    read(der, off, tag).filterOrElse(_.next <= limit, PathInvalid.MalformedChain)

  // One TLV occupying the whole slice, for extension values, which carry exactly one encoding.
  private def only(der: Slice, tag: Int): Either[PathInvalid, DER.Tlv] =
    read(der, 0, tag).filterOrElse(_.next == der.length, PathInvalid.MalformedChain)

  private def wellFormed(ok: Boolean): Either[PathInvalid, Unit] =
    if ok then Right(()) else Left(PathInvalid.MalformedChain)

  def parse(der: IArray[Byte]): Either[PathInvalid, Parsed] =
    val bytes = Array.from(der.iterator)
    val s = Slice.of(bytes)
    for
      cert <- read(s, 0, 0x30)
      _ <- wellFormed(cert.next == s.length)
      tbs <- read(s, cert.contentOff, 0x30, cert.next)
      sigAlg <- read(s, tbs.next, 0x30, cert.next)
      sigBits <- read(s, sigAlg.next, 0x03, cert.next)
      _ <- wellFormed(sigBits.next == cert.next && sigBits.contentLen >= 1)
      fields <- tbsFields(s, tbs)
      // RFC 5280 section 4.1.1.2: the outer signatureAlgorithm is not covered by the signature, so
      // the scheme it names is attacker-chosen unless it equals the signed inner one byte for byte.
      _ <- wellFormed(s.slice(tbs.next, sigAlg.next).contentEquals(fields.innerSigAlg))
      subject <- distinguishedName(s, fields.subjectRange.from, fields.subjectRange.until)
      ext <- extensions(s, fields.exts)
      _ <- wellFormed(fields.exts.isEmpty || fields.version.contains(2))
    yield Parsed(
      encoded = der,
      hash = Parsed.hashOf(der, 0, 1),
      tbs = s.slice(cert.contentOff, tbs.next).toArray,
      serial = fields.serial,
      spki = fields.spki,
      issuerDer = fields.issuerDer,
      subjectDer = fields.subjectDer,
      subject = subject,
      notBefore = fields.notBefore,
      notAfter = fields.notAfter,
      san = ext.san,
      isCa = ext.isCa,
      maxPathLen = ext.maxPathLen,
      ekus = ext.ekus,
      keyCertSign = ext.keyCertSign,
      constraints = ext.constraints,
      unhandledCritical = ext.unhandledCritical,
      sigScheme = sigScheme(s, sigAlg),
      signature = s.slice(sigBits.contentOff + 1, sigBits.next).toArray
    )
    end for
  end parse

  // Named so the same-typed neighbours cannot be transposed: issuerDer/subjectDer are both
  // Array[Byte] and notBefore/notAfter both Long, so a positional slip would type-check and break
  // chain linking or invert the validity window silently.
  private type TbsFields = (
    serial: Array[Byte],
    issuerDer: Array[Byte],
    subjectDer: Array[Byte],
    subjectRange: (from: Int, until: Int),
    innerSigAlg: Slice,
    version: Option[Int],
    notBefore: Long,
    notAfter: Long,
    spki: Array[Byte],
    exts: Option[DER.Tlv]
  )

  // Version is [0] EXPLICIT and absent for v1. RFC 5280 section 4.1.2.1 admits 0, 1 and 2, but DER
  // omits a DEFAULT value, so a present [0] encoding v1 is an alternative encoding of the same
  // certificate.
  private def afterVersion(s: Slice, tbs: DER.Tlv): Either[PathInvalid, (next: Int, version: Option[Int])] =
    if tbs.contentOff < tbs.next && (s(tbs.contentOff) & 0xff) == 0xa0 then
      for
        wrapper <- read(s, tbs.contentOff, 0xa0, tbs.next)
        value <- read(s, wrapper.contentOff, 0x02, wrapper.next)
        _ <- wellFormed(value.next == wrapper.next)
        n <- smallInteger(s, value).toRight(PathInvalid.MalformedChain)
        _ <- wellFormed(n == 1 || n == 2)
      yield (next = wrapper.next, version = Some(n))
    else Right((next = tbs.contentOff, version = None))

  private def tbsFields(s: Slice, tbs: DER.Tlv): Either[PathInvalid, TbsFields] =
    for
      start <- afterVersion(s, tbs)
      serial <- read(s, start.next, 0x02, tbs.next)
      sigAlgId <- read(s, serial.next, 0x30, tbs.next)
      issuer <- read(s, sigAlgId.next, 0x30, tbs.next)
      validity <- read(s, issuer.next, 0x30, tbs.next)
      subject <- read(s, validity.next, 0x30, tbs.next)
      spki <- read(s, subject.next, 0x30, tbs.next)
      times <- parseValidity(s, validity)
      exts <- scanExtensions(s, spki.next, tbs.next)
    yield (
      serial = s.slice(serial.contentOff, serial.next).toArray,
      issuerDer = s.slice(sigAlgId.next, issuer.next).toArray,
      subjectDer = s.slice(validity.next, subject.next).toArray,
      subjectRange = (from = validity.next, until = subject.next),
      innerSigAlg = s.slice(serial.next, sigAlgId.next),
      version = start.version,
      notBefore = times.notBefore,
      notAfter = times.notAfter,
      spki = s.slice(subject.next, spki.next).toArray,
      exts = exts
    )
    end for
  end tbsFields

  private def parseValidity(s: Slice, validity: DER.Tlv): Either[PathInvalid, (notBefore: Long, notAfter: Long)] =
    def time(off: Int): Either[PathInvalid, (epoch: Long, next: Int)] =
      if off >= validity.next then Left(PathInvalid.MalformedChain)
      else
        val tag = s(off) & 0xff
        if tag != 0x17 && tag != 0x18 then Left(PathInvalid.MalformedChain)
        else
          read(s, off, tag, validity.next).flatMap { t =>
            val str = new String(s.slice(t.contentOff, t.next).toArray, "US-ASCII")
            parseTime(str, generalized = tag == 0x18).map(e => (epoch = e, next = t.next)).toRight(PathInvalid.MalformedChain)
          }
    for
      nb <- time(validity.contentOff)
      na <- time(nb.next)
      _ <- wellFormed(na.next == validity.next)
    yield (notBefore = nb.epoch, notAfter = na.epoch)
  end parseValidity

  // The bytes after the SPKI hold issuerUniqueID [1], subjectUniqueID [2] and extensions [3], all
  // optional. `None` is a certificate that carries no extensions; an unreadable TLV is a rejection,
  // because reading past it drops every extension the certificate does carry - a leaf's EKU and SAN
  // included.
  @tailrec private def scanExtensions(s: Slice, start: Int, end: Int): Either[PathInvalid, Option[DER.Tlv]] =
    if start >= end then Right(None)
    else
      val tag = s(start) & 0xff
      read(s, start, tag, end) match
        case Left(e)                 => Left(e)
        case Right(t) if tag == 0xa3 =>
          for
            _ <- wellFormed(t.next == end)
            seq <- read(s, t.contentOff, 0x30, t.next)
            _ <- wellFormed(seq.next == t.next)
          yield Some(seq)
        case Right(t) => scanExtensions(s, t.next, end)

  final private case class Extensions(
    san: Option[San],
    isCa: Option[Boolean],
    maxPathLen: Option[Int],
    ekus: List[String],
    keyCertSign: Option[Boolean],
    constraints: Option[NameConstraints],
    unhandledCritical: Boolean
  )

  private type ExtStep = (next: Int, id: Slice, acc: Extensions)

  // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
  // Every failure is a rejection: a partial parse leaves an empty EKU list or an absent path-length
  // constraint, both of which read as "unrestricted".
  private def extensions(s: Slice, exts: Option[DER.Tlv]): Either[PathInvalid, Extensions] =
    val empty =
      Extensions(san = None, isCa = None, maxPathLen = None, ekus = Nil, keyCertSign = None, constraints = None, unhandledCritical = false)
    exts match
      case None      => Right(empty)
      case Some(seq) =>
        @tailrec def go(pos: Int, seen: List[Slice], acc: Extensions): Either[PathInvalid, Extensions] =
          if pos >= seq.next then Right(acc)
          else
            readExtension(s, pos, seq.next, seen, acc) match
              case Left(e)     => Left(e)
              case Right(step) => go(step.next, step.id :: seen, step.acc)
        go(seq.contentOff, Nil, empty)
  end extensions

  private def readExtension(s: Slice, pos: Int, limit: Int, seen: List[Slice], acc: Extensions): Either[PathInvalid, ExtStep] =
    for
      ext <- read(s, pos, 0x30, limit)
      oid <- read(s, ext.contentOff, 0x06, ext.next)
      flag <- criticality(s, oid.next, ext.next)
      octet <- read(s, flag.next, 0x04, ext.next)
      _ <- wellFormed(octet.next == ext.next)
      id = s.slice(oid.contentOff, oid.next)
      // RFC 5280 section 4.2 forbids a repeated extension; accepting one makes which copy wins a
      // parser-differential question.
      _ <- wellFormed(!seen.exists(id.contentEquals))
      updated <- absorb(s.slice(octet.contentOff, octet.next), id, flag.critical, acc)
    yield (next = ext.next, id = id, acc = updated)

  // DER omits a DEFAULT FALSE and encodes TRUE as 0xFF, so an explicit FALSE or any other content
  // is a second encoding of a value that already has exactly one - the raw material of a parser
  // differential.
  private def booleanFlag(s: Slice, off: Int, limit: Int): Either[PathInvalid, (set: Boolean, next: Int)] =
    if off < limit && (s(off) & 0xff) == 0x01 then
      read(s, off, 0x01, limit).flatMap { b =>
        if b.contentLen != 1 || (s(b.contentOff) & 0xff) != 0xff then Left(PathInvalid.MalformedChain)
        else Right((set = true, next = b.next))
      }
    else Right((set = false, next = off))

  private def criticality(s: Slice, off: Int, limit: Int): Either[PathInvalid, (critical: Boolean, next: Int)] =
    booleanFlag(s, off, limit).map(b => (critical = b.set, next = b.next))

  private def absorb(value: Slice, oid: Slice, critical: Boolean, acc: Extensions): Either[PathInvalid, Extensions] =
    if eq(oid, oidSan) then parseSan(value).map(san => acc.copy(san = Some(san)))
    else if eq(oid, oidBasicConstraints) then
      parseBasicConstraints(value).map(bc => acc.copy(isCa = Some(bc.isCa), maxPathLen = bc.maxPathLen))
    else if eq(oid, oidNameConstraints) then parseNameConstraints(value).map(nc => acc.copy(constraints = Some(nc)))
    else if eq(oid, oidEku) then parseEku(value).map(e => acc.copy(ekus = e))
    else if eq(oid, oidKeyUsage) then parseKeyUsage(value).map(k => acc.copy(keyCertSign = Some(k)))
    else Right(acc.copy(unhandledCritical = acc.unhandledCritical || critical))

  // IA5String is 7-bit: decoding a high byte as US-ASCII substitutes a replacement character, which
  // folds two distinct names onto one string.
  private def ia5(s: Slice, t: DER.Tlv): Option[String] =
    val raw = s.slice(t.contentOff, t.next).toArray
    if raw.forall(_ >= 0) then Some(new String(raw, "US-ASCII")) else None

  // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName. Every form is read: the four with no
  // RFC 5280 matching rule, and URI, only as presence, which is what the fail-closed conjunction
  // consumes.
  private def parseSan(value: Slice): Either[PathInvalid, San] =
    @tailrec def go(pos: Int, limit: Int, count: Int, acc: San): Either[PathInvalid, San] =
      if pos >= limit then Right(acc)
      else if count >= maxNames then Left(PathInvalid.MalformedChain)
      else
        val tag = value(pos) & 0xff
        read(value, pos, tag, limit) match
          case Left(e)  => Left(e)
          case Right(t) =>
            sanEntry(value, tag, t, acc) match
              case Left(e)     => Left(e)
              case Right(next) => go(t.next, limit, count + 1, next)
    for
      seq <- only(value, 0x30)
      _ <- wellFormed(seq.contentOff < seq.next)
      san <- go(seq.contentOff, seq.next, 0, San(Nil, Nil, Nil, Nil, Nil, Set.empty))
    yield San(
      dns = san.dns.reverse,
      ips = san.ips.reverse,
      emails = san.emails.reverse,
      uris = san.uris.reverse,
      dirNames = san.dirNames.reverse,
      unprocessed = san.unprocessed
    )
    end for
  end parseSan

  private def sanEntry(s: Slice, tag: Int, t: DER.Tlv, acc: San): Either[PathInvalid, San] =
    // RFC 5280 section 4.2.1.6 gives no meaning to a zero-length GeneralName; reading one as a name
    // that matches nothing, or everything, is the choice Go's CVE-2026-27138 made.
    if t.contentLen == 0 then Left(PathInvalid.MalformedChain)
    else
      tag match
        case 0x82 => ia5(s, t).filter(Names.validDnsName).toRight(PathInvalid.MalformedChain).map(n => acc.copy(dns = n :: acc.dns))
        case 0x87 =>
          IpAddress
            .of(s.slice(t.contentOff, t.next))
            .left
            .map(_ => PathInvalid.MalformedChain)
            .map(ip => acc.copy(ips = ip.bits :: acc.ips))
        case 0x81 => ia5(s, t).filter(Names.validEmail).toRight(PathInvalid.MalformedChain).map(n => acc.copy(emails = n :: acc.emails))
        case 0x86 =>
          ia5(s, t)
            .toRight(PathInvalid.MalformedChain)
            .map(n => acc.copy(uris = n :: acc.uris, unprocessed = acc.unprocessed + UnprocessedForm.Uri))
        case 0xa4 => distinguishedName(s, t.contentOff, t.next).map(dn => acc.copy(dirNames = dn :: acc.dirNames))
        case 0xa0 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.Other))
        case 0xa3 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.X400))
        case 0xa5 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.EdiParty))
        case 0x88 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.RegisteredId))
        case _    => Left(PathInvalid.MalformedChain)

  // NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL,
  // excludedSubtrees [1] GeneralSubtrees OPTIONAL }, each SEQUENCE SIZE (1..MAX).
  private def parseNameConstraints(value: Slice): Either[PathInvalid, NameConstraints] =
    for
      seq <- only(value, 0x30)
      _ <- wellFormed(seq.contentOff < seq.next)
      permitted <- subtreeList(value, seq.contentOff, seq.next, 0xa0)
      excluded <- subtreeList(value, permitted.next, seq.next, 0xa1)
      _ <- wellFormed(excluded.next == seq.next)
    yield NameConstraints(permitted.subtrees, excluded.subtrees)

  private def subtreeList(s: Slice, pos: Int, limit: Int, tag: Int): Either[PathInvalid, (subtrees: Subtrees, next: Int)] =
    if pos < limit && (s(pos) & 0xff) == tag then
      for
        wrapper <- read(s, pos, tag, limit)
        _ <- wellFormed(wrapper.contentOff < wrapper.next)
        list <- subtrees(s, wrapper.contentOff, wrapper.next, 0, Subtrees.empty)
      yield (subtrees = list, next = wrapper.next)
    else Right((subtrees = Subtrees.empty, next = pos))

  @tailrec private def subtrees(s: Slice, pos: Int, limit: Int, count: Int, acc: Subtrees): Either[PathInvalid, Subtrees] =
    if pos >= limit then Right(acc)
    else if count >= maxSubtrees then Left(PathInvalid.MalformedChain)
    else
      val step =
        for
          sub <- read(s, pos, 0x30, limit)
          _ <- wellFormed(sub.contentOff < sub.next)
          tag = s(sub.contentOff) & 0xff
          base <- read(s, sub.contentOff, tag, sub.next)
          // minimum and maximum have no meaning in this walk, and an explicit `minimum = 0` is a
          // DER DEFAULT violation besides, so either present rejects the subtree.
          _ <- wellFormed(base.next == sub.next)
          next <- subtreeBase(s, tag, base, acc)
        yield (acc = next, next = sub.next)
      step match
        case Left(e)  => Left(e)
        case Right(t) => subtrees(s, t.next, limit, count + 1, t.acc)

  private def subtreeBase(s: Slice, tag: Int, t: DER.Tlv, acc: Subtrees): Either[PathInvalid, Subtrees] =
    tag match
      case 0x82 => ia5(s, t).filter(Names.validDnsBase).toRight(PathInvalid.MalformedChain).map(b => acc.copy(dns = b :: acc.dns))
      case 0x87 => ipSubtree(s, t).map(sub => acc.copy(ips = sub :: acc.ips))
      case 0x81 => ia5(s, t).filter(validEmailBase).toRight(PathInvalid.MalformedChain).map(b => acc.copy(emails = b :: acc.emails))
      case 0x86 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.Uri))
      case 0xa4 => distinguishedName(s, t.contentOff, t.next).map(dn => acc.copy(dirNames = dn :: acc.dirNames))
      case 0xa0 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.Other))
      case 0xa3 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.X400))
      case 0xa5 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.EdiParty))
      case 0x88 => Right(acc.copy(unprocessed = acc.unprocessed + UnprocessedForm.RegisteredId))
      case _    => Left(PathInvalid.MalformedChain)

  private def validEmailBase(base: String): Boolean =
    val at = base.indexOf('@')
    at < 0 || base.indexOf('@', at + 1) < 0

  // The address and its mask, as one value of twice the family's width.
  private def ipSubtree(s: Slice, t: DER.Tlv): Either[PathInvalid, IpSubtree] =
    val raw = s.slice(t.contentOff, t.next)
    if raw.length != 8 && raw.length != 32 then Left(PathInvalid.MalformedChain)
    else
      val half = raw.length / 2
      for
        base <- IpAddress.of(raw.take(half)).left.map(_ => PathInvalid.MalformedChain)
        mask <- IpAddress.of(raw.drop(half)).left.map(_ => PathInvalid.MalformedChain)
        _ <- wellFormed(Names.contiguousMask(mask.bits))
      yield IpSubtree(base.bits, mask.bits)

  // Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName ::= SET OF AttributeTypeAndValue.
  private def distinguishedName(s: Slice, from: Int, until: Int): Either[PathInvalid, List[List[Ava]]] =
    for
      seq <- read(s, from, 0x30, until)
      _ <- wellFormed(seq.next == until)
      rdns <- rdnSequence(s, seq.contentOff, seq.next, Nil)
    yield rdns

  @tailrec private def rdnSequence(s: Slice, pos: Int, limit: Int, acc: List[List[Ava]]): Either[PathInvalid, List[List[Ava]]] =
    if pos >= limit then Right(acc.reverse)
    else
      read(s, pos, 0x31, limit).flatMap(set => avas(s, set.contentOff, set.next, Nil).map(list => (rdn = list, next = set.next))) match
        case Left(e)  => Left(e)
        case Right(t) => rdnSequence(s, t.next, limit, t.rdn :: acc)

  @tailrec private def avas(s: Slice, pos: Int, limit: Int, acc: List[Ava]): Either[PathInvalid, List[Ava]] =
    if pos >= limit then Right(acc.reverse)
    else
      val step =
        for
          ava <- read(s, pos, 0x30, limit)
          oid <- read(s, ava.contentOff, 0x06, ava.next)
          _ <- wellFormed(oid.next < ava.next)
          tag = s(oid.next) & 0xff
          value <- read(s, oid.next, tag, ava.next)
          _ <- wellFormed(value.next == ava.next)
        yield (
          ava = Ava(s.slice(oid.contentOff, oid.next).toArray, tag, s.slice(value.contentOff, value.next).toArray),
          next = ava.next
        )
      step match
        case Left(e)  => Left(e)
        case Right(t) => avas(s, t.next, limit, t.ava :: acc)

  // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.
  private def parseBasicConstraints(value: Slice): Either[PathInvalid, (isCa: Boolean, maxPathLen: Option[Int])] =
    def ca(off: Int, limit: Int): Either[PathInvalid, (set: Boolean, next: Int)] = booleanFlag(value, off, limit)
    def pathLen(off: Int, limit: Int): Either[PathInvalid, Option[Int]] =
      if off < limit && (value(off) & 0xff) == 0x02 then
        read(value, off, 0x02, limit).flatMap(t => smallInteger(value, t).toRight(PathInvalid.MalformedChain)).map(Some(_))
      else Right(None)
    for
      seq <- only(value, 0x30)
      flag <- ca(seq.contentOff, seq.next)
      limit <- if flag.set then pathLen(flag.next, seq.next) else Right(None)
    yield (isCa = flag.set, maxPathLen = limit)
  end parseBasicConstraints

  // A small non-negative DER INTEGER (pathLenConstraint is 0..a handful); reject negative/oversize.
  private def smallInteger(s: Slice, t: DER.Tlv): Option[Int] =
    val raw = s.slice(t.contentOff, t.next).toArray
    // A padding octet a minimal encoding would not carry is a second encoding of the same value,
    // which is how two readers of one certificate are made to disagree about a version or a length.
    if raw.isEmpty || raw.length > 4 || (raw(0) & 0x80) != 0 then None
    else if raw.length > 1 && raw(0) == 0.toByte && (raw(1) & 0x80) == 0 then None
    else Some(raw.foldLeft(0)((a, b) => (a << 8) | (b & 0xff)))

  private def parseEku(value: Slice): Either[PathInvalid, List[String]] =
    @tailrec def go(pos: Int, limit: Int, acc: List[String]): Either[PathInvalid, List[String]] =
      if pos >= limit then Right(acc.reverse)
      else
        read(value, pos, 0x06, limit) match
          case Left(e)  => Left(e)
          case Right(t) => go(t.next, limit, oidString(value.slice(t.contentOff, t.next).toArray) :: acc)
    only(value, 0x30).flatMap(seq => go(seq.contentOff, seq.next, Nil))

  // KeyUsage ::= BIT STRING, keyCertSign at bit 5 (RFC 5280 section 4.2.1.3). The unused-bit count
  // applies to the final octet, so a bit past the encoded length is absent rather than clear.
  private def parseKeyUsage(value: Slice): Either[PathInvalid, Boolean] =
    only(value, 0x03).flatMap { bits =>
      val unused = if bits.contentLen >= 1 then value(bits.contentOff) & 0xff else 8
      if unused > 7 then Left(PathInvalid.MalformedChain)
      else Right((bits.contentLen - 1) * 8 - unused > 5 && (value(bits.contentOff + 1) & 0x04) != 0)
    }

  // A certificate SAN or constraint list this long is pathological, and both walks are quadratic in
  // it; real certificates carry single digits.
  private val maxNames = 4096
  private val maxSubtrees = 4096

  // Subject-DN emailAddress values, for the rfc822Name fallback. A non-IA5 value cannot be a
  // mailbox, so it is dropped rather than decoded into one.
  def emailAttributes(subject: List[List[Ava]]): List[String] =
    subject.flatten.collect {
      case a if Names.bytesEqual(a.oid, oidEmailAddress) && a.content.forall(_ >= 0) => new String(a.content, "US-ASCII")
    }

  // Every key a certificate yields. A peer supplies the encoding, and a backend that meets an
  // unvalidated key inside its own call reports a defect rather than a typed outcome - node does
  // exactly that for a point off its curve - so the import has to happen before the key is handed
  // out, `agree` having no channel to carry a refusal at all. Every arm returned here is the import's
  // own verdict, so this accessor and the core door cannot name one encoding differently.
  def verifyingKey(spki: Array[Byte]): Eff[InvalidKey, ImportedPublicKey] =
    PublicKey.parse(SPKI(Slice.of(spki)))

  // BadSignature is reserved for a verification that ran and failed, which is the only outcome an
  // auditor can read as a forgery signal; a key that will not import means none ran. The match is
  // exhaustive, so a new InvalidKey arm is a compile error here.
  def keyFailure(reason: InvalidKey): PathInvalid = reason match
    case InvalidKey.Unsupported => PathInvalid.UnsupportedAlgorithm
    case InvalidKey.Malformed | InvalidKey.NotOnCurve | InvalidKey.WeakPoint | InvalidKey.WrongLength(_, _) =>
      PathInvalid.MalformedChain
end X509

/** An X.509 certificate, parsed once at construction; construct and read via
  * [[Certificate$ Certificate]].
  */
opaque type Certificate = Parsed
object Certificate:
  /** Two certificates are the same certificate when their DER is the same bytes. */
  given CanEqual[Certificate, Certificate] = CanEqual.derived

  /** A certificate is one DER document (RFC 5280) or its PEM text (RFC 7468): two serialisations of
    * one value, discriminated by parameter type, so they share the `parse` name. The DER form
    * rejects trailing bytes; the PEM form reads the first CERTIFICATE block, ignoring text outside
    * the encapsulation boundaries - the dump `openssl x509 -text` writes ahead of the block (RFC
    * 7468 section 5.2).
    */
  def parse(der: Array[Byte]): Either[Malformed, Certificate] =
    X509.parse(IArray.from(der)).left.map(_ => Malformed)

  def parse(pem: String): Either[Malformed, Certificate] =
    kufuli.PEM
      .decode(encapsulated(pem))
      .flatMap {
        case kufuli.PEM.Block.Certificate(der) => parse(Array.from(der.iterator))
        case _                                 => Left(Malformed)
      }

  /** Parses every CERTIFICATE block of a bundle in file order - a `fullchain.pem` is leaf first.
    * Named for its RESULT shape, which no parameter type carries.
    */
  def chain(pem: String): Either[Malformed, List[Certificate]] =
    kufuli.PEM.decodeAll(encapsulated(pem)).flatMap { blocks =>
      val ders = blocks.collect { case kufuli.PEM.Block.Certificate(der) => der }
      if ders.isEmpty then Left(Malformed)
      else
        val parsed = ders.map(b => parse(Array.from(b.iterator)))
        if parsed.forall(_.isRight) then Right(parsed.collect { case Right(c) => c }) else Left(Malformed)
    }

  // RFC 7468 section 5.2 permits explanatory text around the encapsulation boundaries, which the
  // shared PEM reader treats as a framing error, so it is dropped before decoding.
  private def encapsulated(pem: String): String =
    def boundary(line: String, keyword: String): Boolean = line.startsWith(s"-----$keyword ") && line.endsWith("-----")
    @tailrec def go(rest: List[String], inside: Boolean, acc: List[String]): List[String] =
      rest match
        case Nil          => acc.reverse
        case line :: tail =>
          if inside then go(tail, !boundary(line, "END"), line :: acc)
          else if boundary(line, "BEGIN") then go(tail, true, line :: acc)
          else go(tail, false, acc)
    go(pem.linesIterator.map(_.trim).toList, false, Nil).mkString("\n")

  extension (cert: Certificate)
    private[x509] def parsed: Parsed = cert
    def der: IArray[Byte] = cert.parsed.encoded

    /** The subject public key, imported through the backend, so what it yields is a key every
      * operation can be handed: [[InvalidKey.Unsupported]] names an algorithm kufuli does not
      * implement or an RSA modulus below 2048 bits, and the remaining cases report the encoding the
      * backend refused.
      */
    def publicKey: Eff[InvalidKey, ImportedPublicKey] = X509.verifyingKey(cert.parsed.spki)

    /** Start of the validity window, as epoch seconds. */
    def notBefore: Long = cert.parsed.notBefore

    /** End of the validity window, as epoch seconds. */
    def notAfter: Long = cert.parsed.notAfter

    /** The dNSName SAN entries, wildcard patterns included. */
    def subjectAltDns: List[String] = cert.parsed.san.fold(List.empty[String])(_.dns)

    def subjectAltIps: List[IpAddress] = cert.parsed.san.fold(List.empty[IpAddress])(_.ips.map(IpAddress.wrap))

    def subjectAltEmails: List[String] = cert.parsed.san.fold(List.empty[String])(_.emails)

    /** The uniformResourceIdentifier SAN entries, verbatim - SPIFFE SVIDs carry their identity
      * here. kufuli never authenticates one: a URI is not a server identity, and a URI name
      * constraint rejects the chain rather than being interpreted.
      */
    def subjectAltUris: List[String] = cert.parsed.san.fold(List.empty[String])(_.uris)

    /** The subject Name, as the encoded `RDNSequence`. */
    def subjectDer: IArray[Byte] = IArray.from(cert.parsed.subjectDer.iterator)

    /** The issuer Name, as the encoded `RDNSequence`. */
    def issuerDer: IArray[Byte] = IArray.from(cert.parsed.issuerDer.iterator)
  end extension
end Certificate

/** A DNS name in preferred name syntax, ASCII-folded at construction; construct via
  * [[Hostname$ Hostname]].
  */
opaque type Hostname = String
object Hostname:
  given CanEqual[Hostname, Hostname] = CanEqual.derived

  /** Accepts a name of LDH labels, at most 253 octets, with one optional trailing root dot stripped
    * and an all-numeric final label rejected as an IP literal. An A-label passes through as it
    * stands; converting a U-label to its A-label is the caller's, since IDNA needs a Unicode
    * profile kufuli does not carry.
    */
  def parse(name: String): Either[Malformed, Hostname] =
    val rooted = if name.endsWith(".") then name.substring(0, name.length - 1) else name
    if rooted.isEmpty || !Names.validDnsBase(rooted) then Left(Malformed)
    else if rooted.substring(rooted.lastIndexOf('.') + 1).forall(c => c >= '0' && c <= '9') then Left(Malformed)
    else Right(Names.foldAscii(rooted))

  /** The wire-text contract: decode IS `parse` (which case-folds, so the normalising decode stays
    * idempotent through re-encoding), encode the folded name.
    */
  given valueCodec: ValueCodec.Aux[Hostname, Malformed] = ValueCodec(parse, h => h)

  extension (h: Hostname) def value: String = h
end Hostname

/** The anchors a path must terminate at, non-empty by construction; build via
  * [[TrustAnchors$ TrustAnchors]].
  */
final class TrustAnchors private (val anchors: List[Certificate])
object TrustAnchors:
  /** The pinned-anchor flow, where the set is known at the call site. */
  def apply(anchor: Certificate, more: Certificate*): TrustAnchors = new TrustAnchors(anchor :: more.toList)

  /** The configuration flow: `Certificate.chain(pem).flatMap(TrustAnchors.of)` reports a
    * zero-certificate bundle once, in one vocabulary.
    */
  def of(anchors: List[Certificate]): Either[Malformed, TrustAnchors] =
    if anchors.isEmpty then Left(Malformed) else Right(new TrustAnchors(anchors))

// What a chain is validated for; selects the extended-key-usage OID every path certificate must
// permit. The entry point names the purpose, so this never reaches a caller.
private[x509] enum PathPurpose derives CanEqual:
  case ServerAuth, ClientAuth

/** A validated leaf together with the intermediates it was presented with. */
final case class VerifiedPath(leaf: Certificate, chain: List[Certificate]) derives CanEqual

/** RFC 5280 path validation for the TLS profile, at a caller-supplied instant in epoch seconds -
  * kufuli reads no clock. Chain building, the validity window, basic constraints, key usage,
  * extended key usage, name constraints (RFC 5280 section 4.2.1.10 over dNSName, iPAddress,
  * directoryName and rfc822Name; anchor constraints per RFC 5937) and identity matching (RFC 9525)
  * are evaluated; certificate policies, CRLs and live OCSP are not, so a certificate marking any
  * other extension critical is rejected rather than accepted unconstrained.
  *
  * A directoryName constraint compares attribute values as encoded, relaxed to ASCII case-folding
  * and insignificant-space handling only where both are `PrintableString` or `UTF8String` and
  * wholly ASCII; RFC 5280 section 4.2.1.10 requires a CA to state such a constraint in the encoding
  * the subject itself uses, and one stated in another encoding does not match.
  */
object CertPath:
  /** Validates `chain`, leaf first, against `id` - the name the connection was made to. */
  def verify(chain: List[Certificate], anchors: TrustAnchors, at: Long, id: ServerId): Eff[PathInvalid, VerifiedPath] =
    run(chain, anchors, at, Some(id), PathPurpose.ServerAuth)

  /** Validates a client chain for mTLS; the identity is read off the verified leaf afterwards. */
  def verifyClient(chain: List[Certificate], anchors: TrustAnchors, at: Long): Eff[PathInvalid, VerifiedPath] =
    run(chain, anchors, at, None, PathPurpose.ClientAuth)

  private def run(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long,
    id: Option[ServerId],
    purpose: PathPurpose
  ): Eff[PathInvalid, VerifiedPath] =
    chain match
      case Nil                   => Eff.fail(PathInvalid.MalformedChain)
      case leaf :: intermediates =>
        engine
          .validate(engine.paths(leaf, intermediates, anchors), at, id, purpose)
          .map(_ => VerifiedPath(leaf, intermediates))
end CertPath

private object engine:
  private val maxDepth = 16
  private val maxCandidates = 8

  // The ceiling is on edges FOLLOWED across the whole walk, not on candidates found: an attacker
  // supplies the intermediate pool, same-DN certificates permute factorially, and a pool reaching no
  // anchor yields no candidates for a candidate ceiling to bind on.
  private val maxSteps = 128

  // OpenSSL's NAME_CHECK_MAX. The constraint walk is names x accumulated subtrees and an attacker
  // supplies both sides, so the product is what needs a ceiling.
  private val maxNameChecks = 1 << 20

  private def bytesEq(a: Array[Byte], b: Array[Byte]): Boolean = Slice.of(a).contentEquals(Slice.of(b))

  // `bounded` separates a walk that reached no anchor from one stopped before it could: the two are
  // different verdicts about the chain.
  private type Walk = (found: List[List[Certificate]], steps: Int, bounded: Boolean)

  // Candidate paths leaf-first, anchor last, in the order the walk meets them. Linking is by
  // subject/issuer DN alone, and a CA key rollover reuses the DN across two certificates, so
  // committing to the first match would fail a chain that a later match verifies.
  def paths(leaf: Certificate, intermediates: List[Certificate], anchors: TrustAnchors): Walk =
    def go(current: Certificate, pool: List[Certificate], acc: List[Certificate], depth: Int, state: Walk): Walk =
      val issuer = current.parsed.issuerDer
      val walked = (current :: acc).reverse
      val reached = anchors.anchors.foldLeft(state) { (s, anchor) =>
        if s.found.sizeIs >= maxCandidates || !bytesEq(anchor.parsed.subjectDer, issuer) then s
        else (found = s.found :+ (walked ::: List(anchor)), steps = s.steps, bounded = s.bounded)
      }
      if depth >= maxDepth then reached
      else
        pool.foldLeft(reached) { (s, next) =>
          if s.found.sizeIs >= maxCandidates || !bytesEq(next.parsed.subjectDer, issuer) then s
          else if s.steps <= 0 then (found = s.found, steps = s.steps, bounded = true)
          else go(next, pool.filterNot(_ == next), current :: acc, depth + 1, (found = s.found, steps = s.steps - 1, bounded = s.bounded))
        }
    end go
    if anchors.anchors.exists(_ == leaf) then (found = List(List(leaf)), steps = maxSteps, bounded = false)
    else go(leaf, intermediates, Nil, 0, (found = Nil, steps = maxSteps, bounded = false))
  end paths

  // The first candidate's failure is the one reported: it is the path the chain was assembled for,
  // so its error describes what the peer actually presented. A walk the budget cut short reports the
  // bound, because an absent anchor is a fact it did not establish.
  def validate(walk: Walk, at: Long, id: Option[ServerId], purpose: PathPurpose): Eff[PathInvalid, Unit] =
    def exhausted: PathInvalid = if walk.bounded then PathInvalid.LimitExceeded else PathInvalid.UntrustedAnchor
    def go(rest: List[List[Certificate]], first: Option[PathInvalid]): Eff[PathInvalid, Unit] =
      rest match
        case Nil          => Eff.fail(first.getOrElse(exhausted))
        case path :: tail => check(path, at, id, purpose).catchAll(e => go(tail, first.orElse(Some(e))))
    go(walk.found, None)

  private def check(path: List[Certificate], at: Long, id: Option[ServerId], purpose: PathPurpose): Eff[PathInvalid, Unit] =
    path match
      case Nil          => Eff.fail(PathInvalid.MalformedChain)
      case leaf :: rest =>
        // RFC 5280 numbers the path [1..n] with the trust anchor outside it, so the anchor is
        // qualified rather than validated. The peer certificate never leaves the checked set: a
        // directly pinned leaf is the peer first and the terminus second.
        val terminus = path.last
        val checked = if rest.isEmpty then path else path.init
        val intermediates = checked.drop(1)
        val issuing = rest.nonEmpty
        if path.exists(c => at < c.notBefore || at > c.notAfter) then Eff.fail(PathInvalid.Expired)
        else if path.exists(_.parsed.unhandledCritical) then Eff.fail(PathInvalid.ConstraintViolated)
        else if intermediates.exists(c => !c.parsed.isCa.contains(true)) then Eff.fail(PathInvalid.ConstraintViolated)
        else if intermediates.exists(_.parsed.keyCertSign.contains(false)) then Eff.fail(PathInvalid.ConstraintViolated)
        else if issuing && !anchorQualifies(terminus) then Eff.fail(PathInvalid.ConstraintViolated)
        else if checked.exists(constrainsWithoutAuthority) then Eff.fail(PathInvalid.ConstraintViolated)
        else if pathLenExceeded(rest) then Eff.fail(PathInvalid.ConstraintViolated)
        else if !checked.forall(c => ekuAllows(c.parsed.ekus, purpose)) then Eff.fail(PathInvalid.ConstraintViolated)
        else if !nameOk(leaf, id) then Eff.fail(PathInvalid.NameMismatch)
        else verifyChain(leaf, rest).flatMap(_ => Eff.from(constrained(path, id)))
  end check

  // RFC 5937 section 3.1: an anchor is qualified by what it declares, and an anchor that declares
  // itself not a CA cannot issue. A v1 root declares nothing at all and is still a real anchor.
  private def anchorQualifies(anchor: Certificate): Boolean =
    !anchor.parsed.isCa.contains(false) && !anchor.parsed.keyCertSign.contains(false)

  // RFC 5280 section 4.2.1.10: name constraints "MUST be used only in a CA certificate".
  private def constrainsWithoutAuthority(cert: Certificate): Boolean =
    cert.parsed.constraints.isDefined && !cert.parsed.isCa.contains(true)

  // A CA's pathLenConstraint bounds the number of intermediate CA certs that may follow it toward
  // the leaf. Self-issued intermediates are counted here - a conservative over-count relative to
  // RFC 5280 section 6.1.4, which excludes them (rare in the TLS profile).
  private def pathLenExceeded(issuers: List[Certificate]): Boolean =
    issuers.zipWithIndex.exists((c, i) => c.parsed.maxPathLen.exists(_ < i))

  // Applied to every certificate in the path, not only the leaf: an intermediate restricted to one
  // purpose cannot widen it for the certificates it issues.
  private def ekuAllows(ekus: List[String], purpose: PathPurpose): Boolean =
    if ekus.isEmpty then true
    else
      purpose match
        case PathPurpose.ServerAuth => ekus.contains(X509.ekuServerAuth)
        case PathPurpose.ClientAuth => ekus.contains(X509.ekuClientAuth)

  // Each identity form consults its own SAN form only, so the rfc822/URI-authenticated-as-a-domain
  // confusion (Envoy CVE-2022-21656) is not expressible. The CN is never read, on either side.
  private def nameOk(leaf: Certificate, id: Option[ServerId]): Boolean =
    id match
      case None                  => true
      case Some(ServerId.Dns(h)) => leaf.parsed.san.exists(_.dns.exists(matches(_, h.value)))
      case Some(ServerId.Ip(a))  => leaf.parsed.san.exists(_.ips.exists(_ == a.bits))

  // RFC 9525 section 6.3 SAN matching with a single leftmost wildcard label.
  private def matches(pattern: String, host: String): Boolean =
    val p = Names.foldAscii(pattern)
    val h = Names.foldAscii(host)
    if p == h then true
    else if p.startsWith("*.") then
      val suffix = p.substring(1) // ".example.com"
      val dot = h.indexOf('.')
      // A wildcard needs a label of its own beneath the suffix, or `*.com` covers every `.com` host.
      suffix.indexOf('.', 1) > 0 && dot > 0 && h.substring(dot) == suffix
    else false

  // RFC 5280 section 6.1.4(g) specifies an intersection of permitted subtree sets; the equivalent
  // conjunction over ancestors needs no empty-set representation. A name passes when, for EVERY
  // ancestor that constrains its form, it lies within one of that ancestor's permitted subtrees,
  // and within no excluded subtree of any ancestor. Excluded beats permitted unconditionally.
  private def constrained(path: List[Certificate], id: Option[ServerId]): Either[PathInvalid, Unit] =
    val state = path.flatMap(_.parsed.constraints)
    if state.isEmpty || path.sizeIs < 2 then Right(())
    else
      val checked = path.init
      val subtrees = state.map(nc => nc.permitted.size + nc.excluded.size).sum
      val names = checked.map(nameCount).sum + id.fold(0)(_ => 1)
      if names.toLong * subtrees.toLong > maxNameChecks then Left(PathInvalid.LimitExceeded)
      else
        val leafState = path.drop(1).flatMap(_.parsed.constraints)
        val walked = checked.zipWithIndex.forall { (cert, depth) =>
          // A self-issued certificate below the leaf is the same entity re-keyed, so RFC 5280
          // section 6.1.3 skips its names; its own constraints still fold into the state.
          if depth > 0 && bytesEq(cert.parsed.subjectDer, cert.parsed.issuerDer) then true
          else namesAllowed(cert, path.drop(depth + 1).flatMap(_.parsed.constraints))
        }
        // The identity is walked as a name of its own form. The wildcard containment rules already
        // place every name a permitted SAN matches inside the same subtrees, so this closes the
        // seam RFC 5280 and RFC 9525 each leave to the other (pyca CVE-2026-34073) a second time
        // rather than for the first - it survives either side being loosened alone.
        val identity = id match
          case None                  => true
          case Some(ServerId.Dns(h)) => dnsAllowed(h.value, leafState)
          case Some(ServerId.Ip(a))  => ipAllowed(a.bits, leafState)
        if walked && identity then Right(()) else Left(PathInvalid.NameConstraintViolated)
      end if
    end if
  end constrained

  private def nameCount(cert: Certificate): Int =
    1 + cert.parsed.san.fold(0)(s => s.dns.length + s.ips.length + s.emails.length + s.dirNames.length + s.unprocessed.size)

  private def namesAllowed(cert: Certificate, state: List[NameConstraints]): Boolean =
    val p = cert.parsed
    // RFC 5280 section 4.2.1.10 checks the subject DN's emailAddress attributes as rfc822Names
    // when the certificate carries no subjectAltName extension at all.
    val fallback =
      if p.san.isEmpty && state.exists(nc => nc.permitted.emails.nonEmpty || nc.excluded.emails.nonEmpty) then
        X509.emailAttributes(p.subject)
      else Nil
    unprocessedAllowed(p.san.fold(Set.empty[UnprocessedForm])(_.unprocessed), state) &&
    (p.subject.isEmpty || dnAllowed(p.subject, state)) &&
    p.san.forall(s =>
      s.dns.forall(dnsAllowed(_, state)) && s.ips.forall(ipAllowed(_, state)) &&
        s.emails.forall(emailAllowed(_, state)) && s.dirNames.forall(dnAllowed(_, state))
    ) &&
    // `Names.emailWithin` splits at the first `@`, so a value carrying more than one would be
    // matched on a domain reading past the separator. Such a value is a presented rfc822Name this
    // walk cannot match, which the type gate rejects once rfc822 state is non-vacuous.
    fallback.forall(v => Names.validEmail(v) && emailAllowed(v, state))
  end namesAllowed

  // A constraint on a form with no matching rule rejects a certificate presenting that form, and is
  // vacuous otherwise - RFC 5280 section 4.2.1.10's own conjunction, not a blanket rejection.
  private def unprocessedAllowed(presented: Set[UnprocessedForm], state: List[NameConstraints]): Boolean =
    presented.isEmpty || state.forall(nc => presented.intersect(nc.permitted.unprocessed ++ nc.excluded.unprocessed).isEmpty)

  private def dnsAllowed(name: String, state: List[NameConstraints]): Boolean =
    val pattern = Names.isWildcard(name)
    state.forall { nc =>
      (nc.permitted.dns.isEmpty ||
        nc.permitted.dns.exists(b => if pattern then Names.wildcardPermitted(name, b) else Names.dnsWithin(name, b))) &&
      !nc.excluded.dns.exists(b => if pattern then Names.wildcardExcluded(name, b) else Names.dnsWithin(name, b))
    }

  private def ipAllowed(name: IpBits, state: List[NameConstraints]): Boolean =
    state.forall(nc =>
      (nc.permitted.ips.isEmpty || nc.permitted.ips.exists(Names.ipWithin(name, _))) && !nc.excluded.ips.exists(Names.ipWithin(name, _))
    )

  private def dnAllowed(name: List[List[Ava]], state: List[NameConstraints]): Boolean =
    state.forall(nc =>
      (nc.permitted.dirNames.isEmpty || nc.permitted.dirNames.exists(Names.dnWithin(name, _))) &&
        !nc.excluded.dirNames.exists(Names.dnWithin(name, _))
    )

  private def emailAllowed(name: String, state: List[NameConstraints]): Boolean =
    state.forall(nc =>
      (nc.permitted.emails.isEmpty || nc.permitted.emails.exists(Names.emailWithin(name, _))) &&
        !nc.excluded.emails.exists(Names.emailWithin(name, _))
    )

  private def verifyChain(leaf: Certificate, issuers: List[Certificate]): Eff[PathInvalid, Unit] =
    // each cert (subject) is signed by the next (issuer); the anchor terminates the walk
    val pairs = (leaf :: issuers).zip(issuers)
    pairs.foldLeft(Eff.succeed(()): Eff[PathInvalid, Unit]) { (acc, pair) =>
      val (subject, issuer) = pair
      acc.flatMap(_ => verifyOne(subject, issuer))
    }

  private def verifyOne(subject: Certificate, issuer: Certificate): Eff[PathInvalid, Unit] =
    val sub = subject.parsed
    sub.sigScheme match
      case None         => Eff.fail(PathInvalid.UnsupportedAlgorithm)
      case Some(scheme) =>
        X509
          .verifyingKey(issuer.parsed.spki)
          .mapError(X509.keyFailure)
          .flatMap(key => verifyBy(scheme, key, Slice.of(sub.tbs), sub.signature).mapError(_ => PathInvalid.BadSignature))

  private[x509] def verifyBy(scheme: SigScheme, key: ImportedPublicKey, tbs: Slice, sig: Array[Byte]): Eff[SignatureRejected, Unit] =
    (scheme, key) match
      case (SigScheme.Ed, ImportedPublicKey.Ed(k)) =>
        Eff.from(Signature.of(Ed25519)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s))
      case (SigScheme.Ec(h), ImportedPublicKey.EcP256(k))    => ecVerify(P256, k, tbs, sig, h)
      case (SigScheme.Ec(h), ImportedPublicKey.EcP384(k))    => ecVerify(P384, k, tbs, sig, h)
      case (SigScheme.Ec(h), ImportedPublicKey.EcP521(k))    => ecVerify(P521, k, tbs, sig, h)
      case (SigScheme.RsaPkcs1(h), ImportedPublicKey.Rsa(k)) =>
        Eff.from(Signature.of(RSA)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s, kufuli.RsaPkcs1(h)))
      case (SigScheme.RsaPss(h), ImportedPublicKey.Rsa(k)) =>
        Eff.from(Signature.of(RSA)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s, kufuli.RsaPss(h)))
      case _ => Eff.fail(SignatureRejected)

  private def ecVerify[C <: EcCurve](
    curve: EcSpec[C],
    key: PublicKey[C],
    tbs: Slice,
    sig: Array[Byte],
    hash: Sha2
  )(using Verifying[C]): Eff[SignatureRejected, Unit] =
    Eff.from(Signature.parse(curve)(Signature.Der(IArray.from(sig)))).mapError(_ => SignatureRejected).flatMap(s => key.verify(tbs, s, hash))
end engine

/** Verifies a stapled OCSP response the caller supplies (from the TLS handshake). No network I/O is
  * performed; live OCSP and CRL fetching are out of scope.
  */
object OCSP:
  enum Status derives CanEqual:
    case Good
    case Revoked(at: Long)
    case Unknown

  /** The certificate status a stapled OCSP response asserts about `leaf`, once the response is
    * shown to come from a responder `issuer` authorises and to carry an entry naming `leaf` under
    * `issuer`.
    *
    * The signer is `issuer` itself, or a responder `issuer` delegated: a certificate the response
    * carries, signed by `issuer`, valid at `at`, and marked with the OCSP-signing extended key
    * usage (RFC 6960 section 4.2.2.2). A responder may batch, so every SingleResponse is read and
    * the one whose certID names `leaf` decides; a response carrying no such entry is
    * [[PathInvalid.ResponseMismatch]], since it attests nothing about this certificate, and one
    * carrying more than 64 is [[PathInvalid.LimitExceeded]] whatever it says about this leaf.
    * [[Status.Unknown]] means the responder itself declined to answer - an `unknown` status, a
    * responseStatus other than successful, or a `good` outside the response's own
    * thisUpdate/nextUpdate window at `at`.
    */
  def verifyStapled(response: Array[Byte], leaf: Certificate, issuer: Certificate, at: Long): Eff[PathInvalid, OCSP.Status] =
    Eff.from(parseResponse(response, at)).flatMap {
      case None    => Eff.succeed(OCSP.Status.Unknown)
      case Some(r) =>
        signerKeys(r, issuer, at)
          .flatMap(keys => verifiedBy(keys, r))
          .flatMap(_ => select(r.entries, leaf, issuer))
          .map(entry => if entry.current then entry.status else stale(entry.status))
    }

  // One SingleResponse: the certificate it names, the status it carries, and whether that status
  // speaks for `at`.
  final private case class Entry(
    hashOid: Array[Byte],
    issuerNameHash: Array[Byte],
    issuerKeyHash: Array[Byte],
    serial: Array[Byte],
    status: OCSP.Status,
    current: Boolean
  )

  // Everything a verified decision reads, taken in one pass over the response.
  final private case class Basic(tbs: Slice, scheme: SigScheme, signature: Array[Byte], certs: List[Array[Byte]], entries: List[Entry])

  // A response outside its own validity window asserts nothing about now, so its `Good` is not
  // honoured; `Revoked` stands, since ageing does not undo a revocation.
  private def stale(status: OCSP.Status): OCSP.Status =
    status match
      case OCSP.Status.Good => OCSP.Status.Unknown
      case other            => other

  // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ResponseBytes }.
  // A responseStatus other than successful(0) carries no body, so there is nothing to verify and
  // `None` stands for "the responder declined".
  private def parseResponse(response: Array[Byte], at: Long): Either[PathInvalid, Option[Basic]] =
    if response.isEmpty then Left(PathInvalid.MalformedChain)
    else
      val s = Slice.of(response)
      val outcome =
        for
          outer <- DER.read(s, 0, 0x30)
          // Anything past the OCSPResponse is a second encoding of one staple, which is what lets a
          // cache or an audit log keyed on the bytes stop identifying the response.
          _ <- if outer.next == s.length then Right(()) else Left(InvalidKey.Malformed)
          respStatus <- within(s, outer.contentOff, 0x0a, outer.next)
          // The status is one octet, so a longer ENUMERATED whose first octet is zero is not a
          // second spelling of successful(0).
          _ <- if respStatus.contentLen == 1 then Right(()) else Left(InvalidKey.Malformed)
        yield if (s(respStatus.contentOff) & 0xff) != 0 then None else Some((respStatus.next, outer.next))
      outcome.left.map(_ => PathInvalid.MalformedChain).flatMap {
        case None                => Right(None)
        case Some((next, limit)) => basic(s, next, limit, at).map(Some(_))
      }

  // OCSPResponse -> responseBytes [0] -> ResponseBytes { OID, OCTET STRING } -> BasicOCSPResponse
  // { tbsResponseData, signatureAlgorithm, signature BIT STRING, certs [0] EXPLICIT OPTIONAL }. The
  // OCTET STRING content is DER in place, so the inner reads continue over the same slice.
  // Every element is bounded by the one that contains it: the shared reader bounds a TLV by the
  // whole buffer, so a child claiming a length past its parent would otherwise read a sibling's
  // bytes - here, entries from outside the region the signature covers.
  private def basic(s: Slice, afterStatus: Int, limit: Int, at: Long): Either[PathInvalid, Basic] =
    val structure =
      for
        rb <- within(s, afterStatus, 0xa0, limit) // responseBytes [0] EXPLICIT
        rbSeq <- within(s, rb.contentOff, 0x30, rb.next) // ResponseBytes
        oid <- within(s, rbSeq.contentOff, 0x06, rbSeq.next) // responseType OID
        octet <- within(s, oid.next, 0x04, rbSeq.next) // response OCTET STRING (DER BasicOCSPResponse)
        basicSeq <- within(s, octet.contentOff, 0x30, octet.next) // BasicOCSPResponse
        tbs <- within(s, basicSeq.contentOff, 0x30, basicSeq.next) // tbsResponseData (ResponseData)
        sigAlg <- within(s, tbs.next, 0x30, basicSeq.next) // signatureAlgorithm
        sigBits <- within(s, sigAlg.next, 0x03, basicSeq.next) // signature BIT STRING
        _ <- if sigBits.contentLen >= 1 then Right(()) else Left(InvalidKey.Malformed)
        certs <- responderCerts(s, sigBits.next, basicSeq.next)
        responses <- toResponses(s, tbs)
      yield (sigAlg = sigAlg, tbs = tbs, basicSeq = basicSeq, sigBits = sigBits, certs = certs, responses = responses)
    structure.left.map(_ => PathInvalid.MalformedChain).flatMap { r =>
      readEntries(s, r.responses.contentOff, r.responses.next, at, Nil).flatMap { entries =>
        // A conforming response naming an algorithm kufuli does not implement is unsupported, not
        // unparseable; an auditor cannot act on the two the same way.
        X509
          .sigScheme(s, r.sigAlg)
          .toRight(PathInvalid.UnsupportedAlgorithm)
          .map(scheme =>
            Basic(
              // The signature covers the tbsResponseData element whole, so the verified bytes start
              // at its tag, not at its content.
              tbs = s.slice(r.basicSeq.contentOff, r.tbs.next),
              scheme = scheme,
              signature = s.slice(r.sigBits.contentOff + 1, r.sigBits.next).toArray,
              certs = r.certs,
              entries = entries
            )
          )
      }
    }
  end basic

  // A responder may answer for many certificates in one response, so every entry is read; the cap
  // bounds the hashing the binding search costs. Entries are read before any is selected, so a
  // response carrying more than this is refused whole - the position of this leaf's entry within it
  // does not matter.
  private inline val maxEntries = 64

  private def readEntries(s: Slice, off: Int, end: Int, at: Long, acc: List[Entry]): Either[PathInvalid, List[Entry]] =
    if off >= end then Right(acc.reverse)
    else if acc.length >= maxEntries then Left(PathInvalid.LimitExceeded)
    else
      val entry =
        for
          single <- within(s, off, 0x30, end) // SingleResponse
          certId <- within(s, single.contentOff, 0x30, single.next) // certID
          id <- certIdentity(s, certId)
          status <- statusTag(s, certId.next, single.next)
          current <- fresh(s, status.next, single.next, at)
        yield (
          next = single.next,
          entry = Entry(id.hashOid, id.nameHash, id.keyHash, id.serial, status.value, current)
        )
      entry match
        case Left(_)  => Left(PathInvalid.MalformedChain)
        case Right(e) => readEntries(s, e.next, end, at, e.entry :: acc)

  // RFC 6960 section 4.1.1: the certID names the certificate by the hash of its issuer's name, the
  // hash of its issuer's public key, and its own serial. Selecting on all three is what makes a
  // signed response about one certificate unable to answer for another; an entry whose hash
  // algorithm kufuli does not implement cannot be shown to name `leaf` and so does not select it.
  private def select(entries: List[Entry], leaf: Certificate, issuer: Certificate): Eff[PathInvalid, Entry] =
    entries match
      case Nil          => Eff.fail(PathInvalid.ResponseMismatch)
      case head :: rest =>
        binds(head, leaf, issuer).flatMap(matched => if matched then Eff.succeed(head) else select(rest, leaf, issuer))

  private def binds(entry: Entry, leaf: Certificate, issuer: Certificate): Eff[PathInvalid, Boolean] =
    if !Slice.of(entry.serial).contentEquals(Slice.of(leaf.parsed.serial)) then Eff.succeed(false)
    else
      Eff.from(DER.spkiPublicBits(Slice.of(issuer.parsed.spki))).mapError(_ => PathInvalid.MalformedChain).flatMap { keyBits =>
        digestBy(entry.hashOid, Slice.of(leaf.parsed.issuerDer)).flatMap { nameHash =>
          digestBy(entry.hashOid, keyBits).map { keyHash =>
            (nameHash, keyHash) match
              case (Some(n), Some(k)) =>
                Slice.of(Array.from(n.bytes.iterator)).contentEquals(Slice.of(entry.issuerNameHash)) &&
                Slice.of(Array.from(k.bytes.iterator)).contentEquals(Slice.of(entry.issuerKeyHash))
              case _ => false
          }
        }
      }

  private val oidSha1 = Array[Byte](0x2b, 0x0e, 0x03, 0x02, 0x1a)
  private val oidSha256 = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
  private val oidSha384 = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
  private val oidSha512 = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)

  private def digestBy(oid: Array[Byte], data: Slice): Eff[PathInvalid, Option[Digest]] =
    val id = Slice.of(oid)
    if id.contentEquals(Slice.of(oidSha1)) then Sha1.digest(data).map(Some(_))
    else if id.contentEquals(Slice.of(oidSha256)) then Sha256.digest(data).map(Some(_))
    else if id.contentEquals(Slice.of(oidSha384)) then Sha384.digest(data).map(Some(_))
    else if id.contentEquals(Slice.of(oidSha512)) then Sha512.digest(data).map(Some(_))
    else Eff.succeed(None)

  // CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET STRING,
  // issuerKeyHash OCTET STRING, serialNumber INTEGER }.
  private def certIdentity(
    s: Slice,
    certId: DER.Tlv
  ): Either[InvalidKey, (hashOid: Array[Byte], nameHash: Array[Byte], keyHash: Array[Byte], serial: Array[Byte])] =
    for
      algId <- within(s, certId.contentOff, 0x30, certId.next)
      oid <- within(s, algId.contentOff, 0x06, algId.next)
      nameHash <- within(s, algId.next, 0x04, certId.next)
      keyHash <- within(s, nameHash.next, 0x04, certId.next)
      serial <- within(s, keyHash.next, 0x02, certId.next)
    yield (
      hashOid = s.slice(oid.contentOff, oid.next).toArray,
      nameHash = s.slice(nameHash.contentOff, nameHash.next).toArray,
      keyHash = s.slice(keyHash.contentOff, keyHash.next).toArray,
      serial = s.slice(serial.contentOff, serial.next).toArray
    )

  // certs [0] EXPLICIT SEQUENCE OF Certificate. A real staple carries none or one; the cap bounds
  // the signature attempts an unauthenticated response can demand.
  private inline val maxResponderCerts = 8

  private def responderCerts(s: Slice, off: Int, end: Int): Either[InvalidKey, List[Array[Byte]]] =
    if off >= end || (s(off) & 0xff) != 0xa0 then Right(Nil)
    else
      for
        wrapper <- within(s, off, 0xa0, end)
        list <- within(s, wrapper.contentOff, 0x30, wrapper.next)
        certs <- readCerts(s, list.contentOff, list.next, Nil)
      yield certs

  @tailrec private def readCerts(s: Slice, off: Int, end: Int, acc: List[Array[Byte]]): Either[InvalidKey, List[Array[Byte]]] =
    if off >= end || acc.length >= maxResponderCerts then Right(acc.reverse)
    else
      DER.read(s, off, 0x30) match
        case Left(e)  => Left(e)
        case Right(c) => readCerts(s, c.next, end, s.slice(off, c.next).toArray :: acc)

  // RFC 6960 section 4.2.2.2: the responder is the issuing CA, or a certificate that CA signed and
  // marked for OCSP signing. Anything else in `certs` is ignored, so an attacker-supplied
  // certificate cannot become a signer by being carried along.
  // A candidate the issuer signed but whose own key kufuli cannot import contributes no signer.
  // That is not a rejected signature, so it never enters the signature channel.
  private def candidateKey(spki: Array[Byte]): UEff[Option[ImportedPublicKey]] =
    X509.verifyingKey(spki).map(Some(_)).catchAll(_ => Eff.succeed(None))

  private def signerKeys(r: Basic, issuer: Certificate, at: Long): Eff[PathInvalid, List[ImportedPublicKey]] =
    val own = X509.verifyingKey(issuer.parsed.spki).mapError(X509.keyFailure)
    val candidates = r.certs.flatMap(der => X509.parse(IArray.from(der)).toOption).filter(c => at >= c.notBefore && at <= c.notAfter)
    own.flatMap { issuerKey =>
      candidates
        // RFC 5280 section 6.1.4: a certificate marking an extension kufuli cannot process is not
        // one to proceed past, and a delegated responder is a certificate like any other.
        .filter(c => c.ekus.contains(X509.ekuOcspSigning) && !c.unhandledCritical)
        .foldLeft(Eff.succeed(List(issuerKey)): Eff[PathInvalid, List[ImportedPublicKey]]) { (acc, candidate) =>
          acc.flatMap { keys =>
            candidate.sigScheme match
              case None         => Eff.succeed(keys)
              case Some(scheme) =>
                engine
                  .verifyBy(scheme, issuerKey, Slice.of(candidate.tbs), candidate.signature)
                  .flatMap(_ => candidateKey(candidate.spki))
                  .map(_.fold(keys)(_ :: keys))
                  .catchAll(_ => Eff.succeed(keys))
          }
        }
    }
  end signerKeys

  private def verifiedBy(keys: List[ImportedPublicKey], r: Basic): Eff[PathInvalid, Unit] =
    keys
      .map(key => engine.verifyBy(r.scheme, key, r.tbs, r.signature).mapError(_ => PathInvalid.BadSignature))
      .reduceOption((first, next) => first.catchAll(_ => next))
      .getOrElse(Eff.fail(PathInvalid.BadSignature))

  // ResponseData ::= SEQUENCE { version [0] OPTIONAL, responderID CHOICE([1] byName/[2] byKey),
  // producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse, ... }.
  private def toResponses(s: Slice, tbs: DER.Tlv): Either[InvalidKey, DER.Tlv] =
    def tagAt(off: Int): Int = if off < tbs.next then s(off) & 0xff else -1
    val afterVersion =
      if tagAt(tbs.contentOff) == 0xa0 then within(s, tbs.contentOff, 0xa0, tbs.next).map(_.next)
      else Right(tbs.contentOff)
    afterVersion.flatMap { av =>
      val rid = tagAt(av)
      (if rid == 0xa1 || rid == 0xa2 then within(s, av, rid, tbs.next).map(_.next) else Left(InvalidKey.Malformed))
        .flatMap(ar => within(s, ar, 0x18, tbs.next).flatMap(pa => within(s, pa.next, 0x30, tbs.next)))
    }

  // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
  // unknown [2] IMPLICIT UnknownInfo }. RevokedInfo's first field is revocationTime GeneralizedTime.
  private def statusTag(s: Slice, off: Int, end: Int): Either[InvalidKey, (value: OCSP.Status, next: Int)] =
    if off >= end then Left(InvalidKey.Malformed)
    else
      (s(off) & 0xff) match
        // good and unknown are IMPLICIT NULL, so their content is empty; a status carrying octets
        // is a second spelling of a verdict that already has exactly one.
        case 0x80 =>
          within(s, off, 0x80, end).filterOrElse(_.contentLen == 0, InvalidKey.Malformed).map(t => (value = OCSP.Status.Good, next = t.next))
        case 0x82 =>
          within(s, off, 0x82, end)
            .filterOrElse(_.contentLen == 0, InvalidKey.Malformed)
            .map(t => (value = OCSP.Status.Unknown, next = t.next))
        case 0xa1 =>
          within(s, off, 0xa1, end).flatMap { info =>
            within(s, info.contentOff, 0x18, info.next).flatMap { t =>
              generalizedTime(s, t).map(e => (value = OCSP.Status.Revoked(e), next = info.next))
            }
          }
        case _ => Left(InvalidKey.Malformed)

  // SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate GeneralizedTime,
  // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions [1] EXPLICIT OPTIONAL }.
  // An absent nextUpdate means the responder has newer information at all times (RFC 6960 section
  // 4.2.2.1), so only the lower bound applies.
  private def fresh(s: Slice, off: Int, end: Int, at: Long): Either[InvalidKey, Boolean] =
    for
      tu <- within(s, off, 0x18, end)
      from <- generalizedTime(s, tu)
      until <-
        if tu.next < end && (s(tu.next) & 0xff) == 0xa0 then
          within(s, tu.next, 0xa0, end)
            .flatMap(w => within(s, w.contentOff, 0x18, w.next))
            .flatMap(t => generalizedTime(s, t))
            .map(Some(_))
        else Right(None)
    yield at >= from && until.forall(at <= _)

  private def generalizedTime(s: Slice, t: DER.Tlv): Either[InvalidKey, Long] =
    val str = new String(s.slice(t.contentOff, t.next).toArray, "US-ASCII")
    X509.parseTime(str, generalized = true).toRight(InvalidKey.Malformed)

  private def within(s: Slice, off: Int, tag: Int, limit: Int): Either[InvalidKey, DER.Tlv] = DER.within(s, off, tag, limit)
end OCSP
