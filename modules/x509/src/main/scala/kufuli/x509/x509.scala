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
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.effect.EffIO

import kufuli.*

sealed abstract class X509Error(message: String) extends Exception(message) with NoStackTrace derives CanEqual

// Payload-free cases are a class plus a co-named object, and type positions name the CLASS: a union
// of singleton types does not survive the TypeTest reification `either`/`catchAll` rely on.
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
end PathInvalid

// Everything path validation reads from a certificate, extracted once at construction: `Certificate`
// is opaque over this, so no accessor re-parses.
final private[x509] case class Parsed(
  encoded: IArray[Byte],
  tbs: Array[Byte],
  spki: Array[Byte],
  issuerDer: Array[Byte],
  subjectDer: Array[Byte],
  notBefore: Long,
  notAfter: Long,
  sanDns: List[String],
  isCa: Boolean,
  maxPathLen: Option[Int],
  ekus: List[String],
  keyCertSign: Option[Boolean],
  unhandledCritical: Boolean,
  sigScheme: Option[SigScheme],
  signature: Array[Byte]
)

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
  private val oidEku = Array[Byte](0x55, 0x1d, 0x25)
  // EKU purpose OIDs.
  val ekuServerAuth = "1.3.6.1.5.5.7.3.1"
  val ekuClientAuth = "1.3.6.1.5.5.7.3.2"

  private def eq(a: Slice, b: Array[Byte]): Boolean = a.contentEquals(Slice.of(b))

  private def sigScheme(oid: Slice): Option[SigScheme] =
    if eq(oid, ed25519) then Some(SigScheme.Ed)
    else if eq(oid, ecdsaSha256) then Some(SigScheme.Ec(Sha256))
    else if eq(oid, ecdsaSha384) then Some(SigScheme.Ec(Sha384))
    else if eq(oid, ecdsaSha512) then Some(SigScheme.Ec(Sha512))
    else if eq(oid, rsaSha256) then Some(SigScheme.RsaPkcs1(Sha256))
    else if eq(oid, rsaSha384) then Some(SigScheme.RsaPkcs1(Sha384))
    else if eq(oid, rsaSha512) then Some(SigScheme.RsaPkcs1(Sha512))
    else if eq(oid, rsaPss) then Some(SigScheme.RsaPss(Sha256))
    else None

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

  private def read(der: Slice, off: Int, tag: Int): Either[PathInvalid, Der.Tlv] =
    Der.read(der, off, tag).left.map(_ => PathInvalid.MalformedChain)

  // The core reader bounds a TLV by the whole buffer, not by the structure that contains it, so a
  // child claiming a length past its parent would otherwise read a sibling's bytes as its own.
  private def read(der: Slice, off: Int, tag: Int, limit: Int): Either[PathInvalid, Der.Tlv] =
    read(der, off, tag).filterOrElse(_.next <= limit, PathInvalid.MalformedChain)

  // One TLV occupying the whole slice, for extension values, which carry exactly one encoding.
  private def only(der: Slice, tag: Int): Either[PathInvalid, Der.Tlv] =
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
      sigOid <- read(s, sigAlg.contentOff, 0x06, sigAlg.next)
      sigBits <- read(s, sigAlg.next, 0x03, cert.next)
      _ <- wellFormed(sigBits.next == cert.next && sigBits.contentLen >= 1)
      fields <- tbsFields(s, tbs)
      ext <- extensions(s, fields.exts)
    yield Parsed(
      encoded = der,
      tbs = s.slice(cert.contentOff, tbs.next).toArray,
      spki = fields.spki,
      issuerDer = fields.issuerDer,
      subjectDer = fields.subjectDer,
      notBefore = fields.notBefore,
      notAfter = fields.notAfter,
      sanDns = ext.sanDns,
      isCa = ext.isCa,
      maxPathLen = ext.maxPathLen,
      ekus = ext.ekus,
      keyCertSign = ext.keyCertSign,
      unhandledCritical = ext.unhandledCritical,
      sigScheme = sigScheme(s.slice(sigOid.contentOff, sigOid.next)),
      signature = s.slice(sigBits.contentOff + 1, sigBits.next).toArray
    )
    end for
  end parse

  // Named so the same-typed neighbours cannot be transposed: issuerDer/subjectDer are both
  // Array[Byte] and notBefore/notAfter both Long, so a positional slip would type-check and break
  // chain linking or invert the validity window silently.
  private type TbsFields = (
    issuerDer: Array[Byte],
    subjectDer: Array[Byte],
    notBefore: Long,
    notAfter: Long,
    spki: Array[Byte],
    exts: Option[Der.Tlv]
  )

  // Version is [0] EXPLICIT and defaults to v1 by being absent, so only its encoding is read here.
  private def afterVersion(s: Slice, tbs: Der.Tlv): Either[PathInvalid, Int] =
    if tbs.contentOff < tbs.next && (s(tbs.contentOff) & 0xff) == 0xa0 then read(s, tbs.contentOff, 0xa0, tbs.next).map(_.next)
    else Right(tbs.contentOff)

  private def tbsFields(s: Slice, tbs: Der.Tlv): Either[PathInvalid, TbsFields] =
    for
      start <- afterVersion(s, tbs)
      serial <- read(s, start, 0x02, tbs.next)
      sigAlgId <- read(s, serial.next, 0x30, tbs.next)
      issuer <- read(s, sigAlgId.next, 0x30, tbs.next)
      validity <- read(s, issuer.next, 0x30, tbs.next)
      subject <- read(s, validity.next, 0x30, tbs.next)
      spki <- read(s, subject.next, 0x30, tbs.next)
      times <- parseValidity(s, validity)
      exts <- scanExtensions(s, spki.next, tbs.next)
    yield (
      issuerDer = s.slice(sigAlgId.next, issuer.next).toArray,
      subjectDer = s.slice(validity.next, subject.next).toArray,
      notBefore = times.notBefore,
      notAfter = times.notAfter,
      spki = s.slice(subject.next, spki.next).toArray,
      exts = exts
    )
    end for
  end tbsFields

  private def parseValidity(s: Slice, validity: Der.Tlv): Either[PathInvalid, (notBefore: Long, notAfter: Long)] =
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
  @tailrec private def scanExtensions(s: Slice, start: Int, end: Int): Either[PathInvalid, Option[Der.Tlv]] =
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
    sanDns: List[String],
    isCa: Boolean,
    maxPathLen: Option[Int],
    ekus: List[String],
    keyCertSign: Option[Boolean],
    unhandledCritical: Boolean
  )

  private type ExtStep = (next: Int, id: Slice, acc: Extensions)

  // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
  // Every failure is a rejection: a partial parse leaves an empty EKU list or an absent path-length
  // constraint, both of which read as "unrestricted".
  private def extensions(s: Slice, exts: Option[Der.Tlv]): Either[PathInvalid, Extensions] =
    val empty =
      Extensions(sanDns = Nil, isCa = false, maxPathLen = None, ekus = Nil, keyCertSign = None, unhandledCritical = false)
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

  private def criticality(s: Slice, off: Int, limit: Int): Either[PathInvalid, (critical: Boolean, next: Int)] =
    if off < limit && (s(off) & 0xff) == 0x01 then
      read(s, off, 0x01, limit).flatMap { b =>
        if b.contentLen != 1 then Left(PathInvalid.MalformedChain)
        else Right((critical = (s(b.contentOff) & 0xff) != 0x00, next = b.next))
      }
    else Right((critical = false, next = off))

  private def absorb(value: Slice, oid: Slice, critical: Boolean, acc: Extensions): Either[PathInvalid, Extensions] =
    if eq(oid, oidSan) then parseSan(value).map(dns => acc.copy(sanDns = dns))
    else if eq(oid, oidBasicConstraints) then parseBasicConstraints(value).map(bc => acc.copy(isCa = bc.isCa, maxPathLen = bc.maxPathLen))
    else if eq(oid, oidEku) then parseEku(value).map(e => acc.copy(ekus = e))
    else if eq(oid, oidKeyUsage) then parseKeyUsage(value).map(k => acc.copy(keyCertSign = Some(k)))
    else Right(acc.copy(unhandledCritical = acc.unhandledCritical || critical))

  private def parseSan(value: Slice): Either[PathInvalid, List[String]] =
    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is context [2] IA5String.
    @tailrec def go(pos: Int, limit: Int, acc: List[String]): Either[PathInvalid, List[String]] =
      if pos >= limit then Right(acc.reverse)
      else
        val tag = value(pos) & 0xff
        read(value, pos, tag, limit) match
          case Left(e)  => Left(e)
          case Right(t) =>
            val name = if tag == 0x82 then new String(value.slice(t.contentOff, t.next).toArray, "US-ASCII") :: acc else acc
            go(t.next, limit, name)
    only(value, 0x30).flatMap(seq => go(seq.contentOff, seq.next, Nil))
  end parseSan

  // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.
  private def parseBasicConstraints(value: Slice): Either[PathInvalid, (isCa: Boolean, maxPathLen: Option[Int])] =
    def ca(off: Int, limit: Int): Either[PathInvalid, (set: Boolean, next: Int)] =
      if off < limit && (value(off) & 0xff) == 0x01 then
        read(value, off, 0x01, limit).flatMap { b =>
          if b.contentLen != 1 then Left(PathInvalid.MalformedChain)
          else Right((set = (value(b.contentOff) & 0xff) != 0x00, next = b.next))
        }
      else Right((set = false, next = off))
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
  private def smallInteger(s: Slice, t: Der.Tlv): Option[Int] =
    val raw = s.slice(t.contentOff, t.next).toArray
    if raw.isEmpty || raw.length > 4 || (raw(0) & 0x80) != 0 then None
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

  def issuerKey(spki: Array[Byte]): Option[ImportedPublicKey] =
    Der.peekSpki(Slice.of(spki)).toOption.map {
      case Der.Alg.Ed     => ImportedPublicKey.Ed(PublicKey.unsafe(keyRepr(spki)))
      case Der.Alg.X      => ImportedPublicKey.X(PublicKey.unsafe(keyRepr(spki)))
      case Der.Alg.EcP256 => ImportedPublicKey.EcP256(PublicKey.unsafe(keyRepr(spki)))
      case Der.Alg.EcP384 => ImportedPublicKey.EcP384(PublicKey.unsafe(keyRepr(spki)))
      case Der.Alg.EcP521 => ImportedPublicKey.EcP521(PublicKey.unsafe(keyRepr(spki)))
      case Der.Alg.OfRsa  => ImportedPublicKey.OfRsa(PublicKey.unsafe(keyRepr(spki)))
    }
end X509

/** An X.509 certificate, parsed once at construction; construct and read via
  * [[Certificate$ Certificate]].
  */
opaque type Certificate = Parsed
object Certificate:
  /** Parses one complete DER certificate; trailing bytes are rejected. */
  def fromDer(der: Array[Byte]): Either[Malformed, Certificate] =
    X509.parse(IArray.from(der)).left.map(_ => Malformed)

  /** Parses the first CERTIFICATE block, ignoring text outside the encapsulation boundaries - the
    * dump `openssl x509 -text` writes ahead of the block (RFC 7468 section 5.2).
    */
  def fromPem(pem: String): Either[Malformed, Certificate] =
    kufuli.PEM
      .decode(encapsulated(pem))
      .flatMap(b => if b.label == "CERTIFICATE" then fromDer(Array.from(b.der.iterator)) else Left(Malformed))

  /** Parses every CERTIFICATE block of a bundle in file order - a `fullchain.pem` is leaf first. */
  def chainFromPem(pem: String): Either[Malformed, List[Certificate]] =
    kufuli.PEM.decodeAll(encapsulated(pem)).flatMap { blocks =>
      val ders = blocks.filter(_.label == "CERTIFICATE")
      if ders.isEmpty then Left(Malformed)
      else
        val parsed = ders.map(b => fromDer(Array.from(b.der.iterator)))
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

    /** The subject public key, or [[InvalidKey.Unsupported]] where the SPKI names an algorithm
      * kufuli does not implement - a certificate carrying one still parses, and its validity
      * window, SAN entries and encoding stay readable.
      */
    def publicKey: Either[InvalidKey, ImportedPublicKey] =
      X509.issuerKey(cert.parsed.spki).toRight(InvalidKey.Unsupported)

    /** Start of the validity window, as epoch seconds. */
    def notBefore: Long = cert.parsed.notBefore

    /** End of the validity window, as epoch seconds. */
    def notAfter: Long = cert.parsed.notAfter

    /** The dNSName SAN entries - the only GeneralName form parsed. */
    def subjectAltDns: List[String] = cert.parsed.sanDns
  end extension
end Certificate

/** A hostname to match against a certificate's dNSName SANs; construct via [[Hostname$ Hostname]]. */
opaque type Hostname = String
object Hostname:
  /** Accepts any non-empty name free of spaces - a wrapper for matching, not a DNS-name validator. */
  def of(name: String): Either[Malformed, Hostname] =
    if name.nonEmpty && !name.contains(" ") then Right(name) else Left(Malformed)
  extension (h: Hostname) def value: String = h

/** The anchors a path must terminate at; construction raises when `anchors` is empty. */
final case class TrustAnchors(anchors: List[Certificate]):
  require(anchors.nonEmpty, "at least one trust anchor")

/** What a chain is validated for; selects the extended-key-usage OID every certificate in the path
  * must permit.
  */
enum PathPurpose derives CanEqual:
  case ServerAuth, ClientAuth

/** A validated leaf together with the intermediates it was presented with. */
final case class VerifiedPath(leaf: Certificate, chain: List[Certificate])

/** RFC 5280 path validation for the TLS profile, at a caller-supplied instant in epoch seconds -
  * kufuli reads no clock. Chain building, the validity window, basic constraints, key usage,
  * extended key usage, and dNSName SAN matching are evaluated; certificate policies, name
  * constraints, CRLs, and live OCSP are not, so a certificate marking any other extension critical
  * is rejected rather than accepted unconstrained. A `None` hostname skips SAN matching entirely -
  * pass the name the connection was made to whenever one exists.
  */
object CertPath:
  /** Validates `chain`, leaf first, for ServerAuth at `at`. */
  def verify(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long,
    hostname: Option[Hostname]
  ): EffIO[PathInvalid, VerifiedPath] = verify(chain, anchors, at, hostname, PathPurpose.ServerAuth)

  /** Validates `chain`, leaf first, for `purpose` at `at`; ClientAuth does not match `hostname`. */
  def verify(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long,
    hostname: Option[Hostname],
    purpose: PathPurpose
  ): EffIO[PathInvalid, VerifiedPath] =
    chain match
      case Nil                   => EffIO.fail(PathInvalid.MalformedChain)
      case leaf :: intermediates =>
        engine
          .validate(engine.paths(leaf, intermediates, anchors), at, hostname, purpose)
          .map(_ => VerifiedPath(leaf, intermediates))
end CertPath

private object engine:
  private val maxDepth = 16
  // An attacker supplies the intermediate pool, and same-DN certificates permute factorially, so the
  // candidate enumeration is capped rather than merely depth-bounded.
  private val maxCandidates = 8

  private def bytesEq(a: Array[Byte], b: Array[Byte]): Boolean = Slice.of(a).contentEquals(Slice.of(b))
  private def derBytes(c: Certificate): Array[Byte] = Array.from(c.der.iterator)

  // Candidate paths leaf-first, anchor last, produced lazily. Linking is by subject/issuer DN alone,
  // and a CA key rollover reuses the DN across two certificates, so committing to the first match
  // would fail a chain that a later match verifies.
  def paths(leaf: Certificate, intermediates: List[Certificate], anchors: TrustAnchors): Iterator[List[Certificate]] =
    def go(current: Certificate, pool: List[Certificate], acc: List[Certificate], depth: Int): Iterator[List[Certificate]] =
      if depth > maxDepth then Iterator.empty
      else
        val issuer = current.parsed.issuerDer
        val walked = (current :: acc).reverse
        val terminal = anchors.anchors.iterator.filter(a => bytesEq(a.parsed.subjectDer, issuer)).map(a => walked ::: List(a))
        val deeper = pool.iterator
          .filter(c => bytesEq(c.parsed.subjectDer, issuer))
          .flatMap { next =>
            val chosen = derBytes(next)
            go(next, pool.filterNot(c => bytesEq(derBytes(c), chosen)), current :: acc, depth + 1)
          }
        terminal ++ deeper
    val self = derBytes(leaf)
    if anchors.anchors.exists(a => bytesEq(derBytes(a), self)) then Iterator(List(leaf))
    else go(leaf, intermediates, Nil, 0)
  end paths

  // The first candidate's failure is the one reported: it is the path the chain was assembled for,
  // so its error describes what the peer actually presented.
  def validate(
    candidates: Iterator[List[Certificate]],
    at: Long,
    hostname: Option[Hostname],
    purpose: PathPurpose
  ): EffIO[PathInvalid, Unit] =
    def go(rest: List[List[Certificate]], first: Option[PathInvalid]): EffIO[PathInvalid, Unit] =
      rest match
        case Nil          => EffIO.fail(first.getOrElse(PathInvalid.UntrustedAnchor))
        case path :: tail => check(path, at, hostname, purpose).catchAll(e => go(tail, first.orElse(Some(e))))
    go(candidates.take(maxCandidates).toList, None)

  private def check(path: List[Certificate], at: Long, hostname: Option[Hostname], purpose: PathPurpose): EffIO[PathInvalid, Unit] =
    path match
      case Nil             => EffIO.fail(PathInvalid.MalformedChain)
      case leaf :: issuers =>
        if path.exists(c => at < c.notBefore || at > c.notAfter) then EffIO.fail(PathInvalid.Expired)
        else if path.exists(_.parsed.unhandledCritical) then EffIO.fail(PathInvalid.ConstraintViolated)
        else if issuers.exists(c => !c.parsed.isCa) then EffIO.fail(PathInvalid.ConstraintViolated)
        else if issuers.exists(_.parsed.keyCertSign.contains(false)) then EffIO.fail(PathInvalid.ConstraintViolated)
        else if pathLenExceeded(issuers) then EffIO.fail(PathInvalid.ConstraintViolated)
        else if !path.forall(c => ekuAllows(c.parsed.ekus, purpose)) then EffIO.fail(PathInvalid.ConstraintViolated)
        else if !nameOk(leaf, hostname, purpose) then EffIO.fail(PathInvalid.NameMismatch)
        else verifyChain(leaf, issuers)
  end check

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

  private def nameOk(leaf: Certificate, hostname: Option[Hostname], purpose: PathPurpose): Boolean =
    (purpose, hostname) match
      case (PathPurpose.ClientAuth, _)       => true
      case (PathPurpose.ServerAuth, None)    => true
      case (PathPurpose.ServerAuth, Some(h)) => leaf.parsed.sanDns.exists(matches(_, h.value))

  // RFC 6125 SAN matching with a single leftmost wildcard label. The fold is ASCII-only: DNS labels
  // are ASCII by construction, `toLowerCase` follows the ambient locale, and Unicode case folding
  // maps distinct code points (U+212A KELVIN SIGN) onto ASCII letters.
  private def matches(pattern: String, host: String): Boolean =
    val p = foldCase(pattern)
    val h = foldCase(host)
    if p == h then true
    else if p.startsWith("*.") then
      val suffix = p.substring(1) // ".example.com"
      val dot = h.indexOf('.')
      // A wildcard needs a label of its own beneath the suffix, or `*.com` covers every `.com` host.
      suffix.indexOf('.', 1) > 0 && dot > 0 && h.substring(dot) == suffix
    else false

  private def foldCase(name: String): String = name.map(c => if c >= 'A' && c <= 'Z' then (c + 32).toChar else c)

  private def verifyChain(leaf: Certificate, issuers: List[Certificate]): EffIO[PathInvalid, Unit] =
    // each cert (subject) is signed by the next (issuer); the anchor terminates the walk
    val pairs = (leaf :: issuers).zip(issuers)
    pairs.foldLeft(EffIO.succeed(()): EffIO[PathInvalid, Unit]) { (acc, pair) =>
      val (subject, issuer) = pair
      acc.flatMap(_ => verifyOne(subject, issuer))
    }

  private def verifyOne(subject: Certificate, issuer: Certificate): EffIO[PathInvalid, Unit] =
    val sub = subject.parsed
    (sub.sigScheme, X509.issuerKey(issuer.parsed.spki)) match
      case (Some(scheme), Some(key)) =>
        val tbs = Slice.of(sub.tbs)
        val rejected = verifyBy(scheme, key, tbs, sub.signature)
        rejected.mapError(_ => PathInvalid.BadSignature)
      case _ => EffIO.fail(PathInvalid.BadSignature)

  private def verifyBy(scheme: SigScheme, key: ImportedPublicKey, tbs: Slice, sig: Array[Byte]): EffIO[SignatureRejected, Unit] =
    (scheme, key) match
      case (SigScheme.Ed, ImportedPublicKey.Ed(k)) =>
        EffIO.from(Signature.fromRaw(Ed25519)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s))
      case (SigScheme.Ec(h), ImportedPublicKey.EcP256(k))      => ecVerify(P256, k, tbs, sig, h)
      case (SigScheme.Ec(h), ImportedPublicKey.EcP384(k))      => ecVerify(P384, k, tbs, sig, h)
      case (SigScheme.Ec(h), ImportedPublicKey.EcP521(k))      => ecVerify(P521, k, tbs, sig, h)
      case (SigScheme.RsaPkcs1(h), ImportedPublicKey.OfRsa(k)) =>
        EffIO.from(Signature.fromRaw(Rsa)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s, kufuli.RsaPkcs1(h)))
      case (SigScheme.RsaPss(h), ImportedPublicKey.OfRsa(k)) =>
        EffIO.from(Signature.fromRaw(Rsa)(sig)).mapError(_ => SignatureRejected).flatMap(s => k.verify(tbs, s, kufuli.RsaPss(h)))
      case _ => EffIO.fail(SignatureRejected)

  private def ecVerify[C <: EcCurve](
    curve: EcSpec[C],
    key: PublicKey[C],
    tbs: Slice,
    sig: Array[Byte],
    hash: Sha2
  )(using Verifier[C]): EffIO[SignatureRejected, Unit] =
    EffIO.from(Signature.fromDer(curve)(sig)).mapError(_ => SignatureRejected).flatMap(s => key.verify(tbs, s, hash))
end engine

/** Verifies a stapled OCSP response the caller supplies (from the TLS handshake). No network I/O is
  * performed; live OCSP and CRL fetching are out of scope.
  */
object OCSP:
  enum Status derives CanEqual:
    case Good
    case Revoked(at: Long)
    case Unknown

  /** Reads the first single-response certStatus from a stapled OCSP response, reporting `Unknown`
    * where a `Good` falls outside the response's own thisUpdate/nextUpdate window at `at`.
    *
    * The response signature, producer identity, nonce, and certID-to-leaf binding are NOT verified,
    * so a `Good` result is advisory and MUST NOT be trusted on its own until that binding lands - a
    * forged staple can claim any status. It exists so a genuine `Revoked` staple is honoured.
    */
  def verifyStapled(response: Array[Byte], leaf: Certificate, issuer: Certificate, at: Long): EffIO[PathInvalid, OCSP.Status] =
    val _ = (leaf, issuer)
    parseStatus(response, at) match
      case Some(s) => EffIO.succeed(s)
      case None    => EffIO.fail(PathInvalid.MalformedChain)

  // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ResponseBytes }.
  // A responseStatus other than successful(0) carries no body; anything else is descended to the
  // first SingleResponse's certStatus. Structural deviation is Malformed (None).
  private def parseStatus(response: Array[Byte], at: Long): Option[OCSP.Status] =
    if response.isEmpty then None
    else
      val s = Slice.of(response)
      (for
        outer <- Der.read(s, 0, 0x30)
        respStatus <- Der.read(s, outer.contentOff, 0x0a)
        code = if respStatus.contentLen > 0 then s(respStatus.contentOff) & 0xff else -1
        status <- if code != 0 then Right(OCSP.Status.Unknown) else certStatus(s, respStatus.next, at)
      yield status).toOption

  // OCSPResponse -> responseBytes [0] -> ResponseBytes { OID, OCTET STRING } -> BasicOCSPResponse ->
  // tbsResponseData (ResponseData) -> responses -> first SingleResponse -> certStatus. The OCTET
  // STRING content is DER in place, so the inner reads continue over the same slice.
  private def certStatus(s: Slice, afterStatus: Int, at: Long): Either[InvalidKey, OCSP.Status] =
    for
      rb <- Der.read(s, afterStatus, 0xa0) // responseBytes [0] EXPLICIT
      rbSeq <- Der.read(s, rb.contentOff, 0x30) // ResponseBytes
      oid <- Der.read(s, rbSeq.contentOff, 0x06) // responseType OID
      octet <- Der.read(s, oid.next, 0x04) // response OCTET STRING (DER BasicOCSPResponse)
      basic <- Der.read(s, octet.contentOff, 0x30) // BasicOCSPResponse
      tbs <- Der.read(s, basic.contentOff, 0x30) // tbsResponseData (ResponseData)
      responses <- toResponses(s, tbs)
      single <- Der.read(s, responses.contentOff, 0x30) // first SingleResponse
      certId <- Der.read(s, single.contentOff, 0x30) // certID
      status <- statusTag(s, certId.next, single.next)
      current <- fresh(s, status.next, single.next, at)
    yield if current then status.value else stale(status.value)

  // A response outside its own validity window asserts nothing about now, so its `Good` is not
  // honoured; `Revoked` stands, since ageing does not undo a revocation.
  private def stale(status: OCSP.Status): OCSP.Status =
    status match
      case OCSP.Status.Good => OCSP.Status.Unknown
      case other            => other

  // ResponseData ::= SEQUENCE { version [0] OPTIONAL, responderID CHOICE([1] byName/[2] byKey),
  // producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse, ... }.
  private def toResponses(s: Slice, tbs: Der.Tlv): Either[InvalidKey, Der.Tlv] =
    def tagAt(off: Int): Int = if off < tbs.next then s(off) & 0xff else -1
    val afterVersion =
      if tagAt(tbs.contentOff) == 0xa0 then Der.read(s, tbs.contentOff, 0xa0).map(_.next)
      else Right(tbs.contentOff)
    afterVersion.flatMap { av =>
      val rid = tagAt(av)
      (if rid == 0xa1 || rid == 0xa2 then Der.read(s, av, rid).map(_.next) else Left(InvalidKey.Malformed))
        .flatMap(ar => Der.read(s, ar, 0x18).flatMap(pa => Der.read(s, pa.next, 0x30)))
    }

  // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
  // unknown [2] IMPLICIT UnknownInfo }. RevokedInfo's first field is revocationTime GeneralizedTime.
  private def statusTag(s: Slice, off: Int, end: Int): Either[InvalidKey, (value: OCSP.Status, next: Int)] =
    if off >= end then Left(InvalidKey.Malformed)
    else
      (s(off) & 0xff) match
        case 0x80 => within(s, off, 0x80, end).map(t => (value = OCSP.Status.Good, next = t.next))
        case 0x82 => within(s, off, 0x82, end).map(t => (value = OCSP.Status.Unknown, next = t.next))
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

  private def generalizedTime(s: Slice, t: Der.Tlv): Either[InvalidKey, Long] =
    val str = new String(s.slice(t.contentOff, t.next).toArray, "US-ASCII")
    X509.parseTime(str, generalized = true).toRight(InvalidKey.Malformed)

  private def within(s: Slice, off: Int, tag: Int, limit: Int): Either[InvalidKey, Der.Tlv] =
    Der.read(s, off, tag).filterOrElse(_.next <= limit, InvalidKey.Malformed)
end OCSP
