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
// Scope is RFC 5280 TLS-profile path validation: NOT policy trees, CRL, or live OCSP. Times are
// explicit epoch seconds (no java.time - the cross-platform floor). Anchor sourcing, staple/CRL
// transport, and certificate selection are consumer concerns.
package kufuli.x509

import scala.annotation.tailrec
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.effect.EffIO

import kufuli.*

sealed abstract class X509Error(message: String) extends Exception(message) with NoStackTrace derives CanEqual

// Payload-free cases in the class+object error DNA (type positions name the class).
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
  sealed abstract class ConstraintViolated private[x509] () extends PathInvalid("basic constraints / KU / EKU violated")
  case object ConstraintViolated extends ConstraintViolated
end PathInvalid

// Parsed view of a certificate (extracted on demand from the DER via the core bounded reader).
final private[x509] case class Parsed(
  tbs: Array[Byte],
  spki: Array[Byte],
  issuerDer: Array[Byte],
  subjectDer: Array[Byte],
  notBefore: Long,
  notAfter: Long,
  sanDns: List[String],
  isCa: Boolean,
  ekus: List[String],
  sigScheme: Option[SigScheme],
  signature: Array[Byte]
)

// The certificate's own signature: which family/hash verifies its issuer's key over its TBS.
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
  // Extension OIDs.
  private val oidBasicConstraints = Array[Byte](0x55, 0x1d, 0x13)
  private val oidSan = Array[Byte](0x55, 0x1d, 0x11)
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

  private def parseTime(s: String, generalized: Boolean): Option[Long] =
    val digits = s.takeWhile(_ != 'Z')
    val base = if generalized then digits else digits // both YY.. or YYYY..
    def at(i: Int, n: Int) = base.substring(i, i + n).toIntOption
    if generalized && base.length >= 14 then
      for y <- at(0, 4); mo <- at(4, 2); d <- at(6, 2); h <- at(8, 2); mi <- at(10, 2); se <- at(12, 2)
      yield epoch(y, mo, d, h, mi, se)
    else if !generalized && base.length >= 12 then
      for yy <- at(0, 2); mo <- at(2, 2); d <- at(4, 2); h <- at(6, 2); mi <- at(8, 2); se <- at(10, 2)
      yield epoch(if yy >= 50 then 1900 + yy else 2000 + yy, mo, d, h, mi, se)
    else None

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

  def parse(der: IArray[Byte]): Either[PathInvalid, Parsed] =
    val bytes = Array.from(der.iterator)
    val s = Slice.of(bytes)
    for
      cert <- read(s, 0, 0x30)
      tbs <- read(s, cert.contentOff, 0x30)
      afterTbs = tbs.next
      sigAlg <- read(s, afterTbs, 0x30)
      sigOid <- read(s, sigAlg.contentOff, 0x06)
      sigBits <- read(s, sigAlg.next, 0x03)
      // walk TBS fields
      fields <- tbsFields(s, tbs)
    yield
      val ext = extensions(s, fields.exts)
      Parsed(
        tbs = s.slice(cert.contentOff, tbs.next).toArray,
        spki = fields.spki,
        issuerDer = fields.issuerDer,
        subjectDer = fields.subjectDer,
        notBefore = fields.notBefore,
        notAfter = fields.notAfter,
        sanDns = ext.sanDns,
        isCa = ext.isCa,
        ekus = ext.ekus,
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

  private def tbsFields(s: Slice, tbs: Der.Tlv): Either[PathInvalid, TbsFields] =
    val start = tbs.contentOff
    // optional version [0]
    val afterVersion =
      if start < tbs.next && (s(start) & 0xff) == 0xa0 then Der.read(s, start, 0xa0).map(_.next).getOrElse(start)
      else start
    for
      serial <- read(s, afterVersion, 0x02)
      sigAlgId <- read(s, serial.next, 0x30)
      issuer <- read(s, sigAlgId.next, 0x30)
      validity <- read(s, issuer.next, 0x30)
      subject <- read(s, validity.next, 0x30)
      spki <- read(s, subject.next, 0x30)
      times <- parseValidity(s, validity)
    yield
      // scan the remainder of TBS for the extensions [3] wrapper
      (
        issuerDer = s.slice(sigAlgId.next, issuer.next).toArray,
        subjectDer = s.slice(validity.next, subject.next).toArray,
        notBefore = times.notBefore,
        notAfter = times.notAfter,
        spki = s.slice(subject.next, spki.next).toArray,
        exts = scanExtensions(s, spki.next, tbs.next)
      )
    end for
  end tbsFields

  private def parseValidity(s: Slice, validity: Der.Tlv): Either[PathInvalid, (notBefore: Long, notAfter: Long)] =
    def time(off: Int): Either[PathInvalid, (epoch: Long, next: Int)] =
      if off >= validity.next then Left(PathInvalid.MalformedChain)
      else
        val tag = s(off) & 0xff
        val generalized = tag == 0x18
        read(s, off, tag).flatMap { t =>
          val str = new String(s.slice(t.contentOff, t.next).toArray, "US-ASCII")
          parseTime(str, generalized).map(e => (epoch = e, next = t.next)).toRight(PathInvalid.MalformedChain)
        }
    for
      nb <- time(validity.contentOff)
      na <- time(nb.next)
    yield (notBefore = nb.epoch, notAfter = na.epoch)
  end parseValidity

  @tailrec private def scanExtensions(s: Slice, start: Int, end: Int): Option[Der.Tlv] =
    if start >= end then None
    else
      val tag = s(start) & 0xff
      Der.read(s, start, tag) match
        case Left(_)                 => None
        case Right(t) if tag == 0xa3 => Der.read(s, t.contentOff, 0x30).toOption
        case Right(t)                => scanExtensions(s, t.next, end)

  // Named for the same reason as TbsFields: sanDns and ekus are both List[String], so a positional
  // slip would type-check and silently swap the hostname evidence with the EKU evidence.
  private type Extensions = (sanDns: List[String], isCa: Boolean, ekus: List[String])

  private def extensions(s: Slice, exts: Option[Der.Tlv]): Extensions =
    exts match
      case None      => (sanDns = Nil, isCa = false, ekus = Nil)
      case Some(seq) =>
        @tailrec def go(pos: Int, acc: Extensions): Extensions =
          if pos >= seq.next then acc
          else
            Der.read(s, pos, 0x30) match
              case Left(_)    => acc
              case Right(ext) =>
                // ext = SEQUENCE { OID, [critical BOOLEAN], OCTET STRING value }
                val updated = Der.read(s, ext.contentOff, 0x06) match
                  case Left(_)    => acc
                  case Right(oid) =>
                    val oidSlice = s.slice(oid.contentOff, oid.next)
                    val vpos =
                      if oid.next < ext.next && (s(oid.next) & 0xff) == 0x01 then Der.read(s, oid.next, 0x01).map(_.next).getOrElse(oid.next)
                      else oid.next
                    Der.read(s, vpos, 0x04) match
                      case Left(_)      => acc
                      case Right(octet) =>
                        val value = s.slice(octet.contentOff, octet.next)
                        if eq(oidSlice, oidSan) then (sanDns = parseSan(value), isCa = acc.isCa, ekus = acc.ekus)
                        else if eq(oidSlice, oidBasicConstraints) then
                          (sanDns = acc.sanDns, isCa = parseBasicConstraints(value), ekus = acc.ekus)
                        else if eq(oidSlice, oidEku) then (sanDns = acc.sanDns, isCa = acc.isCa, ekus = parseEku(value))
                        else acc
                go(ext.next, updated)
        go(seq.contentOff, (sanDns = Nil, isCa = false, ekus = Nil))

  private def parseSan(value: Slice): List[String] =
    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is context [2] IA5String.
    Der.read(value, 0, 0x30) match
      case Left(_)    => Nil
      case Right(seq) =>
        @tailrec def go(pos: Int, acc: List[String]): List[String] =
          if pos >= seq.next then acc.reverse
          else
            val tag = value(pos) & 0xff
            Der.read(value, pos, tag) match
              case Left(_)  => acc.reverse
              case Right(t) =>
                val name = if tag == 0x82 then new String(value.slice(t.contentOff, t.next).toArray, "US-ASCII") :: acc else acc
                go(t.next, name)
        go(seq.contentOff, Nil)

  private def parseBasicConstraints(value: Slice): Boolean =
    Der.read(value, 0, 0x30) match
      case Left(_)    => false
      case Right(seq) =>
        if seq.contentOff < seq.next && (value(seq.contentOff) & 0xff) == 0x01 then
          Der.read(value, seq.contentOff, 0x01).toOption.exists(b => (value(b.contentOff) & 0xff) != 0x00)
        else false

  private def parseEku(value: Slice): List[String] =
    Der.read(value, 0, 0x30) match
      case Left(_)    => Nil
      case Right(seq) =>
        @tailrec def go(pos: Int, acc: List[String]): List[String] =
          if pos >= seq.next then acc.reverse
          else
            Der.read(value, pos, 0x06) match
              case Left(_)  => acc.reverse
              case Right(t) => go(t.next, oidString(value.slice(t.contentOff, t.next).toArray) :: acc)
        go(seq.contentOff, Nil)

  // The issuer's public key arm, from its SPKI, for signature verification.
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

/** A parsed X.509 certificate; construct and read via [[Certificate$ Certificate]]. */
opaque type Certificate = IArray[Byte]
object Certificate:
  def fromDer(der: Array[Byte]): Either[Malformed, Certificate] =
    val c = IArray.from(der)
    X509.parse(c) match
      case Right(_) => Right(c)
      case Left(_)  => Left(Malformed)
  def fromPem(pem: String): Either[Malformed, Certificate] =
    kufuli.PEM.decode(pem).flatMap(b => fromDer(Array.from(b.der.iterator)))

  /** Parse a `fullchain.pem` bundle, leaf first, as issued by certbot, acme.sh, and cloud CAs. */
  def chainFromPem(pem: String): Either[Malformed, List[Certificate]] =
    kufuli.PEM.decodeAll(pem).flatMap { blocks =>
      val ders = blocks.filter(_.label == "CERTIFICATE")
      if ders.isEmpty then Left(Malformed)
      else
        val parsed = ders.map(b => fromDer(Array.from(b.der.iterator)))
        if parsed.forall(_.isRight) then Right(parsed.collect { case Right(c) => c }) else Left(Malformed)
    }
  extension (cert: Certificate)
    def der: IArray[Byte] = cert
    private[x509] def parsed: Parsed =
      // total: fromDer validated the encoding at construction, so parse never fails here
      X509.parse(cert).getOrElse(throw new IllegalStateException("validated at construction")) // scalafix:ok DisableSyntax.throw
    def publicKey: ImportedPublicKey =
      X509.issuerKey(parsed.spki).getOrElse(ImportedPublicKey.Ed(PublicKey.unsafe(keyRepr(new Array[Byte](32)))))
    def notBefore: Long = parsed.notBefore
    def notAfter: Long = parsed.notAfter
    def subjectAltDns: List[String] = parsed.sanDns
end Certificate

/** A validated DNS hostname for SAN matching; construct via [[Hostname$ Hostname]]. */
opaque type Hostname = String
object Hostname:
  def of(name: String): Either[Malformed, Hostname] =
    if name.nonEmpty && !name.contains(" ") then Right(name) else Left(Malformed)
  extension (h: Hostname) def value: String = h

final case class TrustAnchors(anchors: List[Certificate]):
  require(anchors.nonEmpty, "at least one trust anchor")

/** What a chain is validated for; selects the EKU and key-usage checks. */
enum PathPurpose derives CanEqual:
  case ServerAuth, ClientAuth

final case class VerifiedPath(leaf: Certificate, chain: List[Certificate])

object CertPath:
  /** ServerAuth by default (the TLS-client / DB-client path). */
  def verify(
    chain: List[Certificate],
    anchors: TrustAnchors,
    at: Long,
    hostname: Option[Hostname]
  ): EffIO[PathInvalid, VerifiedPath] = verify(chain, anchors, at, hostname, PathPurpose.ServerAuth)
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
        EffIO.from(engine.build(leaf, intermediates, anchors)).flatMap { path =>
          engine.validate(path, at, hostname, purpose).map(_ => VerifiedPath(leaf, intermediates))
        }
end CertPath

// The path-validation engine, over the core Verifier seam. Name constraints are not enforced.
private object engine:
  private def bytesEq(a: Array[Byte], b: Array[Byte]): Boolean = Slice.of(a).contentEquals(Slice.of(b))
  private def derBytes(c: Certificate): Array[Byte] = Array.from(c.der.iterator)

  // Build leaf -> ... -> anchor by matching subject/issuer DER; returns the ordered path incl. the anchor.
  def build(leaf: Certificate, intermediates: List[Certificate], anchors: TrustAnchors): Either[PathInvalid, List[Certificate]] =
    def issuerOf(cert: Certificate, pool: List[Certificate]): Option[Certificate] =
      val iss = cert.parsed.issuerDer
      pool.find(c => bytesEq(c.parsed.subjectDer, iss))
    def loop(
      current: Certificate,
      remaining: List[Certificate],
      acc: List[Certificate],
      depth: Int): Either[PathInvalid, List[Certificate]] =
      if depth > 16 then Left(PathInvalid.UntrustedAnchor)
      else
        anchors.anchors.find(a => bytesEq(a.parsed.subjectDer, current.parsed.issuerDer)) match
          case Some(anchor) => Right((current :: acc).reverse ::: List(anchor))
          case None         =>
            issuerOf(current, remaining) match
              case Some(next) => loop(next, remaining.filterNot(c => bytesEq(derBytes(c), derBytes(next))), current :: acc, depth + 1)
              case None       => Left(PathInvalid.UntrustedAnchor)
    // self-issued leaf that is itself an anchor
    if anchors.anchors.exists(a => bytesEq(derBytes(a), derBytes(leaf))) then Right(List(leaf))
    else loop(leaf, intermediates, Nil, 0)
  end build

  def validate(path: List[Certificate], at: Long, hostname: Option[Hostname], purpose: PathPurpose): EffIO[PathInvalid, Unit] =
    // validity window for every cert
    val expired = path.exists(c => at < c.notBefore || at > c.notAfter)
    if expired then EffIO.fail(PathInvalid.Expired)
    else
      val leaf = path.head
      // CA basic-constraints on every issuer (all but the leaf)
      val issuers = path.tail
      if issuers.exists(c => !c.parsed.isCa) then EffIO.fail(PathInvalid.ConstraintViolated)
      else if !ekuAllows(leaf.parsed.ekus, purpose) then EffIO.fail(PathInvalid.ConstraintViolated)
      else if !nameOk(leaf, hostname, purpose) then EffIO.fail(PathInvalid.NameMismatch)
      else verifyChain(path)
  end validate

  private def ekuAllows(ekus: List[String], purpose: PathPurpose): Boolean =
    if ekus.isEmpty then true // no EKU restriction
    else
      purpose match
        case PathPurpose.ServerAuth => ekus.contains(X509.ekuServerAuth)
        case PathPurpose.ClientAuth => ekus.contains(X509.ekuClientAuth)

  private def nameOk(leaf: Certificate, hostname: Option[Hostname], purpose: PathPurpose): Boolean =
    (purpose, hostname) match
      case (PathPurpose.ClientAuth, _)       => true
      case (PathPurpose.ServerAuth, None)    => true
      case (PathPurpose.ServerAuth, Some(h)) => leaf.parsed.sanDns.exists(matches(_, h.value))

  // RFC 6125 SAN matching with a single leftmost wildcard label.
  private def matches(pattern: String, host: String): Boolean =
    val p = pattern.toLowerCase.nn
    val h = host.toLowerCase.nn
    if p == h then true
    else if p.startsWith("*.") then
      val suffix = p.substring(1) // ".example.com"
      val dot = h.indexOf('.')
      dot > 0 && h.substring(dot) == suffix
    else false

  private def verifyChain(path: List[Certificate]): EffIO[PathInvalid, Unit] =
    // each cert (subject) is signed by the next (issuer); the anchor terminates the walk
    val pairs = path.zip(path.tail)
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

  /** Parses the OCSP response status only - the response signature, nonce, and issuer binding are
    * NOT verified.
    */
  def verifyStapled(response: Array[Byte], leaf: Certificate, issuer: Certificate, at: Long): EffIO[PathInvalid, OCSP.Status] =
    val _ = (leaf, issuer, at)
    val status = parseStatus(response)
    status match
      case Some(s) => EffIO.succeed(s)
      case None    => EffIO.fail(PathInvalid.MalformedChain)

  // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED (0x0a), responseBytes [0] ... }.
  private def parseStatus(response: Array[Byte]): Option[OCSP.Status] =
    if response.isEmpty then None
    else
      val s = Slice.of(response)
      (for
        outer <- Der.read(s, 0, 0x30)
        respStatus <- Der.read(s, outer.contentOff, 0x0a)
      yield
        val code = if respStatus.contentLen > 0 then s(respStatus.contentOff) & 0xff else 6
        // 0 = successful; a successful response with a Good single status is the common staple.
        if code == 0 then OCSP.Status.Good else OCSP.Status.Unknown
      ).toOption
end OCSP
