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
package kufuli.tests

import boilerplate.Slice
import boilerplate.effect.*
import cats.effect.IO

import kufuli.*
import kufuli.tests.support.*
import kufuli.x509 as x5

// Ed25519-signed certificates built field by field, so a suite can state exactly which encoding it
// is asserting about. Every fixture certificate is v3 with a single-CN subject.
object x509fixtures:
  type Issued = (der: Array[Byte], key: PrivateKey[Ed25519], subject: String)

  def tlv(tag: Int, content: Array[Byte]): Array[Byte] =
    val len = content.length
    val header =
      if len < 0x80 then Array[Byte](tag.toByte, len.toByte)
      else if len < 0x100 then Array[Byte](tag.toByte, 0x81.toByte, len.toByte)
      else Array[Byte](tag.toByte, 0x82.toByte, (len >> 8).toByte, len.toByte)
    header ++ content

  def seq(parts: Array[Byte]*): Array[Byte] = tlv(0x30, parts.foldLeft(Array.emptyByteArray)(_ ++ _))
  def oid(content: Array[Byte]): Array[Byte] = tlv(0x06, content)
  def ascii(text: String): Array[Byte] = text.getBytes("US-ASCII")

  val edOid: Array[Byte] = Array[Byte](0x2b, 0x65, 0x70) // 1.3.101.112
  val oidKeyUsage: Array[Byte] = Array[Byte](0x55, 0x1d, 0x0f)
  val oidSan: Array[Byte] = Array[Byte](0x55, 0x1d, 0x11)
  val oidBasicConstraints: Array[Byte] = Array[Byte](0x55, 0x1d, 0x13)
  val oidNameConstraints: Array[Byte] = Array[Byte](0x55, 0x1d, 0x1e)
  val oidCertificatePolicies: Array[Byte] = Array[Byte](0x55, 0x1d, 0x20)
  val oidEku: Array[Byte] = Array[Byte](0x55, 0x1d, 0x25)
  val oidCommonName: Array[Byte] = Array[Byte](0x55, 0x04, 0x03)
  val oidOrganisation: Array[Byte] = Array[Byte](0x55, 0x04, 0x0a)
  val oidEmailAddress: Array[Byte] = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x09, 0x01)
  val serverAuth: Array[Byte] = Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)
  val clientAuth: Array[Byte] = Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02)

  def ext(id: Array[Byte], critical: Boolean, value: Array[Byte]): Array[Byte] =
    if critical then seq(oid(id), tlv(0x01, Array[Byte](0xff.toByte)), tlv(0x04, value))
    else seq(oid(id), tlv(0x04, value))

  val caTrue: Array[Byte] = ext(oidBasicConstraints, true, seq(tlv(0x01, Array[Byte](0xff.toByte))))
  val endEntity: Array[Byte] = ext(oidBasicConstraints, false, seq())
  // KeyUsage bit 5 is keyCertSign: 0x06 with one unused bit is keyCertSign + cRLSign, 0x80 with
  // seven unused bits is digitalSignature alone.
  val certSign: Array[Byte] = ext(oidKeyUsage, true, tlv(0x03, Array[Byte](0x01, 0x06)))
  val signOnly: Array[Byte] = ext(oidKeyUsage, true, tlv(0x03, Array[Byte](0x07, 0x80.toByte)))

  def dnsName(name: String): Array[Byte] = tlv(0x82, ascii(name))
  def ipName(octets: Array[Byte]): Array[Byte] = tlv(0x87, octets)
  def emailName(address: String): Array[Byte] = tlv(0x81, ascii(address))
  def uriName(uri: String): Array[Byte] = tlv(0x86, ascii(uri))
  def dirName(rdns: Array[Byte]): Array[Byte] = tlv(0xa4, rdns)
  def otherName(content: Array[Byte]): Array[Byte] = tlv(0xa0, content)

  def sanOf(entries: Array[Byte]*): Array[Byte] = ext(oidSan, false, seq(entries*))
  def san(names: String*): Array[Byte] = sanOf(names.map(dnsName)*)
  def eku(purposes: Array[Byte]*): Array[Byte] = ext(oidEku, false, seq(purposes.map(oid)*))

  def rdn(attribute: Array[Byte], tag: Int, value: String): Array[Byte] =
    tlv(0x31, seq(oid(attribute), tlv(tag, ascii(value))))

  def name(cn: String): Array[Byte] = seq(rdn(oidCommonName, 0x0c, cn))

  // GeneralSubtrees is IMPLICITly tagged, so [0]/[1] replaces its SEQUENCE tag rather than wrapping it.
  def constraints(permitted: List[Array[Byte]], excluded: List[Array[Byte]]): Array[Byte] =
    def subtrees(tag: Int, bases: List[Array[Byte]]): Array[Byte] =
      if bases.isEmpty then Array.emptyByteArray
      else tlv(tag, bases.foldLeft(Array.emptyByteArray)((acc, b) => acc ++ seq(b)))
    ext(oidNameConstraints, true, seq(subtrees(0xa0, permitted), subtrees(0xa1, excluded)))

  val notBefore = "200101000000Z"
  val notAfter = "300101000000Z"
  val at = 1_800_000_000L // 2027-01-15, inside every fixture window

  def tbsOf(
    serial: Int,
    issuer: String,
    subject: String,
    spki: Array[Byte],
    from: String,
    until: String,
    exts: List[Array[Byte]]): Array[Byte] =
    tbsWith(serial, issuer, subject, spki, from, until, if exts.isEmpty then Array.emptyByteArray else tlv(0xa3, seq(exts*)))

  def tbsWith(
    serial: Int,
    issuer: String,
    subject: String,
    spki: Array[Byte],
    from: String,
    until: String,
    region: Array[Byte]): Array[Byte] =
    tbsNamed(serial, name(issuer), name(subject), spki, from, until, region)

  def tbsNamed(
    serial: Int,
    issuer: Array[Byte],
    subject: Array[Byte],
    spki: Array[Byte],
    from: String,
    until: String,
    region: Array[Byte]): Array[Byte] =
    seq(
      tlv(0xa0, tlv(0x02, Array[Byte](2))), // version v3
      tlv(0x02, Array[Byte](serial.toByte)),
      seq(oid(edOid)),
      issuer,
      seq(tlv(0x17, ascii(from)), tlv(0x17, ascii(until))),
      subject,
      spki,
      region
    )

  def assemble(tbs: Array[Byte], signature: Array[Byte]): Array[Byte] =
    seq(tbs, seq(oid(edOid)), tlv(0x03, Array[Byte](0) ++ signature))

  def spkiOf(key: PublicKey[Ed25519]): IO[Array[Byte]] =
    expectRight("spki")(key.spki).map(a => Array.from(a.bytes.iterator))

  def signed(tbs: Array[Byte], key: PrivateKey[Ed25519]): IO[Array[Byte]] =
    key.sign(Slice.of(tbs)).absolve.map(s => assemble(tbs, Array.from(s.bytes.iterator)))

  def selfSigned(subject: String, exts: List[Array[Byte]]): IO[Issued] =
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      der <- signed(tbsOf(1, subject, subject, spki, notBefore, notAfter, exts), kp.privateKey)
    yield (der = der, key = kp.privateKey, subject = subject)

  def issuedBy(issuer: Issued, serial: Int, subject: String, exts: List[Array[Byte]]): IO[Issued] =
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      der <- signed(tbsOf(serial, issuer.subject, subject, spki, notBefore, notAfter, exts), issuer.key)
    yield (der = der, key = kp.privateKey, subject = subject)

  // A leaf whose subject is a caller-built Name, for the directoryName and emailAddress rules.
  def leafNamed(issuer: Issued, serial: Int, subject: Array[Byte], exts: List[Array[Byte]]): IO[Array[Byte]] =
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      region = if exts.isEmpty then Array.emptyByteArray else tlv(0xa3, seq(exts*))
      der <- signed(tbsNamed(serial, name(issuer.subject), subject, spki, notBefore, notAfter, region), issuer.key)
    yield der

  def parsed(der: Array[Byte]): IO[x5.Certificate] =
    x5.Certificate.parse(der) match
      case Right(c) => IO.pure(c)
      case Left(e)  => IO.raiseError(new AssertionError(s"expected a parsable certificate, got $e"))

  def serverId(text: String): IO[x5.ServerId] =
    x5.ServerId.parse(text) match
      case Right(i) => IO.pure(i)
      case Left(e)  => IO.raiseError(new AssertionError(s"identity $text: $e"))
end x509fixtures
