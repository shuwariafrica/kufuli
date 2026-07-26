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
import cats.syntax.all.*

import kufuli.*
import kufuli.tests.support.*
import kufuli.x509 as x5

class X509HardeningSuite extends munit.CatsEffectSuite:

  private def tlv(tag: Int, content: Array[Byte]): Array[Byte] =
    val len = content.length
    val header =
      if len < 0x80 then Array[Byte](tag.toByte, len.toByte)
      else if len < 0x100 then Array[Byte](tag.toByte, 0x81.toByte, len.toByte)
      else Array[Byte](tag.toByte, 0x82.toByte, (len >> 8).toByte, len.toByte)
    header ++ content
  private def seq(parts: Array[Byte]*): Array[Byte] = tlv(0x30, parts.foldLeft(Array.emptyByteArray)(_ ++ _))
  private def oid(content: Array[Byte]): Array[Byte] = tlv(0x06, content)
  private def ascii(text: String): Array[Byte] = text.getBytes("US-ASCII")

  private val edOid = Array[Byte](0x2b, 0x65, 0x70) // 1.3.101.112
  private val oidKeyUsage = Array[Byte](0x55, 0x1d, 0x0f)
  private val oidSan = Array[Byte](0x55, 0x1d, 0x11)
  private val oidBasicConstraints = Array[Byte](0x55, 0x1d, 0x13)
  private val oidNameConstraints = Array[Byte](0x55, 0x1d, 0x1e)
  private val oidCertificatePolicies = Array[Byte](0x55, 0x1d, 0x20)
  private val oidEku = Array[Byte](0x55, 0x1d, 0x25)
  private val serverAuth = Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)
  private val clientAuth = Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02)

  private def ext(id: Array[Byte], critical: Boolean, value: Array[Byte]): Array[Byte] =
    if critical then seq(oid(id), tlv(0x01, Array[Byte](0xff.toByte)), tlv(0x04, value))
    else seq(oid(id), tlv(0x04, value))

  private val caTrue = ext(oidBasicConstraints, true, seq(tlv(0x01, Array[Byte](0xff.toByte))))
  private val endEntity = ext(oidBasicConstraints, false, seq())
  // KeyUsage bit 5 is keyCertSign: 0x06 with one unused bit is keyCertSign + cRLSign, 0x80 with
  // seven unused bits is digitalSignature alone.
  private val certSign = ext(oidKeyUsage, true, tlv(0x03, Array[Byte](0x01, 0x06)))
  private val signOnly = ext(oidKeyUsage, true, tlv(0x03, Array[Byte](0x07, 0x80.toByte)))
  private def san(names: String*): Array[Byte] = ext(oidSan, false, seq(names.map(n => tlv(0x82, ascii(n)))*))
  private def eku(purposes: Array[Byte]*): Array[Byte] = ext(oidEku, false, seq(purposes.map(oid)*))

  private val notBefore = "200101000000Z"
  private val notAfter = "300101000000Z"
  private val at = 1_800_000_000L // 2027-01-15, inside every fixture window

  private def tbsOf(
    serial: Int,
    issuer: String,
    subject: String,
    spki: Array[Byte],
    from: String,
    until: String,
    exts: List[Array[Byte]]
  ): Array[Byte] =
    tbsWith(serial, issuer, subject, spki, from, until, if exts.isEmpty then Array.emptyByteArray else tlv(0xa3, seq(exts*)))

  private def tbsWith(
    serial: Int,
    issuer: String,
    subject: String,
    spki: Array[Byte],
    from: String,
    until: String,
    region: Array[Byte]
  ): Array[Byte] =
    def name(cn: String) = seq(tlv(0x31, seq(oid(Array[Byte](0x55, 0x04, 0x03)), tlv(0x0c, ascii(cn)))))
    seq(
      tlv(0xa0, tlv(0x02, Array[Byte](2))), // version v3
      tlv(0x02, Array[Byte](serial.toByte)),
      seq(oid(edOid)),
      name(issuer),
      seq(tlv(0x17, ascii(from)), tlv(0x17, ascii(until))),
      name(subject),
      spki,
      region
    )
  end tbsWith

  private def assemble(tbs: Array[Byte], signature: Array[Byte]): Array[Byte] =
    seq(tbs, seq(oid(edOid)), tlv(0x03, Array[Byte](0) ++ signature))

  private type Issued = (der: Array[Byte], key: PrivateKey[Ed25519], subject: String)

  private def spkiOf(key: PublicKey[Ed25519]): IO[Array[Byte]] =
    expectRight("spki")(key.spki).map(a => Array.from(a.iterator))

  private def sign(tbs: Array[Byte], key: PrivateKey[Ed25519]): IO[Array[Byte]] =
    key.sign(Slice.of(tbs)).absolve.map(s => assemble(tbs, Array.from(s.bytes.iterator)))

  private def selfSigned(subject: String, exts: List[Array[Byte]]): IO[Issued] =
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      der <- sign(tbsOf(1, subject, subject, spki, notBefore, notAfter, exts), kp.privateKey)
    yield (der = der, key = kp.privateKey, subject = subject)

  private def issuedBy(issuer: Issued, serial: Int, subject: String, exts: List[Array[Byte]]): IO[Issued] =
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      der <- sign(tbsOf(serial, issuer.subject, subject, spki, notBefore, notAfter, exts), issuer.key)
    yield (der = der, key = kp.privateKey, subject = subject)

  private def parsed(der: Array[Byte]): IO[x5.Certificate] =
    x5.Certificate.fromDer(der) match
      case Right(c) => IO.pure(c)
      case Left(e)  => IO.raiseError(new AssertionError(s"expected a parsable certificate, got $e"))

  private def hostname(name: String): IO[x5.Hostname] =
    x5.Hostname.of(name) match
      case Right(h) => IO.pure(h)
      case Left(e)  => IO.raiseError(new AssertionError(s"hostname $name: $e"))

  private def verify(chain: List[Issued], anchor: Issued, host: Option[String]): IO[Either[x5.PathInvalid, x5.VerifiedPath]] =
    for
      certs <- chain.traverse(i => parsed(i.der))
      root <- parsed(anchor.der)
      h <- host.traverse(hostname)
      result <- x5.CertPath.verify(certs, x5.TrustAnchors(List(root)), at, h).either
    yield result

  private def indexOf(haystack: Array[Byte], needle: Array[Byte]): Int =
    (0 to haystack.length - needle.length).find(i => needle.indices.forall(j => haystack(i + j) == needle(j))).getOrElse(-1)

  test("an unrecognised CRITICAL extension is rejected; the same extension non-critical is not") {
    val subtrees = seq(tlv(0xa0, seq(seq(tlv(0x82, ascii(".corp.example"))))))
    val policy = seq(seq(oid(Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0d, 0x01))))
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      plain <- issuedBy(root, 2, "leaf", List(endEntity, san("example.com")))
      constrained <- issuedBy(root, 3, "leaf", List(endEntity, san("example.com"), ext(oidNameConstraints, true, subtrees)))
      tolerable <- issuedBy(root, 4, "leaf", List(endEntity, san("example.com"), ext(oidCertificatePolicies, false, policy)))
      ok <- verify(List(plain), root, Some("example.com"))
      _ <- check(ok.isRight, s"a chain with no unknown critical extension validates, got $ok")
      nc <- verify(List(constrained), root, Some("example.com"))
      _ <- check(nc == Left(x5.PathInvalid.ConstraintViolated), s"critical nameConstraints -> ConstraintViolated, got $nc")
      cp <- verify(List(tolerable), root, Some("example.com"))
      _ <- check(cp.isRight, s"non-critical certificatePolicies is ignorable, got $cp")
      caNc <- selfSigned("Constrained Root", List(caTrue, certSign, ext(oidNameConstraints, true, subtrees)))
      under <- issuedBy(caNc, 2, "leaf", List(endEntity, san("example.com")))
      anchored <- verify(List(under), caNc, Some("example.com"))
      _ <- check(anchored == Left(x5.PathInvalid.ConstraintViolated), s"a constrained anchor -> ConstraintViolated, got $anchored")
    yield ()
    end for
  }

  test("a CA whose KeyUsage withholds keyCertSign cannot issue") {
    for
      withheld <- selfSigned("Withholding Root", List(caTrue, signOnly))
      leaf <- issuedBy(withheld, 2, "leaf", List(endEntity, san("example.com")))
      no <- verify(List(leaf), withheld, Some("example.com"))
      _ <- check(no == Left(x5.PathInvalid.ConstraintViolated), s"no keyCertSign -> ConstraintViolated, got $no")
      granted <- selfSigned("Signing Root", List(caTrue, certSign))
      other <- issuedBy(granted, 2, "leaf", List(endEntity, san("example.com")))
      yes <- verify(List(other), granted, Some("example.com"))
      _ <- check(yes.isRight, s"keyCertSign present -> valid, got $yes")
    yield ()
  }

  test("a zero-length signature BIT STRING is Malformed rather than a raised exception") {
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      tbs = tbsOf(2, "Root", "leaf", spki, notBefore, notAfter, List(endEntity))
      crafted = seq(tbs, seq(oid(edOid)), Array[Byte](0x03, 0x00))
      result = x5.Certificate.fromDer(crafted)
      _ <- check(result == Left(Malformed), s"empty BIT STRING -> Malformed, got $result")
    yield ()
  }

  test("an EKU that cannot be parsed is a rejection, not an unrestricted certificate") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      leaf <- issuedBy(root, 2, "leaf", List(endEntity, san("example.com"), ext(oidEku, false, seq(tlv(0x02, Array[Byte](1))))))
      _ <- check(x5.Certificate.fromDer(leaf.der).isLeft, "an unreadable EKU entry must not parse as an empty EKU list")
    yield ()
  }

  test("EKU is required of every certificate in the path, not only the leaf") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      clientOnly <- issuedBy(root, 2, "Client CA", List(caTrue, certSign, eku(clientAuth)))
      leaf <- issuedBy(clientOnly, 3, "leaf", List(endEntity, san("example.com"), eku(serverAuth)))
      nested <- verify(List(leaf, clientOnly), root, Some("example.com"))
      _ <- check(nested == Left(x5.PathInvalid.ConstraintViolated), s"clientAuth intermediate -> ConstraintViolated, got $nested")
      serverOk <- issuedBy(root, 4, "Server CA", List(caTrue, certSign, eku(serverAuth)))
      under <- issuedBy(serverOk, 5, "leaf", List(endEntity, san("example.com"), eku(serverAuth)))
      ok <- verify(List(under, serverOk), root, Some("example.com"))
      _ <- check(ok.isRight, s"serverAuth throughout validates, got $ok")
    yield ()
  }

  test("a repeated extension, trailing bytes, and a child TLV overrunning its parent are all Malformed") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      duplicated <- issuedBy(root, 2, "leaf", List(endEntity, san("example.com"), endEntity))
      _ <- check(x5.Certificate.fromDer(duplicated.der).isLeft, "a repeated extension OID must not be last-wins")
      leaf <- issuedBy(root, 3, "leaf", List(endEntity, san("example.com")))
      _ <- check(x5.Certificate.fromDer(leaf.der ++ Array[Byte](0)).isLeft, "bytes after the outer SEQUENCE must be rejected")
      roundTrip = x5.Certificate.fromDer(leaf.der).map(c => Array.from(c.der.iterator).sameElements(leaf.der))
      _ <- check(roundTrip == Right(true), s"der round-trips the accepted encoding, got $roundTrip")
      marker = Array[Byte](0x06, 0x03, 0x55, 0x1d, 0x11)
      pos = indexOf(leaf.der, marker)
      _ <- check(pos > 0, "the SAN extension is present in the fixture")
      overrun = leaf.der.updated(pos - 1, (leaf.der(pos - 1) + 8).toByte)
      _ <- check(x5.Certificate.fromDer(overrun).isLeft, "an extension reaching past the extensions SEQUENCE must be rejected")
    yield ()
  }

  test("an unreadable extensions region is a rejection, not a certificate without extensions") {
    // [3] present but holding a SET where the Extensions SEQUENCE belongs; a [1] issuerUniqueID
    // claiming more content than the certificate holds; extensions followed by a further field.
    val notASequence = tlv(0xa3, tlv(0x31, endEntity))
    val truncated = Array[Byte](0x81.toByte, 0x7f)
    val wellFormed = tlv(0xa3, seq(endEntity, san("example.com")))
    val trailing = wellFormed ++ tlv(0x05, Array.emptyByteArray)
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      _ <- List(notASequence, truncated, trailing).traverse_ { region =>
             val der = assemble(tbsWith(2, "Root", "leaf", spki, notBefore, notAfter, region), new Array[Byte](64))
             check(x5.Certificate.fromDer(der).isLeft, "an unreadable extensions region must not parse as an extension-less certificate")
           }
      intact = assemble(tbsWith(2, "Root", "leaf", spki, notBefore, notAfter, wellFormed), new Array[Byte](64))
      names = x5.Certificate.fromDer(intact).map(_.subjectAltDns)
      _ <- check(names == Right(List("example.com")), s"the well-formed region still parses, got $names")
    yield ()
  }

  test("SAN matching folds ASCII only and needs a label beneath a wildcard") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      leaf <- issuedBy(root, 2, "leaf", List(endEntity, san("K.example.com")))
      folded <- verify(List(leaf), root, Some("k.EXAMPLE.com"))
      _ <- check(folded.isRight, s"ASCII case folds, got $folded")
      // U+212A KELVIN SIGN lower-cases to ASCII 'k' under Unicode folding, in every locale.
      kelvin <- verify(List(leaf), root, Some(s"${0x212a.toChar}.example.com"))
      _ <- check(kelvin == Left(x5.PathInvalid.NameMismatch), s"U+212A must not fold onto 'k', got $kelvin")
      broad <- issuedBy(root, 3, "leaf", List(endEntity, san("*.com")))
      any <- verify(List(broad), root, Some("example.com"))
      _ <- check(any == Left(x5.PathInvalid.NameMismatch), s"`*.com` must match nothing, got $any")
      narrow <- issuedBy(root, 4, "leaf", List(endEntity, san("*.example.com")))
      sub <- verify(List(narrow), root, Some("foo.example.com"))
      _ <- check(sub.isRight, s"a wildcard with a label beneath it still matches, got $sub")
    yield ()
  }

  test("validity times must be Zulu with in-range fields") {
    val rejected = List(
      "200101000000+0100", // offset form: RFC 5280 requires Zulu
      "201301000000Z", // month 13
      "200230000000Z", // 30 February
      "200101250000Z", // hour 25
      "200101000060Z", // second 60
      "20010100000Z" // eleven digits
    )
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      _ <- rejected.traverse_ { from =>
             val der = assemble(tbsOf(2, "Root", "leaf", spki, from, notAfter, List(endEntity)), new Array[Byte](64))
             check(x5.Certificate.fromDer(der).isLeft, s"notBefore $from must be rejected")
           }
      good = assemble(tbsOf(2, "Root", "leaf", spki, notBefore, notAfter, List(endEntity)), new Array[Byte](64))
      _ <- check(x5.Certificate.fromDer(good).isRight, "a Zulu window with in-range fields parses")
    yield ()
  }

  test("PEM decoding ignores text outside the boundaries and requires the CERTIFICATE label") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      pem = PEM.encode(PEM.Block("CERTIFICATE", IArray.from(root.der)))
      annotated = "Certificate:\n    Data:\n        Version: 3 (0x2)\n" + pem
      _ <- check(x5.Certificate.fromPem(annotated).isRight, "explanatory text before the block is ignored")
      mislabelled = PEM.encode(PEM.Block("PRIVATE KEY", IArray.from(root.der)))
      _ <- check(x5.Certificate.fromPem(mislabelled).isLeft, "a certificate under another label is rejected")
      bundle = "leaf:\n" + pem + "\nissuer:\n" + pem
      _ <- check(x5.Certificate.chainFromPem(bundle).map(_.length) == Right(2), "text between blocks is ignored")
    yield ()
  }

  test("a rollover anchor sharing a subject DN is tried rather than committed to by name") {
    for
      retired <- selfSigned("Test Root CA", List(caTrue, certSign))
      current <- selfSigned("Test Root CA", List(caTrue, certSign))
      leaf <- issuedBy(current, 2, "leaf", List(endEntity, san("example.com")))
      cert <- parsed(leaf.der)
      first <- parsed(retired.der)
      second <- parsed(current.der)
      host <- hostname("example.com")
      result <- x5.CertPath.verify(List(cert), x5.TrustAnchors(List(first, second)), at, Some(host)).either
      _ <- check(result.isRight, s"the second same-name anchor must be tried, got $result")
    yield ()
  }

  private def gtime(value: String): Array[Byte] = tlv(0x18, ascii(value))
  private val ocspBasicOid = oid(Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01))
  private val ocspCertId =
    seq(oid(Array[Byte](0x2b, 0x0e, 0x03, 0x02, 0x1a)), tlv(0x04, Array[Byte](1)), tlv(0x04, Array[Byte](2)), tlv(0x02, Array[Byte](3)))

  private def staple(status: Array[Byte], thisUpdate: String, nextUpdate: Option[String]): Array[Byte] =
    val single = seq((List(ocspCertId, status, gtime(thisUpdate)) ++ nextUpdate.map(n => tlv(0xa0, gtime(n))))*)
    val responseData = seq(tlv(0xa2, tlv(0x04, Array[Byte](1, 2, 3, 4))), gtime("20260101000000Z"), seq(single))
    val basic = seq(responseData, seq(ocspBasicOid), tlv(0x03, Array[Byte](0, 0)))
    seq(tlv(0x0a, Array[Byte](0)), tlv(0xa0, seq(ocspBasicOid, tlv(0x04, basic))))

  test("a stapled response outside its own update window carries no Good verdict") {
    val good = Array[Byte](0x80.toByte, 0x00)
    val revoked = tlv(0xa1, gtime("20250601000000Z"))
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      cert <- parsed(root.der)
      fresh <- x5.OCSP.verifyStapled(staple(good, "20260101000000Z", Some("20360101000000Z")), cert, cert, at).either
      _ <- check(fresh == Right(x5.OCSP.Status.Good), s"a current Good staple is honoured, got $fresh")
      expired <- x5.OCSP.verifyStapled(staple(good, "20200101000000Z", Some("20200102000000Z")), cert, cert, at).either
      _ <- check(expired == Right(x5.OCSP.Status.Unknown), s"a Good staple past nextUpdate -> Unknown, got $expired")
      early <- x5.OCSP.verifyStapled(staple(good, "20360101000000Z", None), cert, cert, at).either
      _ <- check(early == Right(x5.OCSP.Status.Unknown), s"a Good staple before thisUpdate -> Unknown, got $early")
      stale <- x5.OCSP.verifyStapled(staple(revoked, "20200101000000Z", Some("20200102000000Z")), cert, cert, at).either
      _ <- check(stale.exists { case x5.OCSP.Status.Revoked(_) => true; case _ => false }, s"a stale Revoked still stands, got $stale")
    yield ()
    end for
  }
  test("a certificate whose subject key kufuli cannot import still parses and says so") {
    // A DSA SubjectPublicKeyInfo (1.2.840.10040.4.1): well-formed X.509, outside kufuli's families.
    val dsaSpki =
      seq(seq(oid(Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x01))), tlv(0x03, Array[Byte](0) ++ Array.fill[Byte](20)(7)))
    for
      kp <- Ed25519.generate.absolve
      der <- sign(tbsOf(9, "unsupported", "unsupported", dsaSpki, notBefore, notAfter, Nil), kp.privateKey)
      cert <- IO.fromEither(x5.Certificate.fromDer(der).left.map(e => new AssertionError(s"parse: $e")))
      _ <- check(cert.publicKey.swap.toOption.contains(InvalidKey.Unsupported),
                 s"unsupported SPKI reports itself, got ${cert.publicKey.isRight}"
           )
      _ <- check(cert.subjectAltDns.isEmpty && cert.der.length == der.length, "the certificate stays inspectable")
      mine <- selfSigned("ok.example", List(endEntity))
      good <- IO.fromEither(x5.Certificate.fromDer(mine.der).left.map(e => new AssertionError(s"parse: $e")))
      _ <- check(good.publicKey.isRight, "a supported SPKI yields its key")
    yield ()
    end for
  }
end X509HardeningSuite
