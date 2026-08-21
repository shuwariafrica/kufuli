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

import scala.compiletime.testing.typeChecks

import boilerplate.Slice
import boilerplate.effect.*
import cats.effect.IO

import kufuli.*
import kufuli.tests.support.*
import kufuli.tests.x509fixtures.*
import kufuli.x509 as x5

class X509StrictnessSuite extends munit.CatsEffectSuite:

  private val rsaOid = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x01)
  private val pssOid = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x0a)
  private val mgf1Oid = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x08)
  private val sha384Oid = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
  private val sha512Oid = Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)

  private def rsaSpki(modulusOctets: Int): Array[Byte] =
    val modulus = Array[Byte](0) ++ Array.fill[Byte](modulusOctets)(0xff.toByte)
    val key = seq(tlv(0x02, modulus), tlv(0x02, Array[Byte](1, 0, 1)))
    seq(seq(oid(rsaOid), tlv(0x05, Array.emptyByteArray)), tlv(0x03, Array[Byte](0) ++ key))

  private def pssAlgorithm(hashOid: Array[Byte], mgfHashOid: Array[Byte], saltLength: Int): Array[Byte] =
    val hash = seq(oid(hashOid), tlv(0x05, Array.emptyByteArray))
    seq(
      oid(pssOid),
      seq(
        tlv(0xa0, hash),
        tlv(0xa1, seq(oid(mgf1Oid), seq(oid(mgfHashOid), tlv(0x05, Array.emptyByteArray)))),
        tlv(0xa2, tlv(0x02, Array[Byte](saltLength.toByte)))
      )
    )

  // An RSA CA over a leaf it signs, so the leaf's signature is actually verified with the scheme its
  // algorithm identifier names - a directly pinned certificate would be trusted without a check.
  private def rsaChain(algorithm: Array[Byte], scheme: Scheme[RSA]): IO[(anchor: Array[Byte], leaf: Array[Byte])] =
    def certificate(subject: String, spki: Array[Byte], exts: Array[Byte], key: PrivateKey[RSA]): IO[Array[Byte]] =
      val tbs = seq(
        tlv(0xa0, tlv(0x02, Array[Byte](2))),
        tlv(0x02, Array[Byte](1)),
        algorithm,
        name("Root"),
        seq(tlv(0x17, ascii(notBefore)), tlv(0x17, ascii(notAfter))),
        name(subject),
        spki,
        exts
      )
      key.sign(Slice.of(tbs), scheme).absolve.map(s => seq(tbs, algorithm, tlv(0x03, Array[Byte](0) ++ Array.from(s.bytes.iterator))))
    end certificate
    for
      ca <- RSA.generate(RSA.bits(2048)).absolve
      caSpki <- expectRight("spki")(ca.publicKey.spki).map(a => Array.from(a.bytes.iterator))
      leafKey <- RSA.generate(RSA.bits(2048)).absolve
      leafSpki <- expectRight("spki")(leafKey.publicKey.spki).map(a => Array.from(a.bytes.iterator))
      anchor <- certificate("Root", caSpki, tlv(0xa3, seq(caTrue, certSign)), ca.privateKey)
      leaf <- certificate("leaf", leafSpki, tlv(0xa3, seq(endEntity, san("host.example"))), ca.privateKey)
    yield (anchor = anchor, leaf = leaf)
  end rsaChain

  private def verifyChain(pair: (anchor: Array[Byte], leaf: Array[Byte])): IO[Either[x5.PathInvalid, x5.VerifiedPath]] =
    for
      anchor <- parsed(pair.anchor)
      leaf <- parsed(pair.leaf)
      id <- serverId("host.example")
      result <- x5.CertPath.verify(List(leaf), x5.TrustAnchors(anchor), at, id).either.absolve
    yield result

  test("the outer signatureAlgorithm must be the same bytes as the signed inner one") {
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      tbs = tbsOf(1, "Root", "Root", spki, notBefore, notAfter, List(caTrue, certSign))
      signature <- kp.privateKey.sign(Slice.of(tbs)).absolve
      raw = Array.from(signature.bytes.iterator)
      honest = seq(tbs, seq(oid(edOid)), tlv(0x03, Array[Byte](0) ++ raw))
      _ <- check(x5.Certificate.parse(honest).isRight, "matching algorithm identifiers parse")
      substituted = seq(tbs, seq(oid(sha384Oid)), tlv(0x03, Array[Byte](0) ++ raw))
      _ <- check(x5.Certificate.parse(substituted) == Left(Malformed), "a substituted outer algorithm is Malformed")
      padded = seq(tbs, seq(oid(edOid), tlv(0x05, Array.emptyByteArray)), tlv(0x03, Array[Byte](0) ++ raw))
      _ <- check(x5.Certificate.parse(padded) == Left(Malformed), "differing parameters are a difference too")
    yield ()
  }

  test("version is read: v3 is required when extensions are present, and a DEFAULT v1 is not encoded") {
    def certificate(version: Array[Byte], region: Array[Byte]): IO[Array[Byte]] =
      for
        kp <- Ed25519.generate.absolve
        spki <- spkiOf(kp.publicKey)
        tbs = seq(
                version,
                tlv(0x02, Array[Byte](1)),
                seq(oid(edOid)),
                name("Root"),
                seq(tlv(0x17, ascii(notBefore)), tlv(0x17, ascii(notAfter))),
                name("Root"),
                spki,
                region
              )
        der <- signed(tbs, kp.privateKey)
      yield der
    val v1 = tlv(0xa0, tlv(0x02, Array[Byte](0)))
    val v2 = tlv(0xa0, tlv(0x02, Array[Byte](1)))
    val v3 = tlv(0xa0, tlv(0x02, Array[Byte](2)))
    val v9 = tlv(0xa0, tlv(0x02, Array[Byte](9)))
    val exts = tlv(0xa3, seq(caTrue))
    for
      encodedV1 <- certificate(v1, Array.emptyByteArray)
      _ <- check(x5.Certificate.parse(encodedV1) == Left(Malformed), "an explicitly encoded v1 violates DER DEFAULT omission")
      unknown <- certificate(v9, Array.emptyByteArray)
      _ <- check(x5.Certificate.parse(unknown) == Left(Malformed), "an unknown version value is rejected")
      v2WithExts <- certificate(v2, exts)
      _ <- check(x5.Certificate.parse(v2WithExts) == Left(Malformed), "extensions require v3")
      v3WithExts <- certificate(v3, exts)
      _ <- check(x5.Certificate.parse(v3WithExts).isRight, "v3 with extensions parses")
      absent <- certificate(Array.emptyByteArray, Array.emptyByteArray)
      _ <- check(x5.Certificate.parse(absent).isRight, "an absent version with no extensions is v1")
      padded <- certificate(tlv(0xa0, tlv(0x02, Array[Byte](0, 2))), exts)
      _ <- check(x5.Certificate.parse(padded) == Left(Malformed), "a non-minimal INTEGER is a second encoding of v3")
    yield ()
    end for
  }

  test("a DER BOOLEAN is absent or 0xFF, at the criticality flag and at the cA flag alike") {
    def flagged(content: Array[Byte]): Array[Byte] =
      seq(oid(oidBasicConstraints), tlv(0x01, content), tlv(0x04, seq()))
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      explicitFalse <- signed(tbsOf(1, "Root", "Root", spki, notBefore, notAfter, List(flagged(Array[Byte](0x00)))), kp.privateKey)
      _ <- check(x5.Certificate.parse(explicitFalse) == Left(Malformed), "an explicit FALSE criticality is Malformed")
      trueAsOne <- signed(tbsOf(2, "Root", "Root", spki, notBefore, notAfter, List(flagged(Array[Byte](0x01)))), kp.privateKey)
      _ <- check(x5.Certificate.parse(trueAsOne) == Left(Malformed), "a TRUE encoded as 0x01 is Malformed")
      caFalse = ext(oidBasicConstraints, true, seq(tlv(0x01, Array[Byte](0x00))))
      explicitCa <- signed(tbsOf(3, "Root", "Root", spki, notBefore, notAfter, List(caFalse)), kp.privateKey)
      _ <- check(x5.Certificate.parse(explicitCa) == Left(Malformed), "an explicit cA = FALSE is Malformed")
      absent <- signed(tbsOf(4, "Root", "Root", spki, notBefore, notAfter, List(endEntity)), kp.privateKey)
      _ <- check(x5.Certificate.parse(absent).isRight, "an omitted DEFAULT parses")
    yield ()
    end for
  }

  test("a NameConstraints extension carrying no subtrees, or a minimum, is Malformed") {
    def withValue(value: Array[Byte]): IO[Array[Byte]] =
      for
        kp <- Ed25519.generate.absolve
        spki <- spkiOf(kp.publicKey)
        der <- signed(
                 tbsOf(1, "Root", "Root", spki, notBefore, notAfter, List(caTrue, certSign, ext(oidNameConstraints, true, value))),
                 kp.privateKey
               )
      yield der
    for
      empty <- withValue(seq())
      _ <- check(x5.Certificate.parse(empty) == Left(Malformed), "an empty NameConstraints SEQUENCE is Malformed")
      emptyList <- withValue(seq(tlv(0xa0, Array.emptyByteArray)))
      _ <- check(x5.Certificate.parse(emptyList) == Left(Malformed), "an empty GeneralSubtrees list is Malformed")
      withMinimum <- withValue(seq(tlv(0xa0, seq(dnsName("example.com"), tlv(0x80.toByte, Array[Byte](0))))))
      _ <- check(x5.Certificate.parse(withMinimum) == Left(Malformed), "an encoded minimum is Malformed")
      leadingDot <- withValue(seq(tlv(0xa0, seq(dnsName(".example.com")))))
      _ <- check(x5.Certificate.parse(leadingDot) == Left(Malformed), "a leading-dot dNSName base is Malformed")
      wildcard <- withValue(seq(tlv(0xa0, seq(dnsName("*.example.com")))))
      _ <- check(x5.Certificate.parse(wildcard) == Left(Malformed), "a wildcard dNSName base is Malformed")
      shortIp <- withValue(seq(tlv(0xa0, seq(ipName(Array[Byte](10, 0, 0, 0))))))
      _ <- check(x5.Certificate.parse(shortIp) == Left(Malformed), "an iPAddress base without its mask is Malformed")
      sparse <- withValue(seq(tlv(0xa0, seq(ipName(Array[Byte](10, 0, 0, 0, 255.toByte, 0, 255.toByte, 0))))))
      _ <- check(x5.Certificate.parse(sparse) == Left(Malformed), "a non-contiguous mask is Malformed")
      good <- withValue(seq(tlv(0xa0, seq(dnsName("example.com")))))
      _ <- check(x5.Certificate.parse(good).isRight, "a well-formed constraint parses")
    yield ()
    end for
  }

  test("a SAN entry that is not a name of its form rejects the certificate") {
    def leafWith(entry: Array[Byte]): IO[Array[Byte]] =
      for
        kp <- Ed25519.generate.absolve
        spki <- spkiOf(kp.publicKey)
        der <- signed(tbsOf(1, "Root", "Root", spki, notBefore, notAfter, List(endEntity, sanOf(entry))), kp.privateKey)
      yield der
    for
      empty <- leafWith(dnsName(""))
      _ <- check(x5.Certificate.parse(empty) == Left(Malformed), "a zero-length GeneralName is Malformed")
      dotted <- leafWith(dnsName(".example.com"))
      _ <- check(x5.Certificate.parse(dotted) == Left(Malformed), "a leading-dot dNSName SAN is Malformed")
      inner <- leafWith(dnsName("a.*.example.com"))
      _ <- check(x5.Certificate.parse(inner) == Left(Malformed), "a wildcard that is not leftmost is Malformed")
      partial <- leafWith(dnsName("w*.example.com"))
      _ <- check(x5.Certificate.parse(partial) == Left(Malformed), "a partial-label wildcard is Malformed")
      ip <- leafWith(ipName(Array[Byte](10, 0, 0)))
      _ <- check(x5.Certificate.parse(ip) == Left(Malformed), "an iPAddress SAN of three octets is Malformed")
      mail <- leafWith(emailName("a@b@c.example"))
      _ <- check(x5.Certificate.parse(mail) == Left(Malformed), "a multi-@ rfc822Name is Malformed")
      wildcard <- leafWith(dnsName("*.example.com"))
      _ <- check(x5.Certificate.parse(wildcard).isRight, "a leftmost full-label wildcard parses")
    yield ()
    end for
  }

  test("every SAN form is parsed and readable") {
    val dn = seq(rdn(oidOrganisation, 0x13, "Kufuli Test"))
    for
      kp <- Ed25519.generate.absolve
      spki <- spkiOf(kp.publicKey)
      entries = sanOf(
                  dnsName("host.example"),
                  ipName(Array[Byte](192.toByte, 0, 2, 1)),
                  emailName("ops@example.com"),
                  uriName("spiffe://example.com/workload"),
                  dirName(dn),
                  otherName(seq(oid(serverAuth), tlv(0xa0, tlv(0x0c, ascii("x")))))
                )
      der <- signed(tbsOf(1, "Root", "leaf", spki, notBefore, notAfter, List(endEntity, entries)), kp.privateKey)
      cert <- parsed(der)
      _ <- check(cert.subjectAltDns == List("host.example"), s"dNSName, got ${cert.subjectAltDns}")
      _ <- check(cert.subjectAltIps == x5.IpAddress.parse("192.0.2.1").toOption.toList, s"iPAddress, got ${cert.subjectAltIps.length}")
      _ <- check(cert.subjectAltEmails == List("ops@example.com"), s"rfc822Name, got ${cert.subjectAltEmails}")
      _ <- check(cert.subjectAltUris == List("spiffe://example.com/workload"), s"URI, got ${cert.subjectAltUris}")
      _ <- check(Array.from(cert.subjectDer.iterator).sameElements(name("leaf")), "subjectDer is the encoded Name")
      _ <- check(Array.from(cert.issuerDer.iterator).sameElements(name("Root")), "issuerDer is the encoded Name")
    yield ()
    end for
  }

  test("an RSA subject key below 2048 bits is not imported") {
    for
      kp <- Ed25519.generate.absolve
      weak <- signed(tbsOf(1, "Root", "Root", rsaSpki(128), notBefore, notAfter, List(endEntity)), kp.privateKey)
      weakCert <- parsed(weak)
      weakKey <- weakCert.publicKey.either.absolve
      _ <- check(weakKey == Left(InvalidKey.Unsupported), s"a 1024-bit modulus -> Unsupported, got $weakKey")
      floor <- signed(tbsOf(2, "Root", "Root", rsaSpki(256), notBefore, notAfter, List(endEntity)), kp.privateKey)
      floorCert <- parsed(floor)
      floorKey <- floorCert.publicKey.either.absolve
      _ <- check(floorKey.isRight, s"a 2048-bit modulus is imported, got $floorKey")
      under <- signed(tbsOf(3, "Root", "Root", rsaSpki(255), notBefore, notAfter, List(endEntity)), kp.privateKey)
      underCert <- parsed(under)
      underKey <- underCert.publicKey.either.absolve
      _ <- check(underKey == Left(InvalidKey.Unsupported), s"2040 bits is below the floor, got $underKey")
      // The modulus INTEGER claims 256 octets while the RSAPublicKey SEQUENCE it sits in declares
      // five, so reading it unbounded counts a 2048-bit modulus that the encoding does not carry.
      overrun = seq(
                  seq(oid(rsaOid), tlv(0x05, Array.emptyByteArray)),
                  tlv(0x03, Array[Byte](0, 0x30, 0x05, 0x02, 0x82.toByte, 0x01, 0x00) ++ Array.fill[Byte](256)(0xff.toByte))
                )
      crafted <- signed(tbsOf(4, "Root", "Root", overrun, notBefore, notAfter, List(endEntity)), kp.privateKey)
      craftedCert <- parsed(crafted)
      craftedKey <- craftedCert.publicKey.either.absolve
      _ <- check(craftedKey.isLeft, s"a modulus overrunning its SEQUENCE yields no key, got $craftedKey")
      // The arm above is whichever the backend names for an encoding it declines; the floor's own
      // read is shared code, and it is what must not count octets the SEQUENCE does not carry.
      _ <- check(RSA.flooredSpki(Slice.of(overrun)) == Left(InvalidKey.Malformed), "and the floor refuses to read past the SEQUENCE")
    yield ()
    end for
  }

  test("a certificate key is imported before it is handed out, so an off-curve point yields no key") {
    val ecAlg = seq(
      oid(Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x02, 0x01)),
      oid(Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x03, 0x01, 0x07))
    )
    val offCurve = Array[Byte](0x04) ++ Array.fill[Byte](31)(0) ++ Array[Byte](1) ++ Array.fill[Byte](31)(0) ++ Array[Byte](1)
    val badSpki = seq(ecAlg, tlv(0x03, Array[Byte](0) ++ offCurve))
    for
      kp <- Ed25519.generate.absolve
      root <- signed(tbsOf(1, "Root", "Root", badSpki, notBefore, notAfter, List(caTrue, certSign)), kp.privateKey)
      leafKey <- Ed25519.generate.absolve
      leafSpki <- spkiOf(leafKey.publicKey)
      leaf <- signed(tbsOf(2, "Root", "leaf", leafSpki, notBefore, notAfter, List(endEntity, san("host.example"))), kp.privateKey)
      anchor <- parsed(root)
      cert <- parsed(leaf)
      // The peek that dispatches the family accepts this encoding; the import is what rejects it.
      key <- anchor.publicKey.either.absolve
      // Which arm names the refusal is the backend's: the JVM runs its own on-curve test where
      // aws-lc and node report an encoding they will not parse. What binds is that no key is
      // produced, and that the chain-level mapping below is uniform.
      _ <- check(key.isLeft, s"an off-curve point yields no key, got $key")
      id <- serverId("host.example")
      result <- x5.CertPath.verify(List(cert), x5.TrustAnchors(anchor), at, id).either.absolve
      _ <- check(result == Left(x5.PathInvalid.MalformedChain), s"and the chain reports unusable key material, got $result")
    yield ()
    end for
  }

  test("RSASSA-PSS certificates carry their digest in the algorithm parameters") {
    for
      sha384 <- rsaChain(pssAlgorithm(sha384Oid, sha384Oid, 48), RsaPss(Sha384))
      ok <- verifyChain(sha384)
      _ <- check(ok.isRight, s"a PSS-SHA384 certificate verifies with SHA-384, got $ok")
      // Signed with SHA-384 as the parameters' own hashAlgorithm names, so only the parameter read
      // decides the outcome: hardcoding SHA-256 or ignoring the mismatch would both accept it.
      wrong <- rsaChain(pssAlgorithm(sha384Oid, sha384Oid, 48), RsaPss(Sha256))
      mismatch <- verifyChain(wrong)
      _ <- check(mismatch == Left(x5.PathInvalid.BadSignature), s"a digest other than the one named fails, got $mismatch")
      crossed <- rsaChain(pssAlgorithm(sha384Oid, sha512Oid, 48), RsaPss(Sha384))
      mgf <- verifyChain(crossed)
      _ <- check(mgf == Left(x5.PathInvalid.UnsupportedAlgorithm), s"an MGF1 digest differing from the hash has no scheme, got $mgf")
      salted <- rsaChain(pssAlgorithm(sha384Oid, sha384Oid, 32), RsaPss(Sha384))
      salt <- verifyChain(salted)
      _ <- check(salt == Left(x5.PathInvalid.UnsupportedAlgorithm), s"a salt length other than the digest length has no scheme, got $salt")
    yield ()
  }

  test("certificates compare by their DER, so a chain pool collapses byte-identical entries") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      other <- selfSigned("Root", List(caTrue, certSign))
      first <- parsed(root.der)
      again <- parsed(root.der)
      distinct <- parsed(other.der)
      _ <- check(first == again, "two parses of the same DER are the same certificate")
      _ <- check(first.hashCode == again.hashCode, "and hash alike")
      _ <- check(first != distinct, "a different certificate is not equal")
      leaf <- issuedBy(root, 2, "leaf", List(endEntity, san("host.example")))
      certs <- parsed(leaf.der)
      id <- serverId("host.example")
      // The pool holds the same intermediate twice; duplicate elimination has to collapse them
      // without copying the DER for every comparison.
      result <- x5.CertPath.verify(List(certs, first, first), x5.TrustAnchors(first), at, id).either.absolve
      _ <- check(result.isRight, s"a duplicated pool entry still validates, got $result")
    yield ()
  }

  // A peer supplies the issuer certificate, so its key encoding is attacker-chosen. Every backend
  // imports it before a signature is attempted, which is what keeps the failure inside the
  // PathInvalid channel: wrapping the bytes instead leaves the backend meeting an unvalidated key
  // inside its own verify call, where node reports a defect rather than a typed outcome.
  test("a certificate key that is not on its curve fails closed at verification on every backend") {
    val ecPublicKey = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x02, 0x01)
    val prime256v1 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x03, 0x01, 0x07)
    val ecdsaSha256 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x04, 0x03, 0x02)
    val offCurve = seq(
      seq(oid(ecPublicKey), oid(prime256v1)),
      tlv(0x03, Array[Byte](0, 4) ++ Array.fill[Byte](32)(1) ++ Array.fill[Byte](32)(2))
    )
    val signature = seq(tlv(0x02, Array[Byte](1)), tlv(0x02, Array[Byte](1)))
    def certificate(subject: String, spki: Array[Byte], exts: List[Array[Byte]]): Array[Byte] =
      val tbs = seq(
        tlv(0xa0, tlv(0x02, Array[Byte](2))),
        tlv(0x02, Array[Byte](1)),
        seq(oid(ecdsaSha256)),
        name("Root"),
        seq(tlv(0x17, ascii(notBefore)), tlv(0x17, ascii(notAfter))),
        name(subject),
        spki,
        tlv(0xa3, seq(exts*))
      )
      seq(tbs, seq(oid(ecdsaSha256)), tlv(0x03, Array[Byte](0) ++ signature))
    end certificate
    for
      kp <- Ed25519.generate.absolve
      leafSpki <- spkiOf(kp.publicKey)
      anchor <- parsed(certificate("Root", offCurve, List(caTrue, certSign)))
      leaf <- parsed(certificate("leaf", leafSpki, List(endEntity, san("host.example"))))
      id <- serverId("host.example")
      result <- x5.CertPath.verify(List(leaf), x5.TrustAnchors(anchor), at, id).either.absolve
      _ <- check(result == Left(x5.PathInvalid.MalformedChain), s"an off-curve issuer key verifies nothing, got $result")
      // The accessor declines the same encoding on every backend, and declines it as a value: there
      // is no key to hand to an operation whose channel could not carry the refusal.
      direct <- anchor.publicKey.either.absolve.attempt
      _ <- check(direct.exists(_.isLeft), s"and the accessor declines it typed, never raised, got $direct")
    yield ()
    end for
  }

  test("a certificate key is imported through the blocklist, so a low-order point never reaches agree") {
    val xOid = Array[Byte](0x2b, 0x65, 0x6e)
    def xSpki(point: Array[Byte]): Array[Byte] = seq(seq(oid(xOid)), tlv(0x03, Array[Byte](0) ++ point))
    for
      kp <- Ed25519.generate.absolve
      // The all-zero u-coordinate: RFC 7748 section 6.1 gives it a scalar product of zero under
      // every private key, so an agreement with it is no agreement at all.
      weak <- signed(tbsOf(1, "Root", "peer", xSpki(new Array[Byte](32)), notBefore, notAfter, List(endEntity)), kp.privateKey)
      weakCert <- parsed(weak)
      blocked <- weakCert.publicKey.either.absolve
      _ <- check(blocked == Left(InvalidKey.WeakPoint), s"a low-order point yields no key, got $blocked")
      // The peek reads the AlgorithmIdentifier alone, so key octets of the wrong width dispatch to
      // their family and are refused by the import rather than handed out unvalidated.
      truncated <-
        signed(
          tbsOf(2, "Root", "peer", seq(seq(oid(edOid)), tlv(0x03, Array[Byte](0, 1, 2, 3, 4, 5))), notBefore, notAfter, List(endEntity)),
          kp.privateKey
        )
      shortCert <- parsed(truncated)
      refused <- shortCert.publicKey.either.absolve
      _ <- check(refused.isLeft, s"a truncated key encoding yields no key, got $refused")
      real <- X25519.generate.absolve
      spki <- expectRight("x spki")(real.publicKey.spki).map(a => Array.from(a.bytes.iterator))
      sound <- signed(tbsOf(3, "Root", "peer", spki, notBefore, notAfter, List(endEntity)), kp.privateKey)
      soundCert <- parsed(sound)
      key <- soundCert.publicKey.either.absolve
      _ <- check(key.exists { case ImportedPublicKey.X(_) => true; case _ => false }, s"a sound X25519 certificate key imports, got $key")
    yield ()
    end for
  }

  test("the certificate accessor and the core import door refuse an encoding with the same arm") {
    // The AlgorithmIdentifier slot holds an INTEGER: structurally garbage rather than an algorithm
    // kufuli lacks, so neither door may report it as unsupported.
    val garbage = seq(tlv(0x02, Array[Byte](1)), tlv(0x03, Array[Byte](0) ++ Array.fill[Byte](32)(7)))
    for
      kp <- Ed25519.generate.absolve
      leafSpki <- spkiOf(kp.publicKey)
      anchorDer <- signed(tbsOf(1, "Root", "Root", garbage, notBefore, notAfter, List(caTrue, certSign)), kp.privateKey)
      anchor <- parsed(anchorDer)
      door <- PublicKey.parse(SPKI(Slice.of(garbage))).either.absolve
      accessor <- anchor.publicKey.either.absolve
      _ <- check(door.swap.toOption == accessor.swap.toOption, s"one encoding, one arm: door=$door accessor=$accessor")
      _ <- check(accessor == Left(InvalidKey.Malformed), s"and the arm is the malformed one, got $accessor")
      leafDer <- signed(tbsOf(2, "Root", "leaf", leafSpki, notBefore, notAfter, List(endEntity, san("host.example"))), kp.privateKey)
      leaf <- parsed(leafDer)
      id <- serverId("host.example")
      chain <- x5.CertPath.verify(List(leaf), x5.TrustAnchors(anchor), at, id).either.absolve
      _ <- check(chain == Left(x5.PathInvalid.MalformedChain), s"so the chain reports unusable key material, got $chain")
    yield ()
    end for
  }

  test("a chain whose issuer key algorithm kufuli lacks says so, rather than reporting a forgery") {
    val dsaSpki = seq(
      seq(
        oid(Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x01)),
        seq(tlv(0x02, Array[Byte](2)), tlv(0x02, Array[Byte](3)), tlv(0x02, Array[Byte](5)))
      ),
      tlv(0x03, Array[Byte](0) ++ Array.fill[Byte](20)(1))
    )
    for
      kp <- Ed25519.generate.absolve
      leafSpki <- spkiOf(kp.publicKey)
      anchorDer <- signed(tbsOf(1, "Root", "Root", dsaSpki, notBefore, notAfter, List(caTrue, certSign)), kp.privateKey)
      leafDer <- signed(tbsOf(2, "Root", "leaf", leafSpki, notBefore, notAfter, List(endEntity, san("host.example"))), kp.privateKey)
      anchor <- parsed(anchorDer)
      leaf <- parsed(leafDer)
      id <- serverId("host.example")
      result <- x5.CertPath.verify(List(leaf), x5.TrustAnchors(anchor), at, id).either.absolve
      _ <- check(result == Left(x5.PathInvalid.UnsupportedAlgorithm), s"an unimplemented issuer key algorithm names itself, got $result")
      _ <- check(typeChecks("def p: x5.VerifiedPath = ???; p == p"), "a verified path compares, as the certificates it holds do")
    yield ()
    end for
  }

  test("a chain that reaches no anchor reports the anchor, not the last failure it met on the way") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      stranger <- selfSigned("Stranger", List(caTrue, certSign))
      leaf <- issuedBy(stranger, 2, "leaf", List(endEntity, san("host.example")))
      anchor <- parsed(root.der).map(x5.TrustAnchors(_))
      cert <- parsed(leaf.der)
      id <- serverId("host.example")
      result <- x5.CertPath.verify(List(cert), anchor, at, id).either.absolve
      _ <- check(result == Left(x5.PathInvalid.UntrustedAnchor), s"no candidate path reaches an anchor -> UntrustedAnchor, got $result")
    yield ()
  }

  test("TrustAnchors is non-empty by construction and reports an empty bundle as data") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      cert <- parsed(root.der)
      _ <- check(x5.TrustAnchors(cert).anchors == List(cert), "the varargs entry keeps its order")
      _ <- check(x5.TrustAnchors.of(Nil) == Left(Malformed), "an empty list is Malformed, not a raise")
      _ <- check(x5.TrustAnchors.of(List(cert)).map(_.anchors) == Right(List(cert)), "a non-empty list is accepted")
      pem = PEM.encode(PEM.Block.Certificate(IArray.from(root.der)))
      loaded = x5.Certificate.chain(pem).flatMap(x5.TrustAnchors.of).map(_.anchors.length)
      _ <- check(loaded == Right(1), s"the configuration flow composes in one vocabulary, got $loaded")
    yield ()
  }
end X509StrictnessSuite
