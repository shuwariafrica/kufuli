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

import boilerplate.effect.*
import cats.effect.IO
import cats.syntax.all.*

import kufuli.*
import kufuli.tests.support.*
import kufuli.tests.x509fixtures.*
import kufuli.x509 as x5

class X509HardeningSuite extends munit.CatsEffectSuite:

  private def permit(bases: String*): Array[Byte] = constraints(bases.map(dnsName).toList, Nil)

  private def verify(chain: List[Issued], anchor: Issued, host: String): IO[Either[x5.PathInvalid, x5.VerifiedPath]] =
    for
      certs <- chain.traverse(i => parsed(i.der))
      root <- parsed(anchor.der)
      id <- serverId(host)
      result <- x5.CertPath.verify(certs, x5.TrustAnchors(root), at, id).either
    yield result

  private def indexOf(haystack: Array[Byte], needle: Array[Byte]): Int =
    (0 to haystack.length - needle.length).find(i => needle.indices.forall(j => haystack(i + j) == needle(j))).getOrElse(-1)

  test("an unrecognised CRITICAL extension is rejected; the same extension non-critical is not") {
    val policy = seq(seq(oid(Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0d, 0x01))))
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      plain <- issuedBy(root, 2, "leaf", List(endEntity, san("example.com")))
      unknown <- issuedBy(root, 3, "leaf", List(endEntity, san("example.com"), ext(oidCertificatePolicies, true, policy)))
      tolerable <- issuedBy(root, 4, "leaf", List(endEntity, san("example.com"), ext(oidCertificatePolicies, false, policy)))
      ok <- verify(List(plain), root, "example.com")
      _ <- check(ok.isRight, s"a chain with no unknown critical extension validates, got $ok")
      cp <- verify(List(unknown), root, "example.com")
      _ <- check(cp == Left(x5.PathInvalid.ConstraintViolated), s"critical certificatePolicies -> ConstraintViolated, got $cp")
      lenient <- verify(List(tolerable), root, "example.com")
      _ <- check(lenient.isRight, s"non-critical certificatePolicies is ignorable, got $lenient")
      rootNc <- selfSigned("Root", List(caTrue, certSign, permit("corp.example")))
      inside <- issuedBy(rootNc, 5, "leaf", List(endEntity, san("host.corp.example")))
      recognised <- verify(List(inside), rootNc, "host.corp.example")
      _ <- check(recognised.isRight, s"a critical nameConstraints extension is now processed, got $recognised")
    yield ()
    end for
  }

  test("name constraints are processed, not merely recognised, and only on a CA") {
    for
      rootNc <- selfSigned("Root", List(caTrue, certSign, permit("corp.example")))
      inside <- issuedBy(rootNc, 2, "leaf", List(endEntity, san("host.corp.example")))
      outside <- issuedBy(rootNc, 3, "leaf", List(endEntity, san("host.other.example")))
      ok <- verify(List(inside), rootNc, "host.corp.example")
      _ <- check(ok.isRight, s"a name inside the anchor's permitted subtree validates, got $ok")
      no <- verify(List(outside), rootNc, "host.other.example")
      _ <- check(no == Left(x5.PathInvalid.NameConstraintViolated), s"a name outside it -> NameConstraintViolated, got $no")
      root <- selfSigned("Root", List(caTrue, certSign))
      onLeaf <- issuedBy(root, 4, "leaf", List(endEntity, san("example.com"), permit("example.com")))
      placed <- verify(List(onLeaf), root, "example.com")
      _ <- check(placed == Left(x5.PathInvalid.ConstraintViolated), s"nameConstraints on an end entity -> ConstraintViolated, got $placed")
    yield ()
    end for
  }

  test("a trust anchor is qualified rather than validated: no EKU gate, basic constraints only when present") {
    for
      // No extensions at all, so anchor qualification has neither basicConstraints nor keyUsage to
      // read and must fall back on tolerating both.
      bare <- selfSigned("Bare Root", Nil)
      leaf <- issuedBy(bare, 2, "leaf", List(endEntity, san("example.com"), eku(serverAuth)))
      ok <- verify(List(leaf), bare, "example.com")
      _ <- check(ok.isRight, s"an extension-less anchor is a real anchor, got $ok")
      clientRoot <- selfSigned("Client Root", List(caTrue, certSign, eku(clientAuth)))
      under <- issuedBy(clientRoot, 3, "leaf", List(endEntity, san("example.com"), eku(serverAuth)))
      unGated <- verify(List(under), clientRoot, "example.com")
      _ <- check(unGated.isRight, s"the anchor's own EKU does not gate the path, got $unGated")
      notCa <- selfSigned("Not A CA", List(endEntity, certSign))
      issued <- issuedBy(notCa, 4, "leaf", List(endEntity, san("example.com")))
      refused <- verify(List(issued), notCa, "example.com")
      _ <- check(refused == Left(x5.PathInvalid.ConstraintViolated), s"an anchor declaring cA=FALSE cannot issue, got $refused")
      // The placement rule for name constraints governs the path, not the anchor: an anchor that
      // declares no basic constraints is tolerated, so one carrying constraints is too.
      undeclared <- selfSigned("Undeclared Root", List(certSign, permit("corp.example")))
      beneath <- issuedBy(undeclared, 5, "leaf", List(endEntity, san("host.corp.example")))
      seeded <- verify(List(beneath), undeclared, "host.corp.example")
      _ <- check(seeded.isRight, s"a constrained anchor without basicConstraints still seeds, got $seeded")
    yield ()
    end for
  }

  test("a CA whose KeyUsage withholds keyCertSign cannot issue") {
    for
      withheld <- selfSigned("Withholding Root", List(caTrue, signOnly))
      leaf <- issuedBy(withheld, 2, "leaf", List(endEntity, san("example.com")))
      no <- verify(List(leaf), withheld, "example.com")
      _ <- check(no == Left(x5.PathInvalid.ConstraintViolated), s"no keyCertSign -> ConstraintViolated, got $no")
      granted <- selfSigned("Signing Root", List(caTrue, certSign))
      other <- issuedBy(granted, 2, "leaf", List(endEntity, san("example.com")))
      yes <- verify(List(other), granted, "example.com")
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
      nested <- verify(List(leaf, clientOnly), root, "example.com")
      _ <- check(nested == Left(x5.PathInvalid.ConstraintViolated), s"clientAuth intermediate -> ConstraintViolated, got $nested")
      serverOk <- issuedBy(root, 4, "Server CA", List(caTrue, certSign, eku(serverAuth)))
      under <- issuedBy(serverOk, 5, "leaf", List(endEntity, san("example.com"), eku(serverAuth)))
      ok <- verify(List(under, serverOk), root, "example.com")
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
      folded <- verify(List(leaf), root, "k.EXAMPLE.com")
      _ <- check(folded.isRight, s"ASCII case folds, got $folded")
      // U+212A KELVIN SIGN lower-cases to ASCII 'k' under Unicode folding, in every locale; the LDH
      // definition keeps it out of an identity before any comparison happens.
      kelvin = x5.ServerId.of(s"${0x212a.toChar}.example.com")
      _ <- check(kelvin == Left(Malformed), s"U+212A is not an LDH label, got $kelvin")
      broad <- issuedBy(root, 3, "leaf", List(endEntity, san("*.com")))
      any <- verify(List(broad), root, "example.com")
      _ <- check(any == Left(x5.PathInvalid.NameMismatch), s"`*.com` must match nothing, got $any")
      narrow <- issuedBy(root, 4, "leaf", List(endEntity, san("*.example.com")))
      sub <- verify(List(narrow), root, "foo.example.com")
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
      host <- serverId("example.com")
      result <- x5.CertPath.verify(List(cert), x5.TrustAnchors(first, second), at, host).either
      _ <- check(result.isRight, s"the second same-name anchor must be tried, got $result")
    yield ()
  }

  test("the path walk spends its budget over the whole enumeration, not only over the candidates it finds") {
    for
      unrelated <- selfSigned("Real Root", List(caTrue, certSign))
      head <- selfSigned("Filler CA", List(caTrue, certSign))
      leaf <- issuedBy(head, 2, "leaf", List(endEntity, san("example.com")))
      // Every filler carries the leaf's issuer DN as its own subject and none reaches the anchor, so
      // the walk produces no candidate at all - a ceiling on candidates never fills - while the
      // orderings of fifteen certificates are more than any machine enumerates.
      fillers <- (1 to 14).toList.traverse(_ => selfSigned("Filler CA", List(caTrue, certSign)))
      result <- verify(leaf :: head :: fillers, unrelated, "example.com")
      _ <- check(result == Left(x5.PathInvalid.LimitExceeded), s"the walk reports its own bound rather than running on, got $result")
    yield ()
    end for
  }

  test("the budget does not cut a real chain short: same-DN decoys are walked past to the issuer that signed") {
    for
      root <- selfSigned("Root", List(caTrue, certSign))
      decoys <- (3 to 8).toList.traverse(i => issuedBy(root, i, "Sub CA", List(caTrue, certSign)))
      real <- issuedBy(root, 2, "Sub CA", List(caTrue, certSign))
      leaf <- issuedBy(real, 9, "leaf", List(endEntity, san("example.com")))
      result <- verify(leaf :: (decoys :+ real), root, "example.com")
      _ <- check(result.isRight, s"the issuer that signed the leaf is reached past six same-DN decoys, got $result")
    yield ()
  }

  test("a certificate whose subject key kufuli cannot import still parses and says so") {
    // A DSA SubjectPublicKeyInfo (1.2.840.10040.4.1): well-formed X.509, outside kufuli's families.
    val dsaSpki =
      seq(seq(oid(Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x01))), tlv(0x03, Array[Byte](0) ++ Array.fill[Byte](20)(7)))
    for
      kp <- Ed25519.generate.absolve
      der <- signed(tbsOf(9, "unsupported", "unsupported", dsaSpki, notBefore, notAfter, Nil), kp.privateKey)
      cert <- IO.fromEither(x5.Certificate.fromDer(der).left.map(e => new AssertionError(s"parse: $e")))
      unsupported <- cert.publicKey.either
      _ <- check(unsupported == Left(InvalidKey.Unsupported), s"unsupported SPKI reports itself, got $unsupported")
      _ <- check(cert.subjectAltDns.isEmpty && cert.der.length == der.length, "the certificate stays inspectable")
      mine <- selfSigned("ok.example", List(endEntity))
      good <- IO.fromEither(x5.Certificate.fromDer(mine.der).left.map(e => new AssertionError(s"parse: $e")))
      supported <- good.publicKey.either
      _ <- check(supported.isRight, s"a supported SPKI yields its key, got $supported")
    yield ()
    end for
  }
end X509HardeningSuite
