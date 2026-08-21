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

import cats.effect.IO
import cats.syntax.all.*

import kufuli.tests.support.*
import kufuli.tests.x509fixtures.*
import kufuli.x509 as x5

class X509ConstraintsSuite extends munit.CatsEffectSuite:

  private def verify(chain: List[Array[Byte]], anchor: Array[Byte], host: String): IO[Either[x5.PathInvalid, x5.VerifiedPath]] =
    for
      certs <- chain.traverse(parsed)
      root <- parsed(anchor)
      id <- serverId(host)
      result <- x5.CertPath.verify(certs, x5.TrustAnchors(root), at, id).either.absolve
    yield result

  private def permitted(bases: Array[Byte]*): Array[Byte] = constraints(bases.toList, Nil)
  private def excluded(bases: Array[Byte]*): Array[Byte] = constraints(Nil, bases.toList)
  private def ipRange(octets: Int*): Array[Byte] = ipName(octets.map(_.toByte).toArray)

  private def violated(result: Either[x5.PathInvalid, x5.VerifiedPath]): Boolean =
    result == Left(x5.PathInvalid.NameConstraintViolated)

  // The anchor-borne constraint has exactly one external case in one corpus, so this family is
  // kufuli's own evidence that RFC 5937 seeding is live for each processed form.
  test("anchor family: a permitted dNSName on the anchor admits names beneath it and no others") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("corp.example"))))
      inside <- issuedBy(root, 2, "leaf", List(endEntity, san("host.corp.example")))
      outside <- issuedBy(root, 3, "leaf", List(endEntity, san("host.other.example")))
      ok <- verify(List(inside.der), root.der, "host.corp.example")
      _ <- check(ok.isRight, s"a name within the anchor's permitted subtree validates, got $ok")
      no <- verify(List(outside.der), root.der, "host.other.example")
      _ <- check(violated(no), s"a name outside it -> NameConstraintViolated, got $no")
    yield ()
  }

  test("anchor family: an excluded iPAddress subtree on the anchor rejects addresses inside its mask") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, excluded(ipRange(10, 0, 0, 0, 255, 0, 0, 0))))
      privateIp <- issuedBy(root, 2, "leaf", List(endEntity, sanOf(ipName(Array[Byte](10, 1, 2, 3)))))
      publicIp <- issuedBy(root, 3, "leaf", List(endEntity, sanOf(ipName(Array[Byte](192.toByte, 0, 2, 1)))))
      no <- verify(List(privateIp.der), root.der, "10.1.2.3")
      _ <- check(violated(no), s"an address inside the excluded mask -> NameConstraintViolated, got $no")
      ok <- verify(List(publicIp.der), root.der, "192.0.2.1")
      _ <- check(ok.isRight, s"an address outside it validates, got $ok")
    yield ()
  }

  test("anchor family: a permitted directoryName on the anchor is an RDN-prefix over the subject DN") {
    val org = seq(rdn(oidOrganisation, 0x13, "Kufuli Test"))
    val inOrg = seq(rdn(oidOrganisation, 0x13, "Kufuli Test"), rdn(oidCommonName, 0x0c, "leaf"))
    val elsewhere = seq(rdn(oidOrganisation, 0x13, "Other Org"), rdn(oidCommonName, 0x0c, "leaf"))
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(dirName(org))))
      inside <- leafNamed(root, 2, inOrg, List(endEntity, san("host.example")))
      outside <- leafNamed(root, 3, elsewhere, List(endEntity, san("host.example")))
      ok <- verify(List(inside), root.der, "host.example")
      _ <- check(ok.isRight, s"a subject DN under the permitted prefix validates, got $ok")
      no <- verify(List(outside), root.der, "host.example")
      _ <- check(violated(no), s"a subject DN outside it -> NameConstraintViolated, got $no")
    yield ()
  }

  test("anchor family: an anchor and an intermediate both narrow, and a name must satisfy both") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("corp.example"))))
      ica <- issuedBy(root, 2, "Engineering CA", List(caTrue, certSign, permitted(dnsName("eng.corp.example"))))
      both <- issuedBy(ica, 3, "leaf", List(endEntity, san("host.eng.corp.example")))
      anchorOnly <- issuedBy(ica, 4, "leaf", List(endEntity, san("host.ops.corp.example")))
      ok <- verify(List(both.der, ica.der), root.der, "host.eng.corp.example")
      _ <- check(ok.isRight, s"a name within both permitted sets validates, got $ok")
      no <- verify(List(anchorOnly.der, ica.der), root.der, "host.ops.corp.example")
      _ <- check(violated(no), s"a name within the anchor's set only -> NameConstraintViolated, got $no")
    yield ()
  }

  test("an excluded subtree beats a permitted one that also matches") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, constraints(List(dnsName("example.com")), List(dnsName("bad.example.com")))))
      allowed <- issuedBy(root, 2, "leaf", List(endEntity, san("good.example.com")))
      denied <- issuedBy(root, 3, "leaf", List(endEntity, san("bad.example.com")))
      ok <- verify(List(allowed.der), root.der, "good.example.com")
      _ <- check(ok.isRight, s"permitted and not excluded validates, got $ok")
      no <- verify(List(denied.der), root.der, "bad.example.com")
      _ <- check(violated(no), s"excluded beats permitted, got $no")
    yield ()
  }

  test("a wildcard SAN is admitted by a permitted base only when every name it expands to is") {
    for
      // RUSTSEC-2026-0099: `*.example.com` can expand to reject.example.com, which the base excludes.
      narrow <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("accept.example.com"))))
      wide <- issuedBy(narrow, 2, "leaf", List(endEntity, san("*.example.com")))
      no <- verify(List(wide.der), narrow.der, "accept.example.com")
      _ <- check(violated(no), s"a wildcard reaching outside the base -> NameConstraintViolated, got $no")
      broad <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("example.com"))))
      under <- issuedBy(broad, 2, "leaf", List(endEntity, san("*.corp.example.com")))
      ok <- verify(List(under.der), broad.der, "host.corp.example.com")
      _ <- check(ok.isRight, s"a wildcard wholly inside the base validates, got $ok")
    yield ()
  }

  test("a wildcard SAN violates an excluded base it can expand onto, and no other") {
    for
      // Go CVE-2025-61727: excluded foo.example.com must reject the SAN `*.example.com`.
      root <- selfSigned("Anchor", List(caTrue, certSign, excluded(dnsName("foo.example.com"))))
      wild <- issuedBy(root, 2, "leaf", List(endEntity, san("*.example.com")))
      no <- verify(List(wild.der), root.der, "ok.example.com")
      _ <- check(violated(no), s"an excluded name one label below the wildcard parent -> violated, got $no")
      // Go #76935: the same fix must not make a single-label excluded base reject every wildcard.
      tld <- selfSigned("Anchor", List(caTrue, certSign, excluded(dnsName("com"))))
      other <- issuedBy(tld, 2, "leaf", List(endEntity, san("*.example.org")))
      ok <- verify(List(other.der), tld.der, "host.example.org")
      _ <- check(ok.isRight, s"an unrelated single-label excluded base rejects no wildcard, got $ok")
      under <- issuedBy(tld, 3, "leaf", List(endEntity, san("*.example.com")))
      inside <- verify(List(under.der), tld.der, "host.example.com")
      _ <- check(violated(inside), s"a wildcard whose parent is under the excluded base -> violated, got $inside")
    yield ()
  }

  test("the reference identity runs the same walk as the SANs") {
    for
      // pyca CVE-2026-34073's shape: a wildcard SAN inside the permitted subtree whose matching
      // peer name is excluded. kufuli rejects it twice over - the wildcard rule catches the SAN,
      // and the identity is put through the state as well.
      root <- selfSigned("Anchor", List(caTrue, certSign, constraints(List(dnsName("example.com")), List(dnsName("bar.example.com")))))
      wild <- issuedBy(root, 2, "leaf", List(endEntity, san("*.example.com")))
      no <- verify(List(wild.der), root.der, "bar.example.com")
      _ <- check(violated(no), s"the excluded peer name is rejected, got $no")
      plain <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("example.com"))))
      leaf <- issuedBy(plain, 2, "leaf", List(endEntity, san("*.example.com")))
      ok <- verify(List(leaf.der), plain.der, "ok.example.com")
      _ <- check(ok.isRight, s"a peer name inside the permitted subtree validates, got $ok")
    yield ()
  }

  test("a zero-length dNSName base denies every name in excludedSubtrees and widens nothing in permitted") {
    for
      deny <- selfSigned("Anchor", List(caTrue, certSign, excluded(dnsName(""))))
      any <- issuedBy(deny, 2, "leaf", List(endEntity, san("host.example.com")))
      no <- verify(List(any.der), deny.der, "host.example.com")
      _ <- check(violated(no), s"a zero-length excluded base denies every dNSName, got $no")
      allow <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName(""))))
      free <- issuedBy(allow, 2, "leaf", List(endEntity, san("host.example.com")))
      ok <- verify(List(free.der), allow.der, "host.example.com")
      _ <- check(ok.isRight, s"a zero-length permitted base admits every dNSName, got $ok")
    yield ()
  }

  test("a constraint on a form with no matching rule rejects that form and is vacuous without it") {
    val spiffe = "spiffe://example.com/workload"
    for
      uriNc <- selfSigned("Anchor", List(caTrue, certSign, permitted(uriName("https://example.com"))))
      withUri <- issuedBy(uriNc, 2, "leaf", List(endEntity, sanOf(dnsName("host.example.com"), uriName(spiffe))))
      withoutUri <- issuedBy(uriNc, 3, "leaf", List(endEntity, san("host.example.com")))
      no <- verify(List(withUri.der), uriNc.der, "host.example.com")
      _ <- check(violated(no), s"a URI constraint plus a URI SAN -> NameConstraintViolated, got $no")
      ok <- verify(List(withoutUri.der), uriNc.der, "host.example.com")
      _ <- check(ok.isRight, s"the same constraint with no URI present is vacuous, got $ok")
      other = otherName(seq(oid(serverAuth), tlv(0xa0, tlv(0x0c, ascii("x")))))
      otherNc <- selfSigned("Anchor", List(caTrue, certSign, excluded(other)))
      withOther <- issuedBy(otherNc, 4, "leaf", List(endEntity, sanOf(dnsName("host.example.com"), other)))
      plainLeaf <- issuedBy(otherNc, 5, "leaf", List(endEntity, san("host.example.com")))
      blocked <- verify(List(withOther.der), otherNc.der, "host.example.com")
      _ <- check(violated(blocked), s"an otherName constraint plus an otherName SAN -> NameConstraintViolated, got $blocked")
      clear <- verify(List(plainLeaf.der), otherNc.der, "host.example.com")
      _ <- check(clear.isRight, s"an otherName constraint with no otherName present is vacuous, got $clear")
    yield ()
    end for
  }

  test("rfc822Name constraints match by mailbox, domain and host, and fall back to the subject DN") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(emailName(".corp.example"))))
      inDomain <- issuedBy(root, 2, "leaf", List(endEntity, sanOf(dnsName("host.example"), emailName("ops@eng.corp.example"))))
      atApex <- issuedBy(root, 3, "leaf", List(endEntity, sanOf(dnsName("host.example"), emailName("ops@corp.example"))))
      ok <- verify(List(inDomain.der), root.der, "host.example")
      _ <- check(ok.isRight, s"a mailbox in a subdomain of the base validates, got $ok")
      no <- verify(List(atApex.der), root.der, "host.example")
      _ <- check(violated(no), s"a leading-dot base excludes the apex itself, got $no")
      host <- selfSigned("Anchor", List(caTrue, certSign, permitted(emailName("corp.example"))))
      exact <- issuedBy(host, 4, "leaf", List(endEntity, sanOf(dnsName("host.example"), emailName("ops@corp.example"))))
      sub <- issuedBy(host, 5, "leaf", List(endEntity, sanOf(dnsName("host.example"), emailName("ops@eng.corp.example"))))
      hostOk <- verify(List(exact.der), host.der, "host.example")
      _ <- check(hostOk.isRight, s"a host base matches the host exactly, got $hostOk")
      hostNo <- verify(List(sub.der), host.der, "host.example")
      _ <- check(violated(hostNo), s"a host base does not match a subdomain, got $hostNo")
      mailbox <- selfSigned("Anchor", List(caTrue, certSign, permitted(emailName("Ops@corp.example"))))
      cased <- issuedBy(mailbox, 6, "leaf", List(endEntity, sanOf(dnsName("host.example"), emailName("ops@corp.example"))))
      localCase <- verify(List(cased.der), mailbox.der, "host.example")
      _ <- check(violated(localCase), s"the local part compares case-sensitively, got $localCase")
    yield ()
    end for
  }

  test("a certificate with no SAN extension has its subject emailAddress attributes checked") {
    val allowed = seq(rdn(oidEmailAddress, 0x16, "ops@eng.corp.example"), rdn(oidCommonName, 0x0c, "leaf"))
    val denied = seq(rdn(oidEmailAddress, 0x16, "ops@other.example"), rdn(oidCommonName, 0x0c, "leaf"))
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(emailName(".corp.example"))))
      anchor <- parsed(root.der).map(x5.TrustAnchors(_))
      good <- leafNamed(root, 2, allowed, List(endEntity)).flatMap(parsed)
      bad <- leafNamed(root, 3, denied, List(endEntity)).flatMap(parsed)
      inside <- x5.CertPath.verifyClient(List(good), anchor, at).either.absolve
      _ <- check(inside.isRight, s"an emailAddress inside the permitted domain validates, got $inside")
      outside <- x5.CertPath.verifyClient(List(bad), anchor, at).either.absolve
      _ <- check(violated(outside), s"an emailAddress outside it -> NameConstraintViolated, got $outside")
    yield ()
  }

  test("a subject emailAddress carrying more than one `@` is rejected rather than matched past the separator") {
    // Matching splits at the first `@`, so this value's domain reads `corp.example@x` and clears an
    // exclusion on `corp.example` while a reader taking the first mailbox sees the excluded host.
    val evasive = seq(rdn(oidEmailAddress, 0x16, "ops@corp.example@x"), rdn(oidCommonName, 0x0c, "leaf"))
    val plain = seq(rdn(oidEmailAddress, 0x16, "ops@elsewhere.example"), rdn(oidCommonName, 0x0c, "leaf"))
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, excluded(emailName("corp.example"))))
      anchor <- parsed(root.der).map(x5.TrustAnchors(_))
      evader <- leafNamed(root, 2, evasive, List(endEntity)).flatMap(parsed)
      outside <- leafNamed(root, 3, plain, List(endEntity)).flatMap(parsed)
      slipped <- x5.CertPath.verifyClient(List(evader), anchor, at).either.absolve
      _ <- check(violated(slipped), s"a multi-`@` emailAddress -> NameConstraintViolated, got $slipped")
      // The same exclusion stays vacuous for a well-formed address outside it, so the gate has not
      // become an unconditional rejection of the fallback.
      clean <- x5.CertPath.verifyClient(List(outside), anchor, at).either.absolve
      _ <- check(clean.isRight, s"a well-formed address outside the excluded subtree validates, got $clean")
    yield ()
    end for
  }

  test("a subject emailAddress that is not IA5 is dropped rather than decoded into a mailbox") {
    // IA5String is 7-bit. Decoded as US-ASCII a high byte becomes a replacement character, which
    // would make this value a mailbox outside the permitted subtree and fail the chain; dropping it
    // leaves the fallback with nothing to check.
    val highByte = tlv(0x31, seq(oid(oidEmailAddress), tlv(0x16, ascii("ops@") ++ Array[Byte](0xe9.toByte) ++ ascii(".example"))))
    val outside = seq(rdn(oidEmailAddress, 0x16, "ops@other.example"), rdn(oidCommonName, 0x0c, "leaf"))
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(emailName(".corp.example"))))
      anchor <- parsed(root.der).map(x5.TrustAnchors(_))
      dropped <- leafNamed(root, 2, seq(highByte, rdn(oidCommonName, 0x0c, "leaf")), List(endEntity)).flatMap(parsed)
      decoded <- leafNamed(root, 3, outside, List(endEntity)).flatMap(parsed)
      ignored <- x5.CertPath.verifyClient(List(dropped), anchor, at).either.absolve
      _ <- check(ignored.isRight, s"a non-IA5 attribute is no mailbox, so the fallback has nothing to match, got $ignored")
      checked <- x5.CertPath.verifyClient(List(decoded), anchor, at).either.absolve
      _ <- check(violated(checked), s"while an IA5 address outside the subtree is checked and fails, got $checked")
    yield ()
  }

  test("a self-issued certificate below the leaf has its own names skipped, and a re-keyed peer does not") {
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, permitted(dnsName("corp.example"))))
      // Subject equals issuer, so this is the anchor re-keyed rather than a new entity; its own SAN
      // lies outside the permitted subtree and RFC 5280 section 6.1.3 must not check it.
      rollover <- issuedBy(root, 2, "Anchor", List(caTrue, certSign, san("rollover.other.example")))
      leaf <- issuedBy(rollover, 3, "leaf", List(endEntity, san("host.corp.example")))
      ok <- verify(List(leaf.der, rollover.der), root.der, "host.corp.example")
      _ <- check(ok.isRight, s"a self-issued intermediate's own names are skipped, got $ok")
      // The same SAN on an intermediate that is a distinct entity is checked, and fails.
      distinct <- issuedBy(root, 4, "Department CA", List(caTrue, certSign, san("department.other.example")))
      under <- issuedBy(distinct, 5, "leaf", List(endEntity, san("host.corp.example")))
      no <- verify(List(under.der, distinct.der), root.der, "host.corp.example")
      _ <- check(violated(no), s"a non-self-issued intermediate's names are checked, got $no")
    yield ()
  }

  test("the names-by-subtrees product is bounded") {
    val names = (0 until 4096).map(i => dnsName(s"a$i.x")).toList
    val bases = dnsName("x") :: (1 until 256).map(i => dnsName(s"b$i.y")).toList
    for
      root <- selfSigned("Anchor", List(caTrue, certSign, constraints(bases, Nil)))
      leaf <- issuedBy(root, 2, "leaf", List(endEntity, ext(oidSan, false, seq(names*))))
      result <- verify(List(leaf.der), root.der, "a0.x")
      _ <- check(result == Left(x5.PathInvalid.LimitExceeded), s"4096 names over 256 subtrees -> LimitExceeded, got $result")
    yield ()
  }
end X509ConstraintsSuite
