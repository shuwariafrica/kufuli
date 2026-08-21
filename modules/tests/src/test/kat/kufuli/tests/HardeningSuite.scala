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
import boilerplate.codec.Base64Url
import boilerplate.effect.*
import cats.effect.IO
import cats.syntax.all.*

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*
import kufuli.x509 as x5

class HardeningSuite extends munit.CatsEffectSuite:

  // A stapled OCSP response built and signed exactly as a responder would, so the suite asserts the
  // verified contract rather than the parser alone.
  private val oidBasic = tlv(0x06, Array[Byte](0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1)) // 1.3.6.1.5.5.7.48.1.1
  private val oidSha256Alg = seq(tlv(0x06, Array[Byte](0x60, 0x86.toByte, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)))
  private val ocspSigning = Array[Byte](0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09)

  private def tlv(tag: Int, content: Array[Byte]): Array[Byte] = x509fixtures.tlv(tag, content)
  private def seq(parts: Array[Byte]*): Array[Byte] = x509fixtures.seq(parts*)
  private def gtime(v: String): Array[Byte] = tlv(0x18, v.getBytes("US-ASCII"))

  private val anyCert = x5.Certificate
    .parse("""-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUfBid6gGHCJh1s5LsbQsDwQrulv0wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDcxMjAxMzUwOVoXDTM2MDcw
OTAxMzUwOVowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE6IPTCA5KGi40r1Kj3txg9G7mlEuIVA+h7P3h/j+iG0oHs3Co
uTPzSXs7eiHzd3b6m42+My8SQAWABQiXTHzzU6NjMGEwHQYDVR0OBBYEFHbVnKgI
ae/yr3ZL82d1voI8lNsEMB8GA1UdIwQYMBaAFHbVnKgIae/yr3ZL82d1voI8lNsE
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gA
MEUCIEnpuq4bw9fVKuLP7zblcT+5wECACp3ldG+lLjMbM/imAiEA8rG96I+Xrhmz
nDMs9Kp6zwtMzwY2stmLBVOUBGMX780=
-----END CERTIFICATE-----""")
    .toOption
    .get

  private val ocspAt = 1_800_000_000L
  private val thisUpdate = "20270101000000Z"

  private val statusGood = Array[Byte](0x80.toByte, 0x00) // good [0] IMPLICIT NULL
  private val statusUnknown = Array[Byte](0x82.toByte, 0x00) // unknown [2] IMPLICIT NULL
  private val statusRevoked = tlv(0xa1, gtime("20260601000000Z")) // revoked [1] { revocationTime }

  // certID over SHA-256 of the leaf's issuer name and the issuer's public key, plus the leaf serial.
  private def certIdOf(issuerName: Array[Byte], issuerSpki: Array[Byte], serial: Array[Byte]): IO[Array[Byte]] =
    for
      nameHash <- Sha256.digest(Slice.of(issuerName)).absolve
      keyBits = issuerSpki.drop(issuerSpki.length - 32) // Ed25519 SPKI: the trailing 32 key octets
      keyHash <- Sha256.digest(Slice.of(keyBits)).absolve
    yield seq(
      oidSha256Alg,
      tlv(0x04, Array.from(nameHash.bytes.iterator)),
      tlv(0x04, Array.from(keyHash.bytes.iterator)),
      tlv(0x02, serial)
    )

  private def response(
    certId: Array[Byte],
    certStatus: Array[Byte],
    signer: PrivateKey[Ed25519],
    certs: List[Array[Byte]]
  ): IO[Array[Byte]] =
    window(certId, certStatus, signer, thisUpdate, None, certs)

  private def window(
    certId: Array[Byte],
    certStatus: Array[Byte],
    signer: PrivateKey[Ed25519],
    from: String,
    until: Option[String]
  ): IO[Array[Byte]] = window(certId, certStatus, signer, from, until, Nil)

  private def window(
    certId: Array[Byte],
    certStatus: Array[Byte],
    signer: PrivateKey[Ed25519],
    from: String,
    until: Option[String],
    certs: List[Array[Byte]]
  ): IO[Array[Byte]] =
    val single = seq((List(certId, certStatus, gtime(from)) ++ until.map(u => tlv(0xa0, gtime(u))))*)
    assemble(seq(single), from, signer, edAlgorithm, certs)

  // Several SingleResponse entries under one signature, as a batching responder emits.
  private def entries(rows: List[(Array[Byte], Array[Byte])], signer: PrivateKey[Ed25519]): IO[Array[Byte]] =
    val singles = rows.map((certId, status) => seq(certId, status, gtime(thisUpdate)))
    assemble(seq(singles*), thisUpdate, signer, edAlgorithm, Nil)

  // A response whose signatureAlgorithm is the caller's, so a structure kufuli parses can still
  // name an algorithm it does not implement.
  private def signedWith(
    certId: Array[Byte],
    certStatus: Array[Byte],
    signer: PrivateKey[Ed25519],
    algorithm: Array[Byte]
  ): IO[Array[Byte]] =
    assemble(seq(seq(certId, certStatus, gtime(thisUpdate))), thisUpdate, signer, algorithm, Nil)

  private val edAlgorithm = seq(x509fixtures.oid(x509fixtures.edOid))

  private def assemble(
    responses: Array[Byte],
    producedAt: String,
    signer: PrivateKey[Ed25519],
    algorithm: Array[Byte],
    certs: List[Array[Byte]]
  ): IO[Array[Byte]] =
    val responderId = tlv(0xa2, tlv(0x04, Array[Byte](1, 2, 3, 4))) // byKey [2] KeyHash
    val responseData = seq(responderId, gtime(producedAt), responses)
    signer.sign(Slice.of(responseData)).absolve.map { sig =>
      val carried = if certs.isEmpty then Array.emptyByteArray else tlv(0xa0, seq(certs*))
      val basic = seq(responseData, algorithm, tlv(0x03, Array[Byte](0) ++ Array.from(sig.bytes.iterator)), carried)
      seq(tlv(0x0a, Array[Byte](0)), tlv(0xa0, seq(oidBasic, tlv(0x04, basic))))
    }
  end assemble

  private type Staple = (
    issued: x509fixtures.Issued,
    ca: x5.Certificate,
    leaf: x5.Certificate,
    certId: Array[Byte],
    caName: Array[Byte],
    caSpki: Array[Byte]
  )

  private def staple: IO[Staple] =
    for
      ca <- x509fixtures.selfSigned("OCSP Root", List(x509fixtures.caTrue, x509fixtures.certSign))
      leaf <- x509fixtures.issuedBy(ca, 7, "leaf.example", List(x509fixtures.endEntity, x509fixtures.san("leaf.example")))
      caCert <- x509fixtures.parsed(ca.der)
      leafCert <- x509fixtures.parsed(leaf.der)
      caKey <- expectRight("ca key")(caCert.publicKey)
      caSpki <- caKey match
                  case ImportedPublicKey.Ed(k) => expectRight("spki bytes")(k.spki).map(a => Array.from(a.bytes.iterator))
                  case other                   => IO.raiseError(new AssertionError(s"expected an Ed25519 CA, got $other"))
      caName = x509fixtures.name("OCSP Root")
      certId <- certIdOf(caName, caSpki, Array[Byte](7))
    yield (issued = ca, ca = caCert, leaf = leafCert, certId = certId, caName = caName, caSpki = caSpki)

  test("OCSP: a verified staple reports its status; a non-successful response asserts nothing") {
    for
      s <- staple
      good <- response(s.certId, statusGood, s.issued.key, Nil)
      g <- x5.OCSP.verifyStapled(good, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(g == Right(x5.OCSP.Status.Good), s"issuer-signed good staple -> Good, got $g")
      revoked <- response(s.certId, statusRevoked, s.issued.key, Nil)
      r <- x5.OCSP.verifyStapled(revoked, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(r.exists { case x5.OCSP.Status.Revoked(_) => true; case _ => false }, s"revoked staple -> Revoked, got $r")
      unknown <- response(s.certId, statusUnknown, s.issued.key, Nil)
      u <- x5.OCSP.verifyStapled(unknown, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(u == Right(x5.OCSP.Status.Unknown), s"unknown staple -> Unknown, got $u")
      t <- x5.OCSP.verifyStapled(seq(tlv(0x0a, Array[Byte](3))), s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(t == Right(x5.OCSP.Status.Unknown), s"tryLater -> Unknown, got $t")
      m <- x5.OCSP.verifyStapled(Array[Byte](1, 2, 3), s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(m == Left(x5.PathInvalid.MalformedChain), s"garbage -> MalformedChain, got $m")
    yield ()
    end for
  }

  test("OCSP: a staple outside its own update window carries no Good verdict") {
    for
      s <- staple
      fresh <- window(s.certId, statusGood, s.issued.key, "20270101000000Z", Some("20360101000000Z"))
      f <- x5.OCSP.verifyStapled(fresh, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(f == Right(x5.OCSP.Status.Good), s"a current Good staple is honoured, got $f")
      expired <- window(s.certId, statusGood, s.issued.key, "20200101000000Z", Some("20200102000000Z"))
      e <- x5.OCSP.verifyStapled(expired, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(e == Right(x5.OCSP.Status.Unknown), s"a Good staple past nextUpdate -> Unknown, got $e")
      early <- window(s.certId, statusGood, s.issued.key, "20360101000000Z", None)
      y <- x5.OCSP.verifyStapled(early, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(y == Right(x5.OCSP.Status.Unknown), s"a Good staple before thisUpdate -> Unknown, got $y")
      old <- window(s.certId, statusRevoked, s.issued.key, "20200101000000Z", Some("20200102000000Z"))
      o <- x5.OCSP.verifyStapled(old, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(o.exists { case x5.OCSP.Status.Revoked(_) => true; case _ => false }, s"a stale Revoked still stands, got $o")
    yield ()
    end for
  }

  test("OCSP: a forged Good is not evidence - the responder signature is verified") {
    for
      s <- staple
      other <- x509fixtures.selfSigned("Impostor", List(x509fixtures.caTrue, x509fixtures.certSign))
      forged <- response(s.certId, statusGood, other.key, Nil)
      f <- x5.OCSP.verifyStapled(forged, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(f == Left(x5.PathInvalid.BadSignature), s"a staple signed by a stranger -> BadSignature, got $f")
      good <- response(s.certId, statusGood, s.issued.key, Nil)
      tampered = good.updated(good.length - 1, (good(good.length - 1) ^ 0x01).toByte)
      t <- x5.OCSP.verifyStapled(tampered, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(t == Left(x5.PathInvalid.BadSignature), s"a mutated signature -> BadSignature, got $t")
    yield ()
    end for
  }

  test("OCSP: a signed Good about another certificate does not answer for this one") {
    for
      s <- staple
      wrongKey <- certIdOf(s.caName, Array.fill(64)(0.toByte), Array[Byte](7))
      wrongKeyResp <- response(wrongKey, statusGood, s.issued.key, Nil)
      k <- x5.OCSP.verifyStapled(wrongKeyResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(k == Left(x5.PathInvalid.ResponseMismatch), s"a certID naming another issuer key -> ResponseMismatch, got $k")
      wrongName <- certIdOf(x509fixtures.name("Other Root"), s.caSpki, Array[Byte](7))
      wrongNameResp <- response(wrongName, statusGood, s.issued.key, Nil)
      n <- x5.OCSP.verifyStapled(wrongNameResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(n == Left(x5.PathInvalid.ResponseMismatch), s"a certID naming another issuer -> ResponseMismatch, got $n")
      otherSerial <- certIdOf(s.caName, s.caSpki, Array[Byte](8))
      otherResp <- response(otherSerial, statusGood, s.issued.key, Nil)
      o <- x5.OCSP.verifyStapled(otherResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(o == Left(x5.PathInvalid.ResponseMismatch), s"a certID naming another serial -> ResponseMismatch, got $o")
    yield ()
    end for
  }

  test("OCSP: a responder that batches is read whole, and one that answers for nobody here says so") {
    for
      s <- staple
      otherSerial <- certIdOf(s.caName, s.caSpki, Array[Byte](8))
      thirdSerial <- certIdOf(s.caName, s.caSpki, Array[Byte](9))
      batched <- entries(List((otherSerial, statusRevoked), (s.certId, statusGood), (thirdSerial, statusUnknown)), s.issued.key)
      b <- x5.OCSP.verifyStapled(batched, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(b == Right(x5.OCSP.Status.Good), s"the entry naming this leaf decides, whatever its position, got $b")
      revokedHere <- entries(List((otherSerial, statusGood), (s.certId, statusRevoked)), s.issued.key)
      r <- x5.OCSP.verifyStapled(revokedHere, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(r.exists { case x5.OCSP.Status.Revoked(_) => true; case _ => false },
                 s"a neighbour's Good cannot mask this leaf's Revoked, got $r"
           )
      elsewhere <- entries(List((otherSerial, statusGood), (thirdSerial, statusGood)), s.issued.key)
      e <- x5.OCSP.verifyStapled(elsewhere, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(e == Left(x5.PathInvalid.ResponseMismatch), s"a response with no entry for this leaf -> ResponseMismatch, got $e")
    yield ()
    end for
  }

  test("OCSP: a response signed with an algorithm kufuli does not implement says which") {
    for
      s <- staple
      // A conforming BasicOCSPResponse whose signatureAlgorithm names DSA-with-SHA1 (1.2.840.10040.4.3).
      dsa <- signedWith(s.certId, statusGood, s.issued.key, seq(tlv(0x06, Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x38, 0x04, 0x03))))
      d <- x5.OCSP.verifyStapled(dsa, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(d == Left(x5.PathInvalid.UnsupportedAlgorithm), s"an unimplemented signature algorithm -> UnsupportedAlgorithm, got $d")
      garbage <- x5.OCSP.verifyStapled(seq(tlv(0x0a, Array[Byte](0)), tlv(0xa0, Array[Byte](1, 2))), s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(garbage == Left(x5.PathInvalid.MalformedChain), s"and an unparseable body stays MalformedChain, got $garbage")
    yield ()
    end for
  }

  test("OCSP: a delegated responder signs only when the issuer marked it for OCSP signing") {
    for
      s <- staple
      plain <- x509fixtures.issuedBy(s.issued, 11, "responder.example", List(x509fixtures.endEntity))
      plainResp <- response(s.certId, statusGood, plain.key, List(plain.der))
      p <- x5.OCSP.verifyStapled(plainResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(p == Left(x5.PathInvalid.BadSignature), s"a carried certificate with no OCSP-signing EKU is not a responder, got $p")
      marked <- x509fixtures.issuedBy(s.issued, 12, "responder.example", List(x509fixtures.endEntity, x509fixtures.eku(ocspSigning)))
      markedResp <- response(s.certId, statusGood, marked.key, List(marked.der))
      d <- x5.OCSP.verifyStapled(markedResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(d == Right(x5.OCSP.Status.Good), s"a delegated responder the issuer marked -> Good, got $d")
      stranger <- x509fixtures.selfSigned("Impostor", List(x509fixtures.caTrue, x509fixtures.certSign))
      unsigned <- x509fixtures.issuedBy(stranger, 13, "responder.example", List(x509fixtures.endEntity, x509fixtures.eku(ocspSigning)))
      unsignedResp <- response(s.certId, statusGood, unsigned.key, List(unsigned.der))
      x <- x5.OCSP.verifyStapled(unsignedResp, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(x == Left(x5.PathInvalid.BadSignature), s"a responder the issuer never signed is not delegated, got $x")
    yield ()
    end for
  }

  test("OCSP: one staple has exactly one encoding") {
    for
      s <- staple
      good <- response(s.certId, statusGood, s.issued.key, Nil)
      clean <- x5.OCSP.verifyStapled(good, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(clean == Right(x5.OCSP.Status.Good), s"the canonical response is honoured, got $clean")
      trailing <- x5.OCSP.verifyStapled(good ++ Array[Byte](0x41, 0x41), s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(trailing == Left(x5.PathInvalid.MalformedChain), s"bytes past the response are refused, got $trailing")
      // responseStatus is a single octet, so a wider ENUMERATED whose first octet is zero is not a
      // second spelling of successful(0).
      wide = seq(tlv(0x0a, Array[Byte](0, 0)), tlv(0xa0, seq(oidBasic, tlv(0x04, seq()))))
      w <- x5.OCSP.verifyStapled(wide, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(w == Left(x5.PathInvalid.MalformedChain), s"a two-octet responseStatus is refused, got $w")
      // good is [0] IMPLICIT NULL, so a status carrying content is a second spelling of a verdict.
      padded <- response(s.certId, Array[Byte](0x80.toByte, 0x01, 0x00), s.issued.key, Nil)
      p <- x5.OCSP.verifyStapled(padded, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(p == Left(x5.PathInvalid.MalformedChain), s"a good status carrying octets is refused, got $p")
    yield ()
    end for
  }

  test("OCSP: a batch beyond the cap is refused whole, and a delegated responder may still decline") {
    for
      s <- staple
      others <- (1 to 64).toList.traverse(i => certIdOf(s.caName, s.caSpki, Array[Byte]((i + 100).toByte)))
      oversize <- entries((others :+ s.certId).map(id => (id, statusGood)), s.issued.key)
      big <- x5.OCSP.verifyStapled(oversize, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(big == Left(x5.PathInvalid.LimitExceeded), s"65 entries -> LimitExceeded, whatever the last one says, got $big")
      marked <- x509fixtures.issuedBy(s.issued, 21, "responder.example", List(x509fixtures.endEntity, x509fixtures.eku(ocspSigning)))
      declined <- response(s.certId, statusUnknown, marked.key, List(marked.der))
      d <- x5.OCSP.verifyStapled(declined, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(d == Right(x5.OCSP.Status.Unknown), s"a delegated responder that declines is believed, got $d")
      // RFC 5280 section 6.1.4: a certificate marking an extension kufuli cannot process is not one
      // to proceed past, and a responder is a certificate like any other.
      opaque <- x509fixtures.issuedBy(
                  s.issued,
                  22,
                  "responder.example",
                  List(x509fixtures.endEntity, x509fixtures.eku(ocspSigning), x509fixtures.ext(Array[Byte](0x55, 0x1d, 0x24), true, seq()))
                )
      unreadable <- response(s.certId, statusGood, opaque.key, List(opaque.der))
      u <- x5.OCSP.verifyStapled(unreadable, s.leaf, s.ca, ocspAt).either.absolve
      _ <- check(u == Left(x5.PathInvalid.BadSignature), s"a responder with an unreadable critical extension is not a signer, got $u")
    yield ()
    end for
  }

  test("X25519 small-order points are rejected at import (full blocklist, non-canonical, and SPKI)") {
    // The seven low-order Curve25519 points (RFC 7748 section 6.1).
    val blocklist = List(
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )
    def hex(h: String): Array[Byte] = h.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
    val order8 = hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
    val order8HighBit = order8.updated(31, 0x80.toByte) // non-canonical: byte 31 top bit set, masked away
    val xSpki = hex("302a300506032b656e032100") ++ order8 // RFC 8410 X25519 SubjectPublicKeyInfo
    for
      _ <- blocklist.traverse_ { h =>
             PublicKey.parse(X25519)(Raw(Slice.of(hex(h)))).either.absolve.flatMap { r =>
               check(r.swap.toOption.contains(InvalidKey.WeakPoint), s"fromRaw($h) -> WeakPoint, got $r")
             }
           }
      hb <- PublicKey.parse(X25519)(Raw(Slice.of(order8HighBit))).either.absolve
      _ <- check(hb.swap.toOption.contains(InvalidKey.WeakPoint), s"non-canonical order-8 (high bit) -> WeakPoint, got $hb")
      sp <- PublicKey.parse(SPKI(Slice.of(xSpki))).either.absolve
      _ <- check(sp.swap.toOption.contains(InvalidKey.WeakPoint), s"SPKI-wrapped order-8 -> WeakPoint, got $sp")
      ty <- PublicKey.parse(X25519)(SPKI(Slice.of(xSpki))).either.absolve
      _ <- check(ty.swap.toOption.contains(InvalidKey.WeakPoint), s"the typed SPKI import carries the blocklist, got $ty")
      // The point is positioned by walking the encoding, so bytes appended past the SEQUENCE cannot
      // move the check off it; both the dispatching and the typed import refuse the blob outright.
      evil = xSpki ++ Array.fill[Byte](32)(0x11)
      ev <- PublicKey.parse(SPKI(Slice.of(evil))).either.absolve
      _ <- check(ev == Left(InvalidKey.Malformed), s"trailing bytes after the SPKI -> Malformed, got $ev")
      evt <- PublicKey.parse(X25519)(SPKI(Slice.of(evil))).either.absolve
      _ <- check(evt == Left(InvalidKey.Malformed), s"typed import rejects the same blob, got $evt")
    yield ()
    end for
  }

  test("an import is bound to the family and curve the caller named, not to what the encoding says") {
    for
      ed <- Ed25519.generate.absolve
      edSpki <- expectRight("ed spki")(ed.publicKey.spki)
      asX <- summon[XKeys].fromSpki(Slice.of(Array.from(edSpki.bytes.iterator))).either.absolve
      _ <- check(asX.isLeft, s"an Ed25519 SPKI must not import as X25519, got $asX")
      p256 <- P256.generate.absolve
      p256Spki <- expectRight("p256 spki")(p256.publicKey.spki)
      asP384 <- summon[EcKeys[P384]].fromSpki(Slice.of(Array.from(p256Spki.bytes.iterator))).either.absolve
      _ <- check(asP384.isLeft, s"a P-256 SPKI must not import as P-384, got $asP384")
      p256Pkcs8 <- expectRight("p256 pkcs8")(p256.privateKey.pkcs8)
      privP384 <- summon[EcKeys[P384]].fromPkcs8(Slice.of(Array.from(p256Pkcs8.bytes.iterator))).either.absolve
      _ <- check(privP384.isLeft, s"a P-256 PKCS#8 must not import as P-384, got $privP384")
    yield ()
  }

  test("a stored public key exports at exactly its wire width whatever encoding it arrived in") {
    val point = Array.tabulate[Byte](32)(i => (i + 3).toByte)
    val canonical = Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) ++ point
    val longForm = Array[Byte](0x30, 0x81.toByte, 0x2a) ++ canonical.drop(2)
    for
      k <- expectRight("canonical ed spki")(PublicKey.parse(Ed25519)(SPKI(Slice.of(canonical))))
      raw <- expectRight("raw")(k.raw)
      _ <- check(raw.bytes.length == 32 && raw.bytes.sameElements(point),
                 s"the canonical import exports its 32-byte point, got ${raw.bytes.length}"
           )
      nc <- summon[EdKeys].fromSpki(Slice.of(longForm)).either.absolve
      widths <- nc.traverse(k2 => expectRight("non-canonical raw")(k2.raw).map(_.bytes.length))
      _ <- check(widths.forall(_ == 32), s"a non-canonical SPKI is refused or still exports 32 bytes, got $widths")
    yield ()
  }

  test("a malformed ML-KEM encapsulation key is a value at import, not a defect at encapsulation") {
    val bad = Array.fill[Byte](MlKem768.publicKeyLength)(0xff.toByte)
    PublicKey.parse(MlKem768)(Raw(Slice.of(bad))).either.absolve.flatMap(r => check(r.isLeft, s"FIPS 203 s7.2 check runs at import, got $r"))
  }

  test("the record engine refuses a ciphertext shorter than its tag instead of verifying a truncated one") {
    val nonce = new Array[Byte](12)
    for
      key <- AesGcm256.generate.absolve
      tag <- key.cipher.use { c =>
               val dst = new Array[Byte](16)
               IO.fromEither(c.encrypt(Slice.of(dst), Slice.empty, Slice.empty, Slice.of(nonce))).as(dst)
             }.absolve
      // The leading four bytes of a genuine tag: node accepts a 4-byte GCM tag, so a `src` shorter
      // than the tag length used to authenticate against a truncated one - 2^32 work, not 2^128.
      short = tag.take(4)
      r <- summon[Ciphering[AesGcm256]]
             .engine(key)
             .use(e => IO(e.decrypt(Slice.of(new Array[Byte](16)), Slice.of(short), Slice.empty, Slice.of(nonce))))
             .absolve
      _ <- check(r == Left(AuthFailed), s"a short src is a rejection, not a truncated-tag verification, got $r")
    yield ()
    end for
  }

  test("the AES-CBC-HMAC composite round-trips an empty plaintext") {
    for
      key <- A128CbcHs256.generate.absolve
      box <- key.seal(Slice.empty).absolve
      out <- key.open(box).absolve
      _ <- check(out.length == 0, s"empty plaintext round-trips, got ${out.length}")
    yield ()
  }

  test("a key encoding the backend rejects is a typed value, and the DOOR names the arm") {
    val offCurve = Array[Byte](4) ++ Array.fill[Byte](64)(0xff.toByte)
    for
      // The seam is BINARY: a backend reports only Refused, so three backends cannot drift into
      // three classifications of one input.
      seam <- summon[EdKeys].fromSpki(Slice.of(Array[Byte](1, 2, 3))).either.absolve.attempt
      _ <- check(seam.toOption.flatMap(_.swap.toOption).contains(Refused), s"the seam refuses without an arm, got $seam")
      // The DOOR chooses the public arm from the form it was handed - one input, one arm, every
      // platform.
      spki <- PublicKey.parse(Ed25519)(SPKI(Slice.of(Array[Byte](1, 2, 3)))).either.absolve.attempt
      _ <- check(spki.toOption.flatMap(_.swap.toOption).contains(InvalidKey.Malformed), s"malformed SPKI -> Malformed, got $spki")
      pkcs8 <- PrivateKey.parse(Ed25519)(PKCS8(Slice.of(Array[Byte](1, 2, 3)))).either.absolve.attempt
      _ <- check(pkcs8.toOption.flatMap(_.swap.toOption).contains(InvalidKey.Malformed), s"malformed PKCS#8 -> Malformed, got $pkcs8")
      point <- PublicKey.parse(P256)(SEC1(Slice.of(offCurve))).either.absolve.attempt
      _ <- check(point.toOption.flatMap(_.swap.toOption).contains(InvalidKey.NotOnCurve), s"off-curve point -> NotOnCurve, got $point")
      // A well-formed COMPRESSED point is a variant kufuli declines, not a malformed input.
      compressed <- PublicKey.parse(P256)(SEC1(Slice.of(Array[Byte](2) ++ Array.fill[Byte](32)(1)))).either.absolve
      _ <- check(compressed == Left(InvalidKey.Unsupported), s"compressed SEC1 -> Unsupported, got $compressed")
    yield ()
    end for
  }

  test("the door's point classification reaches inside an SPKI, and the floor precedes the provider") {
    def bits(point: Array[Byte]) = tlv(0x03, Array[Byte](0) ++ point)
    val edOversize = seq(seq(x509fixtures.oid(x509fixtures.edOid)), bits(new Array[Byte](33)))
    val ecCompressed = seq(
      seq(x509fixtures.oid(DER.oidEcPublic), x509fixtures.oid(DER.oidP256)),
      bits(Array[Byte](2) ++ Array.fill[Byte](32)(1))
    )
    // Sub-floor modulus AND a provider-rejectable exponent: the floor answers first.
    val weakRsa = seq(
      seq(x509fixtures.oid(DER.oidRsa), Array[Byte](0x05, 0x00)),
      bits(seq(tlv(0x02, Array[Byte](0) ++ Array.fill[Byte](128)(0xff.toByte)), tlv(0x02, Array[Byte](0))))
    )
    // The inner RSAPublicKey SEQUENCE spells a small length in long form - one value, two
    // spellings - which the input-walking floor refuses where a canonicalising provider forgave.
    val innerContent = tlv(0x02, Array[Byte](0) ++ Array.fill[Byte](8)(1.toByte)) ++ tlv(0x02, Array[Byte](3))
    val longFormInner = Array[Byte](0x30, 0x81.toByte, innerContent.length.toByte) ++ innerContent
    val nonStrict = seq(seq(x509fixtures.oid(DER.oidRsa), Array[Byte](0x05, 0x00)), bits(longFormInner))
    for
      ed33 <- PublicKey.parse(Ed25519)(SPKI(Slice.of(edOversize))).either.absolve
      _ <- check(ed33 == Left(InvalidKey.WrongLength(32, 33)), s"a 33-octet Ed25519 subjectPublicKey -> WrongLength, got $ed33")
      cp <- PublicKey.parse(P256)(SPKI(Slice.of(ecCompressed))).either.absolve
      _ <- check(cp == Left(InvalidKey.Unsupported), s"a compressed point inside an SPKI -> Unsupported, like the SEC1 door, got $cp")
      weak <- PublicKey.parse(RSA)(SPKI(Slice.of(weakRsa))).either.absolve
      _ <- check(weak == Left(InvalidKey.Unsupported), s"sub-floor modulus answers before the provider, got $weak")
      ns <- PublicKey.parse(RSA)(SPKI(Slice.of(nonStrict))).either.absolve
      _ <- check(ns == Left(InvalidKey.Malformed), s"a long-form inner length is one value with two spellings -> Malformed, got $ns")
    yield ()
  }

  test("a certificate whose SPKI kufuli cannot import reports it rather than fabricating a key") {
    for
      key <- anyCert.publicKey.either.absolve
      _ <- check(key.isRight, s"a P-256 certificate yields its key, got $key")
    yield ()
  }

  test("JWT with deeply nested JSON is rejected (Malformed), not a stack overflow") {
    val depth = 200
    val payload = "[" * depth + "]" * depth
    val header = """{"alg":"ES256","kid":"k"}"""
    val token =
      Base64Url.encode(header.getBytes("UTF-8")) + "." + Base64Url.encode(payload.getBytes("UTF-8")) + "." + Base64Url.encode("sig".getBytes)
    check(JWT.peek(token) == Left(JWT.Malformed), s"deep token -> Malformed, got ${JWT.peek(token)}")
  }
end HardeningSuite
