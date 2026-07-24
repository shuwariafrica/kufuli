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

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*
import kufuli.x509 as x5

// Regression tests for the audit hardening fixes: OCSP certStatus parse (was reporting Good for a
// revoked cert), the JWE loud-failure (was faking success), and the bounded JSON/COSE recursion
// (was a stack-overflow DoS on an unsigned token).
class HardeningSuite extends munit.CatsEffectSuite:

  // Minimal DER emitter for the OCSP fixtures.
  private def tlv(tag: Int, content: Array[Byte]): Array[Byte] =
    val len = content.length
    val header =
      if len < 0x80 then Array[Byte](tag.toByte, len.toByte)
      else if len < 0x100 then Array[Byte](tag.toByte, 0x81.toByte, len.toByte)
      else Array[Byte](tag.toByte, 0x82.toByte, (len >> 8).toByte, len.toByte)
    header ++ content
  private def seq(parts: Array[Byte]*): Array[Byte] = tlv(0x30, parts.reduce(_ ++ _))

  private def gtime(v: String): Array[Byte] = tlv(0x18, v.getBytes("US-ASCII"))
  private val oidBasic = tlv(0x06, Array[Byte](0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1)) // 1.3.6.1.5.5.7.48.1.1
  private val certId =
    seq(tlv(0x06, Array[Byte](0x2b, 0x0e, 0x03, 0x02, 0x1a)), tlv(0x04, Array[Byte](1)), tlv(0x04, Array[Byte](2)), tlv(0x02, Array[Byte](3)))
  private val responderId = tlv(0xa2, tlv(0x04, Array[Byte](1, 2, 3, 4))) // byKey [2] KeyHash

  // A successful OCSPResponse carrying one SingleResponse with the given certStatus DER.
  private def ocsp(certStatus: Array[Byte]): Array[Byte] =
    val single = seq(certId, certStatus, gtime("20260101000000Z"))
    val responseData = seq(responderId, gtime("20260101000000Z"), seq(single))
    val basic = seq(responseData, seq(oidBasic), tlv(0x03, Array[Byte](0, 0)))
    val responseBytes = seq(oidBasic, tlv(0x04, basic))
    seq(tlv(0x0a, Array[Byte](0)), tlv(0xa0, responseBytes))

  private val statusGood = Array[Byte](0x80.toByte, 0x00) // good [0] IMPLICIT NULL
  private val statusUnknown = Array[Byte](0x82.toByte, 0x00) // unknown [2] IMPLICIT NULL
  private val statusRevoked = tlv(0xa1, gtime("20250601000000Z")) // revoked [1] { revocationTime }

  private val anyCert = x5.Certificate
    .fromPem("""-----BEGIN CERTIFICATE-----
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

  test("OCSP: a REVOKED single-response is reported Revoked, not Good") {
    val now = 1_800_000_000L
    for
      g <- x5.OCSP.verifyStapled(ocsp(statusGood), anyCert, anyCert, now).either
      _ <- check(g == Right(x5.OCSP.Status.Good), s"good staple -> Good, got $g")
      r <- x5.OCSP.verifyStapled(ocsp(statusRevoked), anyCert, anyCert, now).either
      _ <- check(r.exists { case x5.OCSP.Status.Revoked(_) => true; case _ => false }, s"revoked staple -> Revoked, got $r")
      u <- x5.OCSP.verifyStapled(ocsp(statusUnknown), anyCert, anyCert, now).either
      _ <- check(u == Right(x5.OCSP.Status.Unknown), s"unknown staple -> Unknown, got $u")
      // A non-successful responseStatus carries no body -> Unknown.
      t <- x5.OCSP.verifyStapled(seq(tlv(0x0a, Array[Byte](3))), anyCert, anyCert, now).either
      _ <- check(t == Right(x5.OCSP.Status.Unknown), s"tryLater -> Unknown, got $t")
      m <- x5.OCSP.verifyStapled(Array[Byte](1, 2, 3), anyCert, anyCert, now).either
      _ <- check(m == Left(x5.PathInvalid.MalformedChain), s"garbage -> MalformedChain, got $m")
    yield ()
    end for
  }

  test("JWE seal/open raise loudly rather than fake success") {
    for
      p <- P256.generate.absolve
      sealResult <- JWE.seal(Slice.of("m".getBytes), p.publicKey, JWE.Alg.EcdhEs, JWE.Enc.A128Gcm).absolve.attempt
      _ <- check(sealResult.left.exists { case _: UnsupportedOperationException => true; case _ => false }, s"seal raises, got $sealResult")
      opened <- JWE.open("eyJ.x.y", p.privateKey, Set(JWE.Enc.A128Gcm)).absolve.attempt
      _ <- check(opened.left.exists { case _: UnsupportedOperationException => true; case _ => false }, s"open raises, got $opened")
    yield ()
  }

  test("X25519 small-order peer: import passes (non-zero) but agree yields no shared secret") {
    // An order-8 point (RFC 7748 section 6.1 / libsodium blocklist); its scalar product is all-zero.
    val smallOrder = "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
      .grouped(2)
      .map(Integer.parseInt(_, 16).toByte)
      .toArray
    for
      kp <- X25519.generate.absolve
      peer <- expectRight("import small-order")(PublicKey.fromRaw(X25519)(Slice.of(smallOrder)))
      // `agree` is declared total; a small-order peer forces the backend to reject the all-zero output,
      // surfacing as a raised defect rather than a wrong (predictable all-zero) shared secret.
      result <- kp.privateKey.agree(peer).absolve.attempt
      _ <- check(result.isLeft, s"small-order agree must not yield a shared secret, got ${result.map(_ => "<secret>")}")
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
