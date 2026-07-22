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

import scala.concurrent.duration.*

import boilerplate.Slice
import boilerplate.effect.*

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*
import kufuli.x509 as x5

class RealBackendSuite extends munit.CatsEffectSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"$x%02x").mkString

  private val now = 1_700_000_000L

  test("AEAD: AES-GCM-256, ChaCha20-Poly1305, AES-256-CBC-HS512 seal/open + tamper") {
    for
      g <- AesGcm256.generate.absolve
      gbox <- g.seal(Slice.of("gcm".getBytes), Slice.of("aad".getBytes)).absolve
      gopen <- expectRight("gcm open")(g.open(gbox, Slice.of("aad".getBytes)))
      _ <- check(new String(gopen.toArray) == "gcm", "gcm round-trip")
      c <- ChaCha20Poly1305.generate.absolve
      cbox <- c.seal(Slice.of("chacha".getBytes)).absolve
      copen <- expectRight("chacha open")(c.open(cbox))
      _ <- check(new String(copen.toArray) == "chacha", "chacha round-trip")
      cbc <- A256CbcHs512.generate.absolve
      cbcbox <- cbc.seal(Slice.of("jose".getBytes), Slice.of("aad".getBytes)).absolve
      cbcopen <- expectRight("cbc open")(cbc.open(cbcbox, Slice.of("aad".getBytes)))
      _ <- check(new String(cbcopen.toArray) == "jose", "cbc-hs round-trip")
      tampered <- cbc.open(cbcbox, Slice.of("x".getBytes)).either
      _ <- check(tampered.isLeft, "cbc-hs tamper rejected")
    yield ()
  }

  test("signatures: ECDSA P-256 verify + DER<->raw; RSA-PSS/PKCS1/OAEP") {
    for
      p <- P256.generate.absolve
      sig <- p.privateKey.sign(Slice.of("m".getBytes)).absolve
      ok <- p.publicKey.verify(Slice.of("m".getBytes), sig).either
      _ <- check(ok == Right(()), "ecdsa verify")
      der = Array.from(sig.der.iterator)
      back = Signature.fromDer(P256)(der)
      _ <- check(back.exists(b => Array.from(b.bytes.iterator).sameElements(Array.from(sig.bytes.iterator))), "der round-trip")
      rsa <- Rsa.generate(Rsa.bits(2048)).absolve
      pss <- rsa.privateKey.sign(Slice.of("m".getBytes), RsaPss(Sha256)).absolve
      pssOk <- rsa.publicKey.verify(Slice.of("m".getBytes), pss, RsaPss(Sha256)).either
      _ <- check(pssOk == Right(()), "rsa-pss verify")
      pk1 <- rsa.privateKey.sign(Slice.of("m".getBytes), RsaPkcs1(Sha256)).absolve
      pk1Ok <- rsa.publicKey.verify(Slice.of("m".getBytes), pk1, RsaPkcs1(Sha256)).either
      _ <- check(pk1Ok == Right(()), "rsa-pkcs1 verify")
      ct <- rsa.publicKey.encrypt(Slice.of("secret".getBytes), RsaOaep(Sha256)).absolve
      dec <- expectRight("oaep")(rsa.privateKey.decrypt(ct, RsaOaep(Sha256)))
      _ <- check(new String(dec.toArray) == "secret", "oaep round-trip")
    yield ()
  }

  test("ML-KEM-768 (FIPS 203): encapsulate/decapsulate agree; wire sizes") {
    for
      kp <- MlKem768.generate.absolve
      enc <- kp.publicKey.encapsulate.absolve
      dz <- kp.privateKey.decapsulate(enc.ciphertext).absolve
      ea <- enc.secret.use(s => hex(s.toArray)).absolve
      da <- dz.use(s => hex(s.toArray)).absolve
      _ <- check(ea == da, "shared secret matches")
      raw <- expectRight("raw")(kp.publicKey.raw)
      _ <- check(raw.length == 1184 && enc.ciphertext.bytes.length == 1088, "ML-KEM-768 sizes")
    yield ()
  }

  test("key wrap: AES-KW / AES-KWP wrap and unwrap (SP 800-38F)") {
    for
      kw <- AesKw256.generate.absolve
      kwp <- AesKwp256.generate.absolve
      target <- AesGcm256.generate.absolve
      w1 <- kw.wrap(target).either
      u1 <- kw.unwrap(w1.toOption.get, AesGcm256).either
      _ <- check(u1.isRight, "KW unwrap")
      w2 <- kwp.wrap(target).either
      u2 <- kwp.unwrap(w2.toOption.get, AesGcm256).either
      _ <- check(u2.isRight, "KWP unwrap")
    yield ()
  }

  test("jose: ES256/EdDSA/HS256 sign+verify; expiry/audience/allowlist rejections; JWK; peek") {
    for
      p <- P256.generate.absolve
      jwk <- expectRight("jwk")(JWK.of("k1", p.publicKey))
      jwks = JWKS.of(jwk)
      claims = JWT.Claims.empty
                 .subject("alice")
                 .issuer("iss")
                 .audience("api")
                 .expiresIn(1.hour)
                 .id("jti")
                 .claim("htm", JoseValue.Str("POST"))
      tok <- JWT.sign(claims, ES256, "k1", now)(p.privateKey).absolve
      policy = JWT.Policy("api", Set(ES256, EdDSA)).issuer("iss").skew(60)
      v <- JWT.verify(tok.compact, jwks, policy, now).either
      _ <- check(v.exists(_.subject.contains("alice")), "es256 verify + sub")
      _ <- check(v.exists(_.claims.get("htm").contains(JoseValue.Str("POST"))), "custom claim round-trip")
      exp <- JWT.verify(tok.compact, jwks, policy, now + 7200).either
      _ <- check(exp.isLeft, "expired rejected")
      aud <- JWT.verify(tok.compact, jwks, JWT.Policy("other", Set(ES256)), now).either
      _ <- check(aud.isLeft, "audience mismatch rejected")
      alg <- JWT.verify(tok.compact, jwks, JWT.Policy("api", Set(EdDSA)), now).either
      _ <- check(alg.isLeft, "algorithm not allowlisted rejected")
      _ <- check(
             JWT.peek(tok.compact).exists(u => u.issuer.contains("iss") && u.kid.contains("k1") && u.algorithm == "ES256"),
             "peek routing"
           )
      ed <- Ed25519.generate.absolve
      edJwk <- expectRight("ed jwk")(JWK.of("e1", ed.publicKey))
      edTok <- JWT.sign(JWT.Claims.empty.audience("api").expiresIn(1.hour), EdDSA, "e1", now)(ed.privateKey).absolve
      edOk <- JWT.verify(edTok.compact, JWKS.of(edJwk), JWT.Policy("api", Set(EdDSA)), now).either
      _ <- check(edOk.isRight, "eddsa verify")
      mk <- HmacSha256.generate.absolve
      hsTok <- JWT.sign(JWT.Claims.empty.audience("api").expiresIn(1.hour), HS256, now)(mk).absolve
      hsOk <- JWT.verify(hsTok.compact, HS256, mk, JWT.Policy("api", Set(HS256)), now).either
      _ <- check(hsOk.isRight, "hs256 verify")
    yield ()
  }

  // Nested custom claims must survive sign -> verify verbatim: DPoP binds `cnf.jkt` and OIDC
  // back-channel logout carries a nested `events` object.
  test("jose: nested + array custom claims round-trip through sign/verify (jsoniter)") {
    val cnf = JoseValue.Obj(Map("jkt" -> JoseValue.Str("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")))
    val events = JoseValue.Obj(Map("http://schemas.openid.net/event/backchannel-logout" -> JoseValue.Obj(Map.empty)))
    val claims = JWT.Claims.empty
      .subject("u")
      .audience("api")
      .expiresIn(1.hour)
      .claim("cnf", cnf)
      .claim("events", events)
      .claim("scope", JoseValue.Arr(List(JoseValue.Str("read"), JoseValue.Str("write"))))
      .claim("n", JoseValue.Num(42))
      .claim("b", JoseValue.Bool(true))
      .claim("z", JoseValue.Null)
    for
      ed <- Ed25519.generate.absolve
      jwk <- expectRight("jwk")(JWK.of("k", ed.publicKey))
      tok <- JWT.sign(claims, EdDSA, "k", now)(ed.privateKey).absolve
      v <- JWT.verify(tok.compact, JWKS.of(jwk), JWT.Policy("api", Set(EdDSA)), now).either
      got = v.toOption.map(_.claims)
      _ <- check(got.flatMap(_.get("cnf")).contains(cnf), "nested cnf object round-trips")
      _ <- check(got.flatMap(_.get("events")).contains(events), "nested empty-object events round-trips")
      _ <- check(got.flatMap(_.get("scope")).contains(JoseValue.Arr(List(JoseValue.Str("read"), JoseValue.Str("write")))), "array claim")
      _ <- check(got.flatMap(_.get("n")).contains(JoseValue.Num(42)), "number claim")
      _ <- check(got.flatMap(_.get("b")).contains(JoseValue.Bool(true)), "bool claim")
      _ <- check(got.flatMap(_.get("z")).contains(JoseValue.Null), "null claim")
    yield ()
    end for
  }

  private val caPem =
    """-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIUfBid6gGHCJh1s5LsbQsDwQrulv0wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDcxMjAxMzUwOVoXDTM2MDcw
OTAxMzUwOVowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE6IPTCA5KGi40r1Kj3txg9G7mlEuIVA+h7P3h/j+iG0oHs3Co
uTPzSXs7eiHzd3b6m42+My8SQAWABQiXTHzzU6NjMGEwHQYDVR0OBBYEFHbVnKgI
ae/yr3ZL82d1voI8lNsEMB8GA1UdIwQYMBaAFHbVnKgIae/yr3ZL82d1voI8lNsE
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0gA
MEUCIEnpuq4bw9fVKuLP7zblcT+5wECACp3ldG+lLjMbM/imAiEA8rG96I+Xrhmz
nDMs9Kp6zwtMzwY2stmLBVOUBGMX780=
-----END CERTIFICATE-----"""
  private val leafPem =
    """-----BEGIN CERTIFICATE-----
MIIBujCCAWCgAwIBAgIUW8M3daaQqFDOkL9e7B85QC5V+S0wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDcxMjAxMzUwOVoXDTI3MDcx
MjAxMzUwOVowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASEnWnWJ6znfIICnRQ37RPxS2YRhFjtoBd7vAUf5jCuzFhUum+8
H/721UlR26OHZkVmfZNR70Kw8HrOLiH+41kho4GKMIGHMCUGA1UdEQQeMByCC2V4
YW1wbGUuY29tgg0qLmV4YW1wbGUuY29tMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAkG
A1UdEwQCMAAwHQYDVR0OBBYEFEmAL/JRZ7O+FuojUPBRooLIa87ZMB8GA1UdIwQY
MBaAFHbVnKgIae/yr3ZL82d1voI8lNsEMAoGCCqGSM49BAMCA0gAMEUCIQDFqwzq
1M2HntlgsdhkSt4QmWl3OLBm5JjgzW9uDnwuEgIgZXHTFDhWHEjRyNyONxTTmKm4
Pv/5JMnVs9fgK3Whg6g=
-----END CERTIFICATE-----"""

  test("x509: real EC chain path validation, SAN/wildcard, EKU-by-purpose, negatives") {
    val leaf = x5.Certificate.fromPem(leafPem).toOption.get
    val ca = x5.Certificate.fromPem(caPem).toOption.get
    val anchors = x5.TrustAnchors(List(ca))
    val at = 1_800_000_000L
    val host = x5.Hostname.of("example.com").toOption.get
    val wild = x5.Hostname.of("foo.example.com").toOption.get
    val evil = x5.Hostname.of("evil.com").toOption.get
    for
      _ <- check(leaf.subjectAltDns.sorted == List("*.example.com", "example.com"), "SAN parsed")
      ok <- x5.CertPath.verify(List(leaf), anchors, at, Some(host)).either
      _ <- check(ok.isRight, "serverauth valid")
      w <- x5.CertPath.verify(List(leaf), anchors, at, Some(wild)).either
      _ <- check(w.isRight, "wildcard SAN valid")
      nm <- x5.CertPath.verify(List(leaf), anchors, at, Some(evil)).either
      _ <- check(nm == Left(x5.PathInvalid.NameMismatch), "wrong host -> NameMismatch")
      ex <- x5.CertPath.verify(List(leaf), anchors, 1_600_000_000L, Some(host)).either
      _ <- check(ex == Left(x5.PathInvalid.Expired), "expired -> Expired")
      cu <- x5.CertPath.verify(List(leaf), anchors, at, None, x5.PathPurpose.ClientAuth).either
      _ <- check(cu == Left(x5.PathInvalid.ConstraintViolated), "clientauth on serverauth leaf -> ConstraintViolated")
      _ <- check(x5.Certificate.chainFromPem(leafPem + "\n" + caPem).map(_.length) == Right(2), "chainFromPem")
    yield ()
    end for
  }
end RealBackendSuite
