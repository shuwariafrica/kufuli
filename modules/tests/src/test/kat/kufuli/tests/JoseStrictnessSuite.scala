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
import scala.concurrent.duration.*

import boilerplate.Slice
import boilerplate.effect.*
import cats.effect.IO

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*

class JoseStrictnessSuite extends munit.CatsEffectSuite:

  private val now = 1_700_000_000L

  // COSE_Key CBOR built by hand, so each row states exactly which encoding it asserts about.
  private def bstr(b: Array[Byte]): Array[Byte] =
    if b.length < 24 then Array((0x40 | b.length).toByte) ++ b else Array(0x58.toByte, b.length.toByte) ++ b
  private def uint(n: Int): Array[Byte] = if n < 24 then Array(n.toByte) else Array(0x18.toByte, n.toByte)
  private def nint(n: Int): Array[Byte] = Array((0x20 | (-1 - n)).toByte) // -1 encodes as 0x20
  private def map(entries: Array[Byte]*): Array[Byte] =
    Array((0xa0 | entries.length).toByte) ++ entries.foldLeft(Array.emptyByteArray)(_ ++ _)

  private def okp(x: Array[Byte]): Array[Byte] =
    map(uint(1) ++ uint(1), nint(-1) ++ uint(6), nint(-2) ++ bstr(x))
  private def ec2(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    map(uint(1) ++ uint(2), nint(-1) ++ uint(1), nint(-2) ++ bstr(x), nint(-3) ++ bstr(y))

  test("CoseKey imports the WebAuthn credential-key subset and refuses everything else") {
    for
      ed <- Ed25519.generate.absolve
      raw <- expectRight("ed raw")(ed.publicKey.raw)
      edCose <- CoseKey.parse(okp(Array.from(raw.iterator))).either
      _ <- check(edCose.exists { case ImportedPublicKey.Ed(_) => true; case _ => false }, s"OKP/Ed25519 imports, got $edCose")
      p <- P256.generate.absolve
      sec1 <- expectRight("p256 sec1")(p.publicKey.sec1).map(a => Array.from(a.iterator))
      (x, y) = sec1.tail.splitAt(32)
      ecCose <- CoseKey.parse(ec2(x, y)).either
      _ <- check(ecCose.exists { case ImportedPublicKey.EcP256(_) => true; case _ => false }, s"EC2/P-256 imports, got $ecCose")
      unsupported <- CoseKey.parse(map(uint(1) ++ uint(3))).either
      _ <- check(unsupported == Left(InvalidKey.Unsupported), s"an RSA COSE key is unsupported, got $unsupported")
    yield ()
    end for
  }

  test("CoseKey: one credential key has exactly one COSE encoding") {
    for
      p <- P256.generate.absolve
      sec1 <- expectRight("p256 sec1")(p.publicKey.sec1).map(a => Array.from(a.iterator))
      (x, y) = sec1.tail.splitAt(32)
      // A 64-bit label truncated to 32 bits would read 0xFFFFFFFF00000001 as 1, the `kty` label.
      wide = Array(0xa1.toByte, 0x1b.toByte) ++ Array[Byte](-1, -1, -1, -1, 0, 0, 0, 1) ++ uint(1)
      truncated <- CoseKey.parse(wide).either
      _ <- check(truncated == Left(InvalidKey.Malformed), s"a 64-bit label is not narrowed, got $truncated")
      short <- CoseKey.parse(ec2(x.take(31), y)).either
      _ <- check(short.isLeft, s"a coordinate below the curve size is rejected, got $short")
      long <- CoseKey.parse(ec2(x, y ++ Array[Byte](0))).either
      _ <- check(long.isLeft, s"a coordinate above the curve size is rejected, got $long")
      trailing <- CoseKey.parse(ec2(x, y) ++ Array[Byte](0)).either
      _ <- check(trailing == Left(InvalidKey.Malformed), s"bytes after the map are rejected, got $trailing")
      duplicate = Array(0xa4.toByte) ++ (uint(1) ++ uint(2)) ++ (uint(1) ++ uint(1)) ++
                    (nint(-1) ++ uint(1)) ++ (nint(-2) ++ bstr(x))
      dup <- CoseKey.parse(duplicate).either
      _ <- check(dup == Left(InvalidKey.Malformed), s"a repeated label is rejected, got $dup")
      oversize = Array(0xa1.toByte) ++ nint(-2) ++ Array(0x5a.toByte) ++ Array[Byte](0, 0, 0, 4) ++ Array[Byte](1, 2, 3, 4)
      over <- CoseKey.parse(oversize).either
      _ <- check(over.isLeft, s"a byte string whose declared length overflows is rejected, got $over")
    yield ()
    end for
  }

  // A real 1024-bit key, so the private door is exercised through the backend that parses it rather
  // than through a synthetic encoding no provider would accept.
  private val weakRsaPkcs8 = Base64
    .decode(
      "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOTqDuk551c9Y7QfT0PLQHbdzZGk" +
        "01V/CrmjIag4pnm33EOPBH1qTtcIGdNt7F7u4wbtqG/mCtd6r6eaF2Q2TK/Wk2cdlQVIOza9ESsS" +
        "iRGjltg5KzuDPfarRQtDQwwe0Dpr5iP+PtFq+Iz6vMgNDHj8+PD3rb8fjXXsS0U0hiTBAgMBAAEC" +
        "gYAFxvp1XGbARuZbR2cCuQB5f4OOp3BF+hzVLo7M5hEdhUxj0Bo26BXxS10Lfvy2MKU+KYVUvaOM" +
        "aKZCPptUhiJNSY16f/NaLVh23ftuvdkFv0nN6ui/k4ida+BW8M4Q09/L5E7YT2QywrWZP0cGdhbd" +
        "EeS+imah7zVhf8ZdwauAAQJBAPmnhgYVpD0IIk7t5HeUBnYPPNtPoikIr+2aO3Q+6P+JXYKP8tdM" +
        "Aid4CGZwZ1qOhWseK3lMzXxgae6DE20NBQECQQDqu5S4fOIE6MEXaquhfow2k34ogv3pz5hjAVwr" +
        "G2kXIcC53HExZQLRh/QxMwjr3R09/pzD2LBYrgVP1ZPm2l/BAkEAj7suAyTEiMq9DdoSVfHoAmJl" +
        "dBIV1zAEMXRBVHy/ohcQuhFsCx3cg6Ksm2WNa2pwT6pv9wcLqtbLRiE6tubvAQJBANuSTDOm3eWp" +
        "s7Wr2pBeR9plbYWHwuyLfAhgpU7NfSheMmGpi1ihHFnTyuCa1KWNWGU9Xnb0o0DQx7c+GfPAIgEC" +
        "QFPsnBQaerz3U2k7zbcYhATHIzc0EunTDCPXfHMO8VaII8/v/CdsMqtPaQl5ErsmxuBF4UT0IQaR" +
        "FXNbRF9CyMI="
    )
    .toOption
    .get

  test("RSA keys below the 2048-bit floor are declined at import, not merely at generation") {
    val e = Array[Byte](1, 0, 1)
    for
      weak <- PublicKey.fromComponents(Slice.of(Array.fill[Byte](128)(0xff.toByte)), Slice.of(e)).either
      _ <- check(weak == Left(InvalidKey.Unsupported), s"a 1024-bit modulus is unsupported, got $weak")
      jwk = s"""{"kty":"RSA","n":"${Base64Url.encode(Array.fill[Byte](128)(0xff.toByte))}","e":"${Base64Url.encode(e)}"}"""
      parsed <- JWK.parse(jwk).either
      _ <- check(parsed == Left(InvalidKey.Unsupported), s"a sub-floor JWK is unsupported, got $parsed")
      ok <- PublicKey.fromComponents(Slice.of(Array.fill[Byte](256)(0xff.toByte)), Slice.of(e)).either
      _ <- check(ok.isRight, s"a 2048-bit modulus imports, got $ok")
    yield ()
  }

  test("the floor governs the private door too, so it cannot be walked around by loading a key") {
    for
      weak <- PrivateKey.fromPkcs8(RSA)(Slice.of(weakRsaPkcs8)).either
      _ <- check(weak == Left(InvalidKey.Unsupported), s"a 1024-bit private key is unsupported, got $weak")
      kp <- RSA.generate(RSA.bits(2048)).absolve
      exported <- expectRight("pkcs8")(kp.privateKey.pkcs8).map(a => Array.from(a.iterator))
      back <- PrivateKey.fromPkcs8(RSA)(Slice.of(exported)).either
      _ <- check(back.isRight, s"a 2048-bit private key round-trips through export and import, got $back")
    yield ()
  }

  test("an RSA modulus is the minimum octets that carry it, so one key has one JWK") {
    val e = Array[Byte](1, 0, 1)
    val modulus = Array.fill[Byte](256)(0xff.toByte)
    // RFC 7518 section 6.3.1.1 forbids the leading zero, and the backends do not read it alike:
    // node's JWK importer takes the octets verbatim where the JVM and Native normalise them away.
    val padded = Array[Byte](0) ++ modulus
    for
      inflated <- PublicKey.fromComponents(Slice.of(padded), Slice.of(e)).either
      _ <- check(inflated == Left(InvalidKey.Malformed), s"a leading zero octet is refused, got $inflated")
      jwk = s"""{"kty":"RSA","n":"${Base64Url.encode(padded)}","e":"${Base64Url.encode(e)}"}"""
      viaJwk <- JWK.parse(jwk).either
      _ <- check(viaJwk == Left(InvalidKey.Malformed), s"and refused through a JWK, got $viaJwk")
      // The floor itself reads the magnitude, so padding neither lifts a weak modulus over it nor
      // drops a sound one below it.
      _ <-
        check(RSA.modulusBits(Slice.of(padded)) == 2048, s"padding does not inflate the bit count, got ${RSA.modulusBits(Slice.of(padded))}")
      _ <- check(
             RSA.floored(Slice.of(Array[Byte](0) ++ Array.fill[Byte](128)(0xff.toByte))) == Left(InvalidKey.Unsupported),
             "nor lift a 1024-bit modulus over the floor"
           )
    yield ()
    end for
  }

  test("a JWT policy cannot be constructed or reshaped around its own checks") {
    assert(!typeChecks("JWT.Policy(\"api\", Set(HS256))"), "the allowlist is varargs, so an empty set cannot be passed")
    assert(!typeChecks("JWT.Policy.unaudienced(Set(HS256))"), "the unaudienced allowlist is varargs too")
    assert(!typeChecks("JWT.Policy(\"api\", HS256).copy(requireExpiry = false)"), "there is no copy to defeat the expiry default")
    assert(!typeChecks("new JWT.Policy(None, Set.empty, None, 0L, false)"), "the constructor is private")
    assert(!typeChecks("JWT.Policy(\"api\", HS256).requireExpiry"), "policy fields are not readable outside jose")
    assert(typeChecks("JWT.Policy(\"api\", HS256).unexpiring"), "the named opt-out is the only door")
    assert(JWT.Policy.of("api", Set.empty).isLeft, "the validated door rejects an empty dynamic allowlist")
    assert(JWT.Policy.of("api", Set(HS256)).isRight, "a non-empty dynamic allowlist constructs")
    assert(JWT.Policy.of(Set.empty).isLeft, "the unaudienced validated door rejects an empty allowlist")
  }

  test("a JOSE number that JSON cannot render is unrepresentable") {
    assert(scala.util.Try(JoseValue.Num(Double.PositiveInfinity)).isFailure, "an infinite Num does not construct")
    assert(scala.util.Try(JoseValue.Num(Double.NaN)).isFailure, "a NaN Num does not construct")
    assert(scala.util.Try(JoseValue.Num(1.0).copy(value = Double.NaN)).isFailure, "copy is bound by the same check")
    assert(JoseValue.Num(1e308).value == 1e308, "a finite Num constructs")
  }

  test("every JOSE value kufuli emits is one it reads back") {
    val values = List(
      JoseValue.Num(1),
      JoseValue.Num(-0.5),
      JoseValue.Num(1e308),
      JoseValue.Num(1.0e-5),
      JoseValue.Num(Long.MaxValue.toDouble),
      JoseValue.Str("plain"),
      JoseValue.Str("quotes \" backslash \\ tab \t"),
      JoseValue.Bool(true),
      JoseValue.Null,
      JoseValue.Arr(List(JoseValue.Num(1), JoseValue.Str("x"))),
      JoseValue.Obj(Map("b" -> JoseValue.Num(2), "a" -> JoseValue.Null))
    )
    val claims = values.zipWithIndex.foldLeft(JWT.Claims.empty.expiresIn(1.hour))((c, v) => c.claim(s"c${v._2}", v._1))
    for
      key <- HmacSha256.generate.absolve
      tok <- JWT.sign(claims, HS256, now)(key).absolve
      v <- JWT.verify(tok.compact, HS256, key, JWT.Policy.unaudienced(HS256), now).either
      got <- IO.fromEither(v.left.map(e => new AssertionError(s"verify: $e")))
      _ <- check(
             values.zipWithIndex.forall((value, i) => got.claims.get(s"c$i").contains(value)),
             s"every emitted value parses back to itself, got ${got.claims}"
           )
    yield ()
  }

  test("text no JSON document can carry is refused where the truncation happened, not at sign") {
    // What slicing a string through a surrogate pair leaves behind.
    val lone = "a\ud800b"
    val trailing = "a\udc00b"
    val paired = "a\ud83d\ude00b" // the same code units, spelled without leaving ASCII
    assert(scala.util.Try(JoseValue.Str(lone)).isFailure, "a lone high surrogate does not construct")
    assert(scala.util.Try(JoseValue.Str(trailing)).isFailure, "a lone low surrogate does not construct")
    assert(scala.util.Try(JoseValue.Str("ok").copy(value = lone)).isFailure, "copy is bound by the same check")
    assert(JoseValue.Str(paired).value == paired, "a well-formed pair constructs")
    assert(scala.util.Try(JWT.Claims.empty.subject(lone)).isFailure, "an ill-formed subject does not construct")
    assert(scala.util.Try(JWT.Claims.empty.issuer(lone)).isFailure, "nor an issuer")
    assert(scala.util.Try(JWT.Claims.empty.audience(lone)).isFailure, "nor an audience")
    assert(scala.util.Try(JWT.Claims.empty.id(lone)).isFailure, "nor a jti")
    assert(scala.util.Try(JWT.Claims.empty.claim(lone, JoseValue.Bool(true))).isFailure, "nor a custom claim name")
    // A nested member name is the same claim-carrying text, and `Claims`'s own require reaches only
    // the top level - so `sign` is total by construction only once the value type carries this.
    assert(scala.util.Try(JoseValue.Obj(Map(lone -> JoseValue.Bool(true)))).isFailure, "nor a nested object's member name")
    assert(
      scala.util.Try(JoseValue.Obj(Map("ok" -> JoseValue.Bool(true))).copy(fields = Map(lone -> JoseValue.Bool(true)))).isFailure,
      "copy is bound by the same check"
    )
    assert(JWT.Claims.empty.subject(paired).subject.contains(paired), "a well-formed subject constructs")
  }

  test("the Ed25519 identifier is emitted current and verified either way (RFC 9864)") {
    val claims = JWT.Claims.empty.subject("s").expiresIn(1.hour)
    val policy = JWT.Policy.unaudienced(EdDSA)
    for
      kp <- Ed25519.generate.absolve
      tok <- JWT.sign(claims, EdDSA, now)(kp.privateKey).absolve
      header <- IO.fromEither(Base64Url.decode(tok.compact.split('.')(0)).left.map(e => new AssertionError(s"header: $e")))
      _ <- check(new String(header, "UTF-8").contains("\"alg\":\"Ed25519\""),
                 s"the emitted alg is the current registry value, got ${new String(header, "UTF-8")}"
           )
      _ <- check(JWT.peek(tok.compact).exists(_.algorithm == "Ed25519"), s"peek reports what was emitted, got ${JWT.peek(tok.compact)}")
      current <- JWT.verify(tok.compact, EdDSA, kp.publicKey, policy, now).either
      _ <- check(current.isRight, s"a token carrying Ed25519 verifies, got $current")
      legacy <- reheaded(tok.compact, """{"alg":"EdDSA"}""", kp.privateKey)
      accepted <- JWT.verify(legacy, EdDSA, kp.publicKey, policy, now).either
      _ <- check(accepted.isRight, s"a token carrying the legacy EdDSA verifies into the same arm, got $accepted")
      set <- expectRight("jwk")(JWK.of("k", kp.publicKey)).map(JwkSet.of(_))
      viaSet <- JWT.verify(legacy, set, policy, now).either
      _ <- check(viaSet.isRight, s"and through a key set, got $viaSet")
      foreign <- reheaded(tok.compact, """{"alg":"ES256"}""", kp.privateKey)
      other <- JWT.verify(foreign, EdDSA, kp.publicKey, policy, now).either
      _ <- check(other == Left(JWT.UntrustedAlgorithm), s"another algorithm still does not match this arm, got $other")
      jwkTok <- JWT.sign(claims.id("j"), EdDSA, "dpop+jwt", kp.publicKey, now)(kp.privateKey).absolve
      jwkHeader <- IO.fromEither(Base64Url.decode(jwkTok.compact.split('.')(0)).left.map(e => new AssertionError(s"header: $e")))
      _ <- check(new String(jwkHeader, "UTF-8").contains("\"alg\":\"Ed25519\""), "the header-jwk profile emits through the same field")
    yield ()
    end for
  }

  // Re-signs a token's payload under a caller-supplied protected header.
  private def reheaded(token: String, header: String, key: PrivateKey[Ed25519]): IO[String] =
    val payload = token.split('.')(1)
    val input = Base64Url.encode(header.getBytes("UTF-8")) + "." + payload
    key.sign(Slice.of(input.getBytes("US-ASCII"))).absolve.map(sig => input + "." + Base64Url.encode(Array.from(sig.bytes.iterator)))

  test("a JWT is comparable, and the two-parameter claim wither has its non-curried form") {
    val a = JWT.Claims.empty.subject("s").expiresIn(1.hour)
    val b = JWT.Claims.claim(a, "htm", JoseValue.Str("POST"))
    assert(b.custom.get("htm").contains(JoseValue.Str("POST")), "the companion alias is the extension")
    assert(b == a.claim("htm", JoseValue.Str("POST")), "and agrees with the extension form")
    for
      key <- HmacSha256.generate.absolve
      one <- JWT.sign(a, HS256, now)(key).absolve
      two <- JWT.sign(a, HS256, now)(key).absolve
      _ <- check(one == two, "two tokens over the same claims at the same instant compare equal")
    yield ()
  }

  test("a verified token exposes the not-before it was signed with") {
    val claims = JWT.Claims.empty.subject("s").notBefore(now - 60).expiresIn(1.hour)
    for
      key <- HmacSha256.generate.absolve
      tok <- JWT.sign(claims, HS256, now)(key).absolve
      v <- JWT.verify(tok.compact, HS256, key, JWT.Policy.unaudienced(HS256), now).either
      _ <- check(v.exists(_.notBefore.contains(now - 60)), s"nbf reaches Verified, got $v")
      early <- JWT.verify(tok.compact, HS256, key, JWT.Policy.unaudienced(HS256), now - 120).either
      _ <- check(early == Left(JWT.NotYetValid), s"a token before its nbf is rejected, got $early")
    yield ()
  }

  test("the JWK curve arms round-trip every curve the library publishes") {
    for
      p384 <- P384.generate.absolve
      j384 <- expectRight("p384 jwk")(JWK.of("k384", p384.publicKey))
      r384 <- JWK.parse(j384.json).either
      _ <- check(r384.exists(_.key match
                   case ImportedPublicKey.EcP384(_) => true;
                   case _                           => false),
                 s"P-384 round-trips, got $r384"
           )
      p521 <- P521.generate.absolve
      j521 <- expectRight("p521 jwk")(JWK.of("k521", p521.publicKey))
      r521 <- JWK.parse(j521.json).either
      _ <- check(r521.exists(_.key match
                   case ImportedPublicKey.EcP521(_) => true;
                   case _                           => false),
                 s"P-521 round-trips, got $r521"
           )
      short = j521.json.replace("\"y\":\"", "\"y\":\"A")
      bad <- JWK.parse(short).either
      _ <- check(bad.isLeft, s"an over-long coordinate is rejected, got $bad")
    yield ()
    end for
  }
end JoseStrictnessSuite
