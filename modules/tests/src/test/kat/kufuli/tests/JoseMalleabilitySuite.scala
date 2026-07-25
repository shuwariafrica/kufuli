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
import cats.effect.IO
import cats.syntax.all.*

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*

class JoseMalleabilitySuite extends munit.CatsEffectSuite:

  private val now = 1_700_000_000L
  private val apiPolicy = JWT.Policy("api", Set(HS256))
  private val livePayload = """{"aud":"api","exp":9999999999}""".getBytes("UTF-8")

  private def b64(text: String): String = Base64Url.encode(text.getBytes("UTF-8"))

  // Assembles a token from raw header/payload octets so a test can present bytes the signer would
  // never emit, carrying a signature that genuinely verifies.
  private def signed(header: Array[Byte], payload: Array[Byte], key: SecretKey[HmacSha256])(using m: Mac[HmacSha256]): IO[String] =
    val input = Base64Url.encode(header) + "." + Base64Url.encode(payload)
    m.sign(key, Slice.of(input.getBytes("US-ASCII"))).map(sig => input + "." + Base64Url.encode(Array.from(sig.bytes.iterator))).absolve

  private def segment(token: String, index: Int): String = token.split('.')(index)

  test("RFC 7515 section 5.2 step 1: trailing periods are rejected, though every variant carries the same valid signature") {
    for
      key <- HmacSha256.generate.absolve
      tok <- JWT.sign(JWT.Claims.empty.audience("api").expiresIn(1.hour), HS256, now)(key).absolve
      ok <- JWT.verify(tok.compact, HS256, key, apiPolicy, now).either
      _ <- check(ok.isRight, s"the canonical token verifies, got $ok")
      _ <- List(".", "..", ".....").traverse_ { suffix =>
             JWT.verify(tok.compact + suffix, HS256, key, apiPolicy, now).either.flatMap { r =>
               check(r == Left(JWT.Malformed), s"token + '$suffix' -> Malformed, got $r")
             }
           }
      _ <- check(JWT.peek(tok.compact + ".") == Left(JWT.Malformed), "peek rejects a trailing period")
    yield ()
  }

  test("base64url decoding is canonical: a final group with non-zero unused bits is rejected, at the codec and in a signed token") {
    for
      key <- HmacSha256.generate.absolve
      tok <- JWT.sign(JWT.Claims.empty.audience("api").expiresIn(1.hour), HS256, now)(key).absolve
      sig = segment(tok.compact, 2)
      tail = sig.length % 4
      _ <- check(tail != 0, s"the 32-byte tag ends in a short group, got length ${sig.length}")
      // A final group of `tail` characters carries 6*tail bits but only 8*(tail-1) octet bits; the
      // remainder sits in the low bits of the last character and no byte receives it.
      unused = (1 << (6 * tail - 8 * (tail - 1))) - 1
      variant = tok.compact.init + Base64.urlAlphabet((Base64.urlInverse(sig.last.toInt) & ~unused) | 1)
      _ <- check(Base64Url.decode(sig).isRight, "the canonical signature decodes")
      _ <- check(
             Base64Url.decode(segment(variant, 2)).toOption.isEmpty,
             s"the variant signature no longer decodes, got ${Base64Url.decode(segment(variant, 2)).map(_.length)}"
           )
      r <- JWT.verify(variant, HS256, key, apiPolicy, now).either
      _ <- check(r == Left(JWT.Malformed), s"non-canonical signature encoding -> Malformed, got $r")
      _ <- check(Base64Url.decode("QQ").isRight, "'QQ' is the canonical encoding of 0x41")
      _ <- check(Base64Url.decode("QR").isLeft, "'QR' decodes to the same octet and is rejected")
      _ <- check(Base64Url.decode("Zm8").isRight, "'Zm8' is the canonical encoding of 'fo'")
      _ <- check(Base64Url.decode("Zm9").isLeft, "'Zm9' decodes to the same octets and is rejected")
      _ <- check(Base64.decode("QUJD").isRight, "a correctly padded standard base64 body decodes")
      _ <- check(Base64.decode("QUJD====").isLeft, "more than two padding characters are rejected")
    yield ()
  }

  test("RFC 7515 section 4.1.11: a token declaring a crit extension is rejected, though its signature is valid") {
    val crit = """{"alg":"HS256","crit":["exp"],"exp":1363284000}""".getBytes("UTF-8")
    val plain = """{"alg":"HS256","exp":1363284000}""".getBytes("UTF-8")
    for
      key <- HmacSha256.generate.absolve
      tok <- signed(crit, livePayload, key)
      r <- JWT.verify(tok, HS256, key, apiPolicy, now).either
      _ <- check(r == Left(JWT.Malformed), s"crit header -> Malformed, got $r")
      _ <- check(JWT.peek(tok) == Left(JWT.Malformed), "peek rejects a crit header")
      // the same token without `crit` verifies, so the rejection is the crit member and nothing else
      control <- signed(plain, livePayload, key)
      ok <- JWT.verify(control, HS256, key, apiPolicy, now).either
      _ <- check(ok.isRight, s"the same header without crit verifies, got $ok")
    yield ()
  }

  test("RFC 7519 section 4: a custom claim repeating a registered name does not emit that name twice") {
    val claims = JWT.Claims.empty
      .audience("api")
      .expiresIn(1.hour)
      .claim("exp", JoseValue.Num(9.0e9))
      .claim("htm", JoseValue.Str("POST"))
    for
      key <- HmacSha256.generate.absolve
      tok <- JWT.sign(claims, HS256, now)(key).absolve
      payload = new String(Base64Url.decode(segment(tok.compact, 1)).toOption.get, "UTF-8")
      _ <- check(payload.sliding(6).count(_ == "\"exp\":") == 1, s"exp emitted once, got $payload")
      _ <- check(payload.contains(s""""exp":${now + 3600}"""), s"the typed expiry is the emitted one, got $payload")
      _ <- check(payload.contains(""""htm":"POST""""), s"a claim outside the registered set still emits, got $payload")
      v <- JWT.verify(tok.compact, HS256, key, apiPolicy, now).either
      _ <- check(v.exists(_.expiresAt.contains(now + 3600)), s"the verified expiry is the typed one, got $v")
    yield ()
  }

  test("RFC 7515 section 5.2 step 3: header octets that are not valid UTF-8 are rejected rather than replaced") {
    val prefix = """{"alg":"HS256","kid":"""".getBytes("UTF-8")
    val suffix = """"}""".getBytes("UTF-8")
    for
      key <- HmacSha256.generate.absolve
      a <- signed(prefix ++ Array[Byte](0xff.toByte) ++ suffix, livePayload, key)
      b <- signed(prefix ++ Array[Byte](0xfe.toByte) ++ suffix, livePayload, key)
      _ <- check(a != b, "the two tokens are distinct strings")
      ra <- JWT.verify(a, HS256, key, apiPolicy, now).either
      rb <- JWT.verify(b, HS256, key, apiPolicy, now).either
      _ <- check(ra == Left(JWT.Malformed) && rb == Left(JWT.Malformed), s"invalid UTF-8 header -> Malformed, got $ra and $rb")
      _ <- check(JWT.peek(a) == Left(JWT.Malformed), "peek rejects invalid UTF-8 header octets")
    yield ()
  }

  test("an out-of-Double-range number in the header jwk is rejected, with no signature and no raised defect") {
    val header = """{"alg":"EdDSA","typ":"dpop+jwt","jwk":{"crv":"Ed25519","kty":"OKP","x":"AAAA","zz":1e999}}"""
    val token = b64(header) + "." + b64("""{"exp":9999999999}""") + "." + Base64Url.encode(new Array[Byte](64))
    for
      r <- JWT.verifyWithHeaderKey(token, "dpop+jwt", JWT.Policy.unaudienced(Set(EdDSA)), now).either
      _ <- check(r == Left(JWT.Malformed), s"1e999 in the header jwk -> Malformed, got $r")
    yield ()
  }

  // The header jwk is the one attacker-supplied value kufuli re-serialises, so it is where a reader
  // that accepts more than the writer emits surfaces: the parse must reject whatever cannot be
  // written, and no input may leave the typed error channel.
  test("reader and writer agree: a hostile member in the header jwk always yields a rejection, never a defect") {
    val members = List(
      "1e999",
      "-1e999",
      "1e-999",
      "1.7976931348623157e308",
      "-1.7976931348623157e308",
      "123456789012345678901234567890",
      "-0",
      "0.30000000000000004",
      "\"\\ud83d\\ude00\"",
      "\"\\u0000\"",
      "\"\"",
      "null",
      "true",
      "[[[[[[[[[[1]]]]]]]]]]",
      "[1e999]",
      "{\"n\":1e999}",
      "{\"a\":{\"b\":{\"c\":1}}}"
    )
    val policy = JWT.Policy.unaudienced(Set(EdDSA))
    for
      kp <- Ed25519.generate.absolve
      raw <- kp.publicKey.raw.absolve
      x = Base64Url.encode(Array.from(raw.iterator))
      _ <- members.traverse_ { member =>
             val header = s"""{"alg":"EdDSA","typ":"dpop+jwt","jwk":{"crv":"Ed25519","kty":"OKP","x":"$x","zz":$member}}"""
             val token = b64(header) + "." + b64("""{"exp":9999999999}""") + "." + Base64Url.encode(new Array[Byte](64))
             JWT.verifyWithHeaderKey(token, "dpop+jwt", policy, now).either.flatMap { r =>
               check(r.isLeft, s"jwk member $member -> a typed rejection, got $r")
             }
           }
    yield ()
    end for
  }

  test("ES384 and ES512: a published JWK parses back to its own arm and a proof verifies under its embedded header key") {
    val claims = JWT.Claims.empty.id("jti-ec").expiresIn(1.hour)
    for
      k384 <- P384.generate.absolve
      k521 <- P521.generate.absolve
      j384 <- JWK.of("k384", k384.publicKey).absolve
      j521 <- JWK.of("k521", k521.publicKey).absolve
      r384 <- JWK.parse(j384.json).absolve
      r521 <- JWK.parse(j521.json).absolve
      _ <- check(r384.key match
                   case ImportedPublicKey.EcP384(_) => true;
                   case _                           => false
                 ,
                 s"P-384 parses to its arm, got ${r384.key}"
           )
      _ <- check(r521.key match
                   case ImportedPublicKey.EcP521(_) => true;
                   case _                           => false
                 ,
                 s"P-521 parses to its arm, got ${r521.key}"
           )
      p384 <- JWT.sign(claims, ES384, "dpop+jwt", k384.publicKey, now)(k384.privateKey).absolve
      v384 <- JWT.verifyWithHeaderKey(p384.compact, "dpop+jwt", JWT.Policy.unaudienced(Set(ES384)), now).either
      _ <- check(v384.exists((verified, _) => verified.id.contains("jti-ec")), s"ES384 proof verifies under its embedded key, got $v384")
      p521 <- JWT.sign(claims, ES512, "dpop+jwt", k521.publicKey, now)(k521.privateKey).absolve
      v521 <- JWT.verifyWithHeaderKey(p521.compact, "dpop+jwt", JWT.Policy.unaudienced(Set(ES512)), now).either
      _ <- check(v521.exists((verified, _) => verified.id.contains("jti-ec")), s"ES512 proof verifies under its embedded key, got $v521")
    yield ()
    end for
  }

  test("a token beyond the accepted length is rejected before any of it is decoded") {
    def padded(n: Int) = JWT.Claims.empty.audience("api").expiresIn(1.hour).claim("pad", JoseValue.Str("a" * n))
    for
      key <- HmacSha256.generate.absolve
      big <- JWT.sign(padded(70000), HS256, now)(key).absolve
      _ <- check(big.compact.length > 65536, s"the token exceeds the bound, length ${big.compact.length}")
      r <- JWT.verify(big.compact, HS256, key, apiPolicy, now).either
      _ <- check(r == Left(JWT.Malformed), s"oversized token -> Malformed, got $r")
      small <- JWT.sign(padded(1000), HS256, now)(key).absolve
      ok <- JWT.verify(small.compact, HS256, key, apiPolicy, now).either
      _ <- check(ok.isRight, s"a token within the bound still verifies, got $ok")
    yield ()
  }
end JoseMalleabilitySuite
