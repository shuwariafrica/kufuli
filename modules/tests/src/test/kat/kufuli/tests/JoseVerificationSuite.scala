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

import boilerplate.effect.*

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*

class JoseVerificationSuite extends munit.CatsEffectSuite:

  private val now = 1_700_000_000L

  // The typeChecks receivers below exist only to be named inside the compile-fact string.
  def xfamP256Pub: PublicKey[P256] = ???
  def xfamEdPriv: PrivateKey[Ed25519] = ???

  test("jose rejections: UnknownKey (absent kid) is distinct from KeyAlgorithmMismatch (arm / symmetric-on-JWKS / pinned)") {
    val claims = JWT.Claims.empty.subject("alice").audience("api").expiresIn(1.hour)
    val policy = JWT.Policy("api", Set(ES256, EdDSA, HS256))
    for
      ec <- P256.generate.absolve
      rsa <- Rsa.generate(Rsa.bits(2048)).absolve
      mk <- HmacSha256.generate.absolve
      ed <- Ed25519.generate.absolve
      ecJwk <- expectRight("ec jwk")(JWK.of("k1", ec.publicKey))
      rsaJwk <- expectRight("rsa jwk")(JWK.of("k1", rsa.publicKey))
      tok <- JWT.sign(claims, ES256, "k1", now)(ec.privateKey).absolve
      hsTok <- JWT.sign(claims, HS256, now)(mk).absolve
      // absent kid: an empty JWKS with a kid'd token -> UnknownKey (the refresh-on-miss signal)
      unknown <- JWT.verify(tok.compact, JWKS.of(), policy, now).either
      _ <- check(unknown == Left(JWT.UnknownKey), s"empty JWKS -> UnknownKey, got $unknown")
      // kid resolves but the key arm mismatches (RSA jwk under the same kid, ES256 token)
      arm <- JWT.verify(tok.compact, JWKS.of(rsaJwk), policy, now).either
      _ <- check(arm == Left(JWT.KeyAlgorithmMismatch), s"RSA jwk vs ES256 token -> KeyAlgorithmMismatch, got $arm")
      // an allowlisted symmetric alg reaching the public-key set
      sym <- JWT.verify(hsTok.compact, JWKS.of(ecJwk), policy, now).either
      _ <- check(sym == Left(JWT.KeyAlgorithmMismatch), s"HS256 via a JWKS -> KeyAlgorithmMismatch, got $sym")
      // pinned single-key verify: the token alg (ES256) is allowlisted but is not the pinned alg (EdDSA)
      pinned <- JWT.verify(tok.compact, EdDSA, ed.publicKey, policy, now).either
      _ <- check(pinned == Left(JWT.KeyAlgorithmMismatch), s"pinned alg mismatch -> KeyAlgorithmMismatch, got $pinned")
    yield ()
    end for
  }

  test("jose expiry: a token with no exp is rejected by default (MissingExpiry) and accepted under .unexpiring") {
    val noExp = JWT.Claims.empty.subject("job-7").audience("api")
    for
      mk <- HmacSha256.generate.absolve
      tok <- JWT.sign(noExp, HS256, now)(mk).absolve
      missing <- JWT.verify(tok.compact, HS256, mk, JWT.Policy("api", Set(HS256)), now).either
      _ <- check(missing == Left(JWT.MissingExpiry), s"no-exp under a default policy -> MissingExpiry, got $missing")
      accepted <- JWT.verify(tok.compact, HS256, mk, JWT.Policy("api", Set(HS256)).unexpiring, now).either
      _ <- check(accepted.exists(_.subject.contains("job-7")), s"no-exp under .unexpiring is accepted, got $accepted")
    yield ()
  }

  test("jose header-key (DPoP): round-trip returns the claims and the binding JWK; typ / jwk / embedded-key enforced") {
    val claims = JWT.Claims.empty.id("jti-9").claim("htm", JoseValue.Str("POST")).expiresIn(1.hour)
    val policy = JWT.Policy.unaudienced(Set(EdDSA))
    for
      kp <- Ed25519.generate.absolve
      other <- Ed25519.generate.absolve
      proof <- JWT.sign(claims, EdDSA, "dpop+jwt", kp.publicKey, now)(kp.privateKey).absolve
      res <- expectRight("dpop verify")(JWT.verifyWithHeaderKey(proof.compact, "dpop+jwt", policy, now))
      (verified, jwk) = res
      _ <- check(
             verified.id.contains("jti-9") && verified.claims.get("htm").contains(JoseValue.Str("POST")),
             s"header-keyed verify returns the claims, got $verified"
           )
      // the returned key is the caller's binding handle: its thumbprint equals the signing key's (DPoP cnf.jkt)
      _ <- jwk.key match
             case ImportedPublicKey.Ed(pub) =>
               for
                 t1 <- expectRight("returned tp")(pub.thumbprint)
                 t2 <- expectRight("signing tp")(kp.publicKey.thumbprint)
                 _ <- check(t1.constantTimeEquals(t2), "returned-key thumbprint == signing-key thumbprint (cnf.jkt)")
               yield ()
             case _ => check(false, "the embedded key dispatched to the Ed arm")
      wrongTyp <- JWT.verifyWithHeaderKey(proof.compact, "jwt", policy, now).either
      _ <- check(wrongTyp == Left(JWT.TypeMismatch), s"wrong typ -> TypeMismatch, got $wrongTyp")
      craftedNoJwk =
        val h = Base64Url.encode("""{"alg":"EdDSA","typ":"dpop+jwt"}""".getBytes("UTF-8"))
        val p = Base64Url.encode("{}".getBytes("UTF-8"))
        s"$h.$p.${Base64Url.encode(new Array[Byte](64))}"
      noJwk <- JWT.verifyWithHeaderKey(craftedNoJwk, "dpop+jwt", policy, now).either
      _ <- check(noJwk == Left(JWT.MissingHeaderKey), s"typ present but no jwk member -> MissingHeaderKey, got $noJwk")
      // a proof signed by one key but embedding a different same-family key fails under its own header key
      lying <- JWT.sign(claims, EdDSA, "dpop+jwt", other.publicKey, now)(kp.privateKey).absolve
      liar <- JWT.verifyWithHeaderKey(lying.compact, "dpop+jwt", policy, now).either
      _ <- check(liar == Left(JWT.BadSignature), s"embedded key that did not sign -> BadSignature, got $liar")
    yield ()
    end for
  }

  // RFC 9449 section 4.1 example DPoP proof (compact JWS + its embedded EC P-256 jwk). It verifies
  // under its own header key; iat = 1562262616, no exp -> unaudienced + unexpiring (DPoP freshness is
  // the caller's iat window). The signature was independently confirmed to validate (ECDSA P-256).
  test("RFC 9449 section 4.1 DPoP proof verifies under its embedded header key") {
    val proof =
      "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZy" +
        "aHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VO" +
        "SmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwi" +
        "aHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYy" +
        "NjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
    val iat = 1562262616L
    for
      v <- JWT.verifyWithHeaderKey(proof, "dpop+jwt", JWT.Policy.unaudienced(Set(ES256)).unexpiring, iat).either
      _ <- check(
             v.exists((verified, _) => verified.id.contains("-BwC3ESc6acc2lTc") && verified.claims.get("htm").contains(JoseValue.Str("POST"))),
             s"RFC 9449 section 4.1 proof verifies under its embedded key, got $v"
           )
    yield ()
  }

  test("a cross-family header key does not compile (EdDSA alg + P-256 headerKey)") {
    check(
      !typeChecks("""JWT.sign(JWT.Claims.empty, EdDSA, "dpop+jwt", xfamP256Pub, 0L)(xfamEdPriv)"""),
      "a cross-family header key must not typecheck"
    )
  }
end JoseVerificationSuite
