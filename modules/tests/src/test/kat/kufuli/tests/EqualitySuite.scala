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

class EqualitySuite extends munit.CatsEffectSuite:

  test("a JWK parsed twice from one document compares equal (document identity)") {
    for
      kp <- Ed25519.generate.absolve
      jwk <- expectRight("of")(JWK.of("kid-1", kp.publicKey))
      a <- expectRight("parse 1")(JWK.parse(jwk.json))
      b <- expectRight("parse 2")(JWK.parse(jwk.json))
      _ <- check(a == b, "one document, one value")
      again <- expectRight("of again")(JWK.of("kid-1", kp.publicKey))
      _ <- check(jwk == again, "one key and kid, one published document")
    yield ()
  }

  test("a JwkSet round-tripped through its json compares equal") {
    for
      kp <- Ed25519.generate.absolve
      jwk <- expectRight("of")(JWK.of("kid-1", kp.publicKey))
      set = JwkSet(jwk)
      re <- expectRight("reparse")(JwkSet.parse(set.json))
      _ <- check(set == re, "the set is its document")
    yield ()
  }

  test("identically-configured policies compare equal, and a named opt-out breaks the equality") {
    val a = JWT.Policy("api", ES256).issuer("https://issuer.example")
    val b = JWT.Policy("api", ES256).issuer("https://issuer.example")
    val c = JWT.Policy("api", ES256).issuer("https://issuer.example").unexpiring
    for
      _ <- check(a == b, "same five components, same policy")
      _ <- check(a != c, "unexpiring is a different policy")
    yield ()
  }

  private val certPem = """-----BEGIN CERTIFICATE-----
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

  test("one certificate parsed twice compares equal by its DER, and VerifiedPath inherits it") {
    val a = x5.Certificate.parse(certPem)
    val b = x5.Certificate.parse(certPem)
    for
      _ <- check(a.isRight && a == b, "one DER, one value")
      _ <- check(a.toOption.zip(b.toOption).exists(_ == _), "the values compare equal directly")
    yield ()
  }

  // The executed fact JWK equality is implemented for rather than withheld: collection membership
  // never consults CanEqual, so a withheld instance would not have stopped `contains` - it would
  // only have made it silently reference-based.
  test("collection membership over Digest compiles and behaves despite the withheld CanEqual") {
    for
      d <- Sha256.digest(Slice.of("x".getBytes)).absolve
      ds = List(d)
      _ <- check(ds.contains(d), "membership on the same value")
    yield ()
  }
end EqualitySuite
