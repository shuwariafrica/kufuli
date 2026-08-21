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

import boilerplate.testkit.ValueCodecLaws
import org.scalacheck.Arbitrary
import org.scalacheck.Gen

import kufuli.jose.*
import kufuli.x509 as x5

// The published law machinery is the substrate's; kufuli supplies generators built from its own
// doors, so every instance is pinned by round-trip, canonical-encode and (where the decode
// normalises) idempotence laws on every KAT row.
class CodecLawsSuite extends munit.ScalaCheckSuite with ValueCodecLaws:

  private val algs: List[JwsAlg] = List(ES256, ES384, ES512, EdDSA, PS256, RS256, HS256, HS384, HS512)
  private given Arbitrary[JwsAlg] = Arbitrary(Gen.oneOf(algs))
  valueCodecLaws[JwsAlg]("JwsAlg")
  valueCodecNormalisation[JwsAlg]("JwsAlg", Gen.oneOf(algs.map(_.name) ++ List("EdDSA", "none", "es256")))

  private val labelGen: Gen[String] =
    for
      head <- Gen.alphaLowerChar
      tail <- Gen.stringOfN(4, Gen.oneOf(Gen.alphaLowerChar, Gen.numChar))
    yield s"$head$tail"
  private val hostnameGen: Gen[x5.Hostname] =
    Gen.chooseNum(1, 3).flatMap(n => Gen.listOfN(n, labelGen)).map(ls => x5.Hostname.parse(ls.mkString(".") + ".example").toOption.get)
  private given Arbitrary[x5.Hostname] = Arbitrary(hostnameGen)
  valueCodecLaws[x5.Hostname]("Hostname")
  valueCodecNormalisation[x5.Hostname]("Hostname", hostnameGen.map(h => x5.Hostname.value(h).toUpperCase))

  private val ipGen: Gen[x5.IpAddress] =
    Gen
      .oneOf(
        Gen.listOfN(4, Gen.chooseNum(0, 255)).map(_.map(_.toByte).toArray),
        Gen.listOfN(16, Gen.chooseNum(0, 255)).map(_.map(_.toByte).toArray)
      )
      .map(bs => x5.IpAddress.of(boilerplate.Slice.of(bs)).toOption.get)
  private given Arbitrary[x5.IpAddress] = Arbitrary(ipGen)
  valueCodecLaws[x5.IpAddress]("IpAddress")

  private given Arbitrary[x5.ServerId] =
    Arbitrary(Gen.oneOf(hostnameGen.map(x5.ServerId.Dns(_)), ipGen.map(x5.ServerId.Ip(_))))
  valueCodecLaws[x5.ServerId]("ServerId")

  // No `PasswordHash` row: the type ships no ValueCodec. Its cost parameters are what `verify`
  // recomputes at, so a generic scalar binder must not be able to decode one - see the door.
end CodecLawsSuite
