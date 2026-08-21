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
import kufuli.tests.support.*

class FormatRoundTripSuite extends munit.CatsEffectSuite:

  private val msg = Slice.of("the-message".getBytes)

  test("an Ed25519 export feeds its parse door with no tag call, and the reimport OPERATES") {
    for
      kp <- Ed25519.generate.absolve
      sig <- kp.privateKey.sign(msg).absolve
      spki <- expectRight("spki")(kp.publicKey.spki)
      pub2 <- expectRight("reimport spki")(PublicKey.parse(Ed25519)(spki))
      _ <- expectRight("verify via reimport")(pub2.verify(msg, sig))
      raw <- expectRight("raw")(kp.publicKey.raw)
      pub3 <- expectRight("reimport raw")(PublicKey.parse(Ed25519)(raw))
      _ <- expectRight("verify via raw reimport")(pub3.verify(msg, sig))
      pkcs8 <- expectRight("pkcs8")(kp.privateKey.pkcs8)
      priv2 <- expectRight("reimport pkcs8")(PrivateKey.parse(Ed25519)(pkcs8))
      sig2 <- priv2.sign(msg).absolve
      _ <- expectRight("verify sig from reimported private")(kp.publicKey.verify(msg, sig2))
    yield ()
  }

  test("a P-256 export feeds its parse door typed, and the ECDSA DER round trip is typed end to end") {
    for
      kp <- P256.generate.absolve
      sig <- kp.privateKey.sign(msg).absolve
      sec1 <- expectRight("sec1")(kp.publicKey.sec1)
      pub2 <- expectRight("reimport sec1")(PublicKey.parse(P256)(sec1))
      _ <- expectRight("verify via sec1 reimport")(pub2.verify(msg, sig))
      der = sig.der
      back <- expectRight("der parse")(Eff.from(Signature.parse(P256)(der)))
      _ <- expectRight("verify the der round trip")(kp.publicKey.verify(msg, back))
    yield ()
  }

  test("an X25519 raw export re-imports and agrees to the same shared secret") {
    for
      a <- X25519.generate.absolve
      b <- X25519.generate.absolve
      raw <- expectRight("raw")(b.publicKey.raw)
      b2 <- expectRight("reimport")(PublicKey.parse(X25519)(raw))
      s1 <- a.privateKey.agree(b.publicKey).absolve
      s2 <- a.privateKey.agree(b2).absolve
      k1 <- s1.deriveKey(Sha256, Slice.empty, Slice.of("ctx".getBytes), AesGcm256).absolve
      k2 <- s2.deriveKey(Sha256, Slice.empty, Slice.of("ctx".getBytes), AesGcm256).absolve
      box <- k1.seal(msg).absolve
      opened <- expectRight("open under the re-imported agreement")(k2.open(box))
      _ <- check(java.util.Arrays.equals(opened.toArray, msg.toArray), "same shared secret")
    yield ()
  }

  test("a PEM private-key block round-trips into the pkcs8 door with no tag call between") {
    for
      kp <- Ed25519.generate.absolve
      pkcs8 <- expectRight("pkcs8")(kp.privateKey.pkcs8)
      text = PEM.encode(PEM.Block.PrivateKey(pkcs8))
      block <- expectRight("decode")(Eff.from(PEM.decode(text)))
      priv2 <- block match
                 case PEM.Block.PrivateKey(key) => expectRight("parse")(PrivateKey.parse(Ed25519)(key))
                 case other                     => munit.Assertions.fail(s"expected the PrivateKey arm, got $other")
      sig <- priv2.sign(msg).absolve
      _ <- expectRight("operates")(kp.publicKey.verify(msg, sig))
    yield ()
  }

  test("an unknown PEM label survives as Other, verbatim, through a mixed container") {
    for
      kp <- Ed25519.generate.absolve
      spki <- expectRight("spki")(kp.publicKey.spki)
      mixed = PEM.encode(PEM.Block.Other("X509 CRL", IArray[Byte](9, 9))) + "\n" + PEM.encode(PEM.Block.PublicKey(spki))
      blocks <- expectRight("decodeAll")(Eff.from(PEM.decodeAll(mixed)))
      _ <- check(
             blocks match
               case PEM.Block.Other("X509 CRL", d) :: PEM.Block.PublicKey(_) :: Nil => d.length == 2
               case _                                                               => false
             ,
             "the container classifies in order and keeps the unknown label readable"
           )
    yield ()
  }
end FormatRoundTripSuite
