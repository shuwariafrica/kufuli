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
import kufuli.password.*
import kufuli.tests.support.*

class EnvelopeSuite extends munit.CatsEffectSuite:

  private val passphrase = Slice.of("password".getBytes)
  private val salt = Slice.of(Array.fill[Byte](16)(0x02))
  private val params = Argon2Params.of(512, 3, 1).toOption.get
  private val declaration = Slice.of("secret:billing/api-token".getBytes)

  test("a passphrase-derived key is anchored to the argon2id reference vector on every backend") {
    // The tag is HMAC-SHA256 over "kufuli-derive-kat" under the PUBLISHED argon2id vector output
    // (the PasswordVectorSuite vector), computed with independent tooling. One expectation for all
    // three rows, so a divergent backend fails its own lane.
    for
      key <- expectRight("derive")(Argon2.deriveKey(passphrase, salt, params, HmacSha256))
      tag <- key.sign(Slice.of("kufuli-derive-kat".getBytes)).absolve
      _ <- check(
             Array.from(tag.bytes.iterator).map(b => f"${b & 0xff}%02x").mkString ==
               "e65a2d72f6b62a35a9436b88e77d3c7634cd0e0e92440c9f79e587149c267d13",
             "derived-key tag matches the vector-anchored expectation"
           )
    yield ()
  }

  test("the envelope round-trips across a simulated restart, and the declaration AAD detects a swap") {
    for
      root <- expectRight("root")(Argon2.deriveKey(passphrase, salt, params, AesKw256))
      dataKey <- AesGcm256.generate.absolve
      wrapped <- expectRight("wrap")(root.wrap(dataKey))
      box <- dataKey.seal(Slice.of("db-password-value".getBytes), declaration).absolve
      root2 <- expectRight("re-derive")(Argon2.deriveKey(passphrase, salt, params, AesKw256))
      dk2 <- expectRight("unwrap")(root2.unwrap(wrapped, AesGcm256))
      opened <- expectRight("open")(dk2.open(box, declaration))
      _ <- check(java.util.Arrays.equals(opened.toArray, "db-password-value".getBytes), "round trip across restart")
      swapped <- dk2.open(box, Slice.of("secret:other/declaration".getBytes)).either.absolve
      _ <- check(swapped == Left(AuthFailed), "a ciphertext swapped between declarations fails authentication")
    yield ()
  }

  test("a wrong passphrase derives a key that fails closed at unwrap") {
    for
      root <- expectRight("root")(Argon2.deriveKey(passphrase, salt, params, AesKw256))
      dataKey <- AesGcm256.generate.absolve
      wrapped <- expectRight("wrap")(root.wrap(dataKey))
      other <- expectRight("other root")(Argon2.deriveKey(Slice.of("not the passphrase".getBytes), salt, params, AesKw256))
      bad <- other.unwrap(wrapped, AesGcm256).either.absolve
      _ <- check(bad.isLeft, s"a wrong root refuses the wrapped key, got $bad")
    yield ()
  }

  test("the argon2 salt floor is a typed refusal, not a raise") {
    Argon2
      .deriveKey(passphrase, Slice.of("shrt".getBytes), params, AesKw256)
      .either
      .absolve
      .flatMap(r => check(r == Left(InvalidParams), s"a sub-floor salt is InvalidParams, got $r"))
  }

  test("a borrowing module applies a key through a handle; after destroy the handle raises") {
    for
      key <- expectRight("key")(Eff.from(SecretKey.of(HmacSha256)(Array.tabulate[Byte](32)(i => (i * 5).toByte))))
      tag <- key.signer.use(_.sign(Slice.of("audit-line".getBytes))).absolve
      _ <- expectRight("verify")(key.verify(Slice.of("audit-line".getBytes), tag))
      _ <- key.destroy.absolve
      late <- key.signer.use(_.sign(Slice.of("late".getBytes))).absolve.attempt
      _ <- check(late.isLeft, "the release-ordering contract: a destroyed key's handle raises, never signs")
    yield ()
  }
end EnvelopeSuite
