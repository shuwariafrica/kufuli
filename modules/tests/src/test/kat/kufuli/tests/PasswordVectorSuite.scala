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

class PasswordVectorSuite extends munit.CatsEffectSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  // The reference vector below, encoded to PHC on the JVM (BouncyCastle).
  private val jvmProducedPhc =
    "$argon2id$v=19$m=512,t=3,p=1$AgICAgICAgICAgICAgICAg$zJ3cVXILOjRG0mQdTE5AQYvj4vQBlDsS8e0/JD7VIXA"

  test("Argon2id == OpenSSL 3.5 reference vector (pass=password, salt=16x02, m=512, t=3, p=1)") {
    val a = summon[Argon2]
    val params = Argon2Params.of(512, 3, 1).toOption.get
    for
      out <- a.hash(Slice.of("password".getBytes), Slice.of(Array.fill(16)(0x02.toByte)), params).absolve
      _ <- check(hex(out) == "cc9ddc55720b3a3446d2641d4c4e40418be3e2f401943b12f1ed3f243ed52170", "argon2id vector")
    yield ()
  }

  test("password: Argon2id login flow (PHC parse, verify, policy rehash)") {
    for
      stored <- "correct horse".hash(Argon2Params.interactive).absolve
      parsed = PasswordHash.of(stored.value)
      _ <- check(parsed.isRight, "PHC parses")
      good <- "correct horse".verify(parsed.toOption.get, Argon2Params.interactive).absolve
      _ <- check(good match
                   case PasswordCheck.Verified(None) => true;
                   case _                            => false
                 ,
                 "correct password, no rehash"
           )
      bad <- "wrong".verify(parsed.toOption.get, Argon2Params.interactive).absolve
      _ <- check(bad == PasswordCheck.Rejected, "wrong password rejected")
      rehash <- "correct horse".verify(parsed.toOption.get, Argon2Params.default).absolve
      _ <- check(rehash match
                   case PasswordCheck.Verified(Some(_)) => true;
                   case _                               => false
                 ,
                 "stronger policy -> rehash"
           )
    yield ()
  }

  test("password: a JVM-produced PHC hash verifies on this backend (hash-on-JVM/verify-here)") {
    val stored = PasswordHash.of(jvmProducedPhc).toOption.get
    val policy = Argon2Params.of(512, 3, 1).toOption.get
    for
      good <- "password".verify(stored, policy).absolve
      _ <- check(good == PasswordCheck.Verified(None), "cross-backend verify")
      bad <- "wrong".verify(stored, policy).absolve
      _ <- check(bad == PasswordCheck.Rejected, "wrong password rejected cross-backend")
    yield ()
  }
  test("a stored PHC column has exactly one spelling") {
    val ok = jvmProducedPhc
    assert(PasswordHash.of(ok).isRight, "the canonical column parses")
    assert(PasswordHash.of(ok + "$").isLeft, "a trailing separator is not a second spelling of it")
    assert(PasswordHash.of(ok.replace("m=512,", "m=512,x=9,")).isLeft, "an unknown parameter is refused")
    assert(PasswordHash.of(ok.replace("m=512,", "m=512,m=8,")).isLeft, "a repeated one leaves the cost to the reader")
    assert(PasswordHash.of(ok.replace("m=512,t=3,p=1", "t=3,m=512,p=1")).isLeft, "and so does a reordered list")
    assert(PasswordHash.of(ok.replace("m=512", "m=0512")).isLeft, "a non-canonical decimal is refused")
    assert(PasswordHash.of(ok.dropRight(4)).isLeft, "a tag of another width could never match a recomputation")
    assert(PasswordHash.of(ok) == PasswordHash.of(ok), "one column compares equal to itself")
  }

  test("a stored PHC column with a salt no conformant hasher produces is refused at parse") {
    val short = "$argon2id$v=19$m=512,t=3,p=1$AgICAgIC$zJ3cVXILOjRG0mQdTE5AQYvj4vQBlDsS8e0/JD7VIXA"
    val floor = "$argon2id$v=19$m=512,t=3,p=1$AgICAgICAgI$zJ3cVXILOjRG0mQdTE5AQYvj4vQBlDsS8e0/JD7VIXA"
    assert(PasswordHash.of(short).isLeft, "a 6-byte salt is below Argon2's own minimum")
    assert(PasswordHash.of(floor).isRight, "an 8-byte salt is at the minimum and parses")
    assert(PasswordHash.of(jvmProducedPhc).isRight, "a 16-byte salt is unaffected")
  }

  test("Argon2 parameters are validated at their edges, not merely at the presets") {
    assert(Argon2Params.of(8, 1, 1).isRight, "memory at exactly 8x the lane count is the floor Argon2 states")
    assert(Argon2Params.of(7, 1, 1).isLeft, "a kibibyte below it is refused")
    assert(Argon2Params.of(2040, 1, 255).isRight, "255 lanes is the widest the format encodes")
    assert(Argon2Params.of(2048, 1, 256).isLeft, "256 is one past it")
    assert(Argon2Params.of(8, 0, 1).isLeft, "a pass count of zero hashes nothing")
    assert(Argon2Params.of(8, 1, 0).isLeft, "and no lanes is not a configuration")
  }
end PasswordVectorSuite
