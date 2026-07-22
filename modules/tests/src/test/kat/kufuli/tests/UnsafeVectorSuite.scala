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
import cats.effect.IO

import kufuli.tests.support.*
import kufuli.unsafe.*

class UnsafeVectorSuite extends munit.CatsEffectSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"$x%02x").mkString
  private def hb(s: String): Array[Byte] = s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  test("AesBlock: FIPS 197 C.1 single-block AES-128") {
    AesBlock
      .of(hb("000102030405060708090a0b0c0d0e0f"))
      .use(block =>
        IO {
          val out = new Array[Byte](16)
          block.encrypt(Slice.of(hb("00112233445566778899aabbccddeeff")), Slice.of(out))
          out
        }
      )
      .flatMap(out => check(hex(out) == "69c4e0d86a7b0430d8cdb78070b4c55a", "aes block"))
  }

  test("ChaCha20 keystream: RFC 8439 section 2.3.2 block (counter 1)") {
    ChaCha20
      .of(hb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
      .use(stream =>
        IO {
          val out = new Array[Byte](64)
          stream.keystream(Slice.of(out), Slice.of(hb("000000090000004a00000000")), 1)
          out
        }
      )
      .flatMap(out =>
        check(
          hex(out) == "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
          "chacha keystream"
        )
      )
  }

  test("HeaderProtection.aes: RFC 9001 A.2 QUIC mask") {
    HeaderProtection
      .aes(hb("9f50449e04a0e810283a1e9933adedd2"))
      .use(hp =>
        IO {
          val out = new Array[Byte](5)
          hp.mask(Slice.of(hb("d1b1c98dd7689fb8ec11d242b123dc9b")), Slice.of(out))
          out
        }
      )
      .flatMap(out => check(hex(out) == "437b9aec36", "aes hp mask"))
  }

  test("HeaderProtection.chacha: RFC 9001 A.5 QUIC mask") {
    HeaderProtection
      .chacha(hb("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"))
      .use(hp =>
        IO {
          val out = new Array[Byte](5)
          hp.mask(Slice.of(hb("5e5cd55c41f69080575d7999c25a5bfb")), Slice.of(out))
          out
        }
      )
      .flatMap(out => check(hex(out) == "aefefe7d03", "chacha hp mask"))
  }
end UnsafeVectorSuite
