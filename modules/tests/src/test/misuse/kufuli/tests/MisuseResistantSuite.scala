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
import cats.effect.IO
import cats.syntax.all.*
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.*
import kufuli.tests.support.*
import kufuli.tests.wycheproof.*

// The misuse-resistant AEAD tier. aws-lc is the only engine kufuli ships that carries
// XChaCha20-Poly1305 and AES-256-GCM-SIV, so this source set belongs to the Native row alone: it is
// not a platform-variance directory but the test set of a capability grouping of one, and the README
// tells consumers to prefer these two for sealing at volume.
class MisuseResistantSuite extends munit.CatsEffectSuite:

  private def hb(s: String): Array[Byte] =
    if s.isEmpty then Array.emptyByteArray else s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private def hx(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  private def parse(json: String): Js = readFromString[Js](json)

  // Every published (key, nonce, aad, msg, ct, tag) row of the corpus, at the one key size and nonce
  // width kufuli's spec fixes. `seal` is driven forward against the published ciphertext and `open`
  // backward against the plaintext, so a backend that agreed with itself but not with the standard
  // fails here rather than round-tripping happily.
  private def vectors[A <: AeadAlgorithm](json: String, spec: AeadSpec[A])(using AEAD[A]): IO[Unit] =
    val cases = for
      g <- parse(json).field("testGroups").arr.toList
      if g.field("keySize").int == spec.keyLength * 8 && g.field("ivSize").int == spec.nonceLength * 8 &&
        g.field("tagSize").int == spec.tagLength * 8
      t <- g.field("tests").arr.toList
      res = t.field("result").str
      if res == "valid" || res == "invalid"
    yield (t.field("key").str,
           t.field("iv").str,
           t.field("aad").str,
           t.field("msg").str,
           t.field("ct").str,
           t.field("tag").str,
           res,
           t
             .field("tcId")
             .int
    )
    check(cases.nonEmpty,
          s"the corpus at key ${spec.keyLength * 8} / nonce ${spec.nonceLength * 8} is empty - vector embedding failed"
    ) *> cases
      .traverse { (key, iv, aad, msg, ct, tag, res, tc) =>
        val k = SecretKey.of(spec)(hb(key)).toOption.get
        val ad = Slice.of(hb(aad))
        val whole = hb(ct) ++ hb(tag)
        for
          opened <- k.open(Nonce.unsafe[A](hb(iv)), ad, Slice.of(whole)).either.absolve
          sealedOut <-
            if res == "valid" then k.seal(Nonce.unsafe[A](hb(iv)), ad, Slice.of(hb(msg))).absolve.map(s => Some(hx(s.toArray)))
            else IO.pure(None)
        yield Option
          .when(res == "valid" && !opened.exists(p => hx(p.toArray) == msg))(s"tc$tc open did not recover the published plaintext")
          .orElse(Option.when(res == "invalid" && opened.isRight)(s"tc$tc opened a vector the corpus marks invalid"))
          .orElse(sealedOut.flatMap(got => Option.when(got != ct + tag)(s"tc$tc seal produced $got")))
      }
      .flatMap(rs => check(rs.flatten.isEmpty, s"${rs.flatten.size} mismatches: ${rs.flatten.take(6).mkString("; ")}"))
  end vectors

  test("XChaCha20-Poly1305: the published vectors, both directions") {
    vectors(Xchacha20Poly1305TestJson.json, XChaCha20Poly1305)
  }

  test("AES-256-GCM-SIV (RFC 8452): the published vectors, both directions") {
    vectors(AesGcmSivTestJson.json, AesGcmSiv256)
  }

  test("the misuse-resistant tier survives a repeated nonce, which is the whole reason it is here") {
    // Under AES-GCM a repeated nonce leaks the XOR of the plaintexts and the authentication key. The
    // SIV construction derives its per-message value from the plaintext, so a repeat is a confidenti-
    // ality loss bounded to revealing that two messages were equal - and XChaCha's 192-bit nonce
    // makes a random-nonce collision unreachable at any volume. Both must still be correct when the
    // caller hands the same nonce twice, which is what the record tier's budget cannot promise.
    val message = Slice.of("the same plaintext twice".getBytes)
    val aad = Slice.of("ctx".getBytes)
    for
      siv <- AesGcmSiv256.generate.absolve
      sivNonce <- Nonce.random(AesGcmSiv256).absolve
      first <- siv.seal(sivNonce, aad, message).absolve
      second <- siv.seal(sivNonce, aad, message).absolve
      _ <- check(hx(first.toArray) == hx(second.toArray), "GCM-SIV is deterministic in its nonce, as SIV requires")
      back <- expectRight("siv open")(siv.open(sivNonce, aad, first))
      _ <- check(back.toArray.sameElements(message.toArray), "and still opens what it sealed")
      x <- XChaCha20Poly1305.generate.absolve
      xNonce <- Nonce.random(XChaCha20Poly1305).absolve
      _ <- check(xNonce.repr.length == 24, s"XChaCha's nonce is 192 bits, got ${xNonce.repr.length * 8}")
      xSealed <- x.seal(xNonce, aad, message).absolve
      xBack <- expectRight("xchacha open")(x.open(xNonce, aad, xSealed))
      _ <- check(xBack.toArray.sameElements(message.toArray), "XChaCha round-trips at its own nonce width")
      other <- Nonce.random(XChaCha20Poly1305).absolve
      wrong <- x.open(other, aad, xSealed).either.absolve
      _ <- check(wrong.isLeft, s"and refuses another nonce, got $wrong")
    yield ()
    end for
  }

  test("the record tier carries the misuse-resistant algorithms too") {
    // `Ciphering` is a separate capability from `AEAD`, so the record engine for these two is its own
    // instance and its own aws-lc context: a tier advertised for sealing at volume that had no record
    // path would send a consumer back to the whole-message API for every frame.
    val plaintext = Slice.of(Array.tabulate[Byte](1300)(i => (i * 3 + 1).toByte))
    val aad = Slice.of("record".getBytes)
    for
      key <- XChaCha20Poly1305.generate.absolve
      round <- key.cipher.use { c =>
                 IO {
                   val dst = Slice.of(new Array[Byte](1400))
                   val nonce = Slice.of(Array.tabulate[Byte](24)(i => (i + 1).toByte))
                   val n = c.encrypt(dst, plaintext, aad, nonce).toOption.get
                   val out = Slice.of(new Array[Byte](1400))
                   val m = c.decrypt(out, dst.take(n), aad, nonce).toOption.get
                   out.take(m).toArray.sameElements(plaintext.toArray)
                 }
               }.absolve
      _ <- check(round, "an XChaCha record encrypts and decrypts through the budgeted engine")
      siv <- AesGcmSiv256.generate.absolve
      sivRound <- siv.cipher.use { c =>
                    IO {
                      val dst = Slice.of(new Array[Byte](1400))
                      val nonce = Slice.of(Array.tabulate[Byte](12)(i => (i + 1).toByte))
                      val n = c.encrypt(dst, plaintext, aad, nonce).toOption.get
                      val out = Slice.of(new Array[Byte](1400))
                      val m = c.decrypt(out, dst.take(n), aad, nonce).toOption.get
                      out.take(m).toArray.sameElements(plaintext.toArray)
                    }
                  }.absolve
      _ <- check(sivRound, "and so does an AES-256-GCM-SIV record")
    yield ()
    end for
  }
end MisuseResistantSuite
