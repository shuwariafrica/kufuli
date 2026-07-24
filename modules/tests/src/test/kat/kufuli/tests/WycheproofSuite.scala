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

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.effect.*
import cats.effect.IO
import cats.syntax.all.*
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.*
import kufuli.tests.support.*
import kufuli.tests.wycheproof.*

class WycheproofSuite extends munit.CatsEffectSuite:

  private def hb(s: String): Array[Byte] =
    if s.isEmpty then Array.emptyByteArray else s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private def parse(json: String): Js = readFromString[Js](json)

  private def runVerify(json: String, key: Js => String, verify: (String, String, String) => IO[Boolean]): IO[Unit] =
    val cases = for
      g <- parse(json).field("testGroups").arr.toList
      material = key(g)
      t <- g.field("tests").arr.toList
      res = t.field("result").str
      if res == "valid" || res == "invalid"
    yield (material, t.field("msg").str, t.field("sig").str, res, t.field("tcId").int)
    // Guard against a silently empty corpus (a failed vector embedding would otherwise pass vacuously).
    check(cases.nonEmpty, "wycheproof verify corpus is empty - vector embedding failed") *> cases
      .traverse((material, msg, sig, res, tc) =>
        // A raise (a backend rejecting a malformed key or signature) is a rejection: correct for an
        // `invalid` vector, a real defect only for a `valid` one.
        verify(material, msg, sig).attempt.map {
          case Right(accepted) => Option.when(accepted != (res == "valid"))(s"tc$tc expected=$res accepted=$accepted")
          case Left(_)         => Option.when(res == "valid")(s"tc$tc raised on a valid vector")
        }
      )
      .flatMap(rs => check(rs.flatten.isEmpty, s"${rs.flatten.size} mismatches: ${rs.flatten.take(6).mkString("; ")}"))
  end runVerify

  private def openGcm[A <: AeadAlgorithm](spec: AeadSpec[A], k: Array[Byte], iv: Array[Byte], aad: Array[Byte], ctTag: Array[Byte])(using
    Aead[A]
  ): IO[Option[Array[Byte]]] =
    SecretKey.of(spec)(k) match
      case Left(_)    => IO.pure(None)
      case Right(key) =>
        summon[Aead[A]].open(key, Nonce.unsafe[A](iv), Slice.of(aad), Slice.of(ctTag)).either.map(_.toOption.map(_.toArray))

  // Restricted to the 96-bit-nonce / 128-bit-tag groups the EVP_AEAD ciphers accept.
  private def runAead(json: String, open: (Int, Array[Byte], Array[Byte], Array[Byte], Array[Byte]) => IO[Option[Array[Byte]]]): IO[Unit] =
    val cases = for
      g <- parse(json).field("testGroups").arr.toList
      if g.field("ivSize").int == 96 && g.field("tagSize").int == 128
      keySize = g.field("keySize").int
      t <- g.field("tests").arr.toList
      res = t.field("result").str
      if res == "valid" || res == "invalid"
    yield (keySize,
           t.field("key").str,
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
    check(cases.nonEmpty, "wycheproof aead corpus is empty - vector embedding failed") *> cases
      .traverse { (keySize, key, iv, aad, msg, ct, tag, res, tc) =>
        open(keySize, hb(key), hb(iv), hb(aad), hb(ct) ++ hb(tag)).attempt.map {
          case Right(opened) =>
            val pass = if res == "valid" then opened.exists(_.sameElements(hb(msg))) else opened.isEmpty
            Option.when(!pass)(s"tc$tc expected=$res")
          case Left(_) => Option.when(res == "valid")(s"tc$tc raised on a valid vector")
        }
      }
      .flatMap(rs => check(rs.flatten.isEmpty, s"${rs.flatten.size} mismatches: ${rs.flatten.take(6).mkString("; ")}"))
  end runAead

  test("Wycheproof AES-GCM: decrypt/verify (auth-bypass) corpus, 96-bit nonce") {
    runAead(
      AesGcmTestJson.json,
      (keySize, k, iv, aad, ctTag) =>
        keySize match
          case 128 => openGcm(AesGcm128, k, iv, aad, ctTag)
          case 192 => openGcm(AesGcm192, k, iv, aad, ctTag)
          case _   => openGcm(AesGcm256, k, iv, aad, ctTag)
    )
  }

  test("Wycheproof ChaCha20-Poly1305: decrypt/verify (auth-bypass) corpus") {
    runAead(Chacha20Poly1305TestJson.json, (_, k, iv, aad, ctTag) => openGcm(ChaCha20Poly1305, k, iv, aad, ctTag))
  }

  test("Wycheproof ECDSA secp256r1 p1363 (raw r||s): verify corpus, sign-elsewhere/verify-here") {
    runVerify(
      EcdsaSecp256r1Sha256P1363TestJson.json,
      g => g.field("publicKey").field("uncompressed").str,
      (point, msg, sig) =>
        PublicKey.fromSec1(P256)(Slice.of(hb(point))).either.flatMap {
          case Right(k) =>
            Signature.fromRaw(P256)(hb(sig)) match
              case Right(s) => k.verify(Slice.of(hb(msg)), s).either.map(_.isRight)
              case Left(_)  => IO.pure(false)
          case Left(_) => IO.pure(false)
        }
    )
  }

  test("Wycheproof Ed25519: verify corpus") {
    runVerify(
      Ed25519TestJson.json,
      g => g.field("publicKey").field("pk").str,
      (pk, msg, sig) =>
        PublicKey.fromRaw(Ed25519)(Slice.of(hb(pk))).either.flatMap {
          case Right(k) =>
            Signature.fromRaw(Ed25519)(hb(sig)) match
              case Right(s) => k.verify(Slice.of(hb(msg)), s).either.map(_.isRight)
              case Left(_)  => IO.pure(false)
          case Left(_) => IO.pure(false)
        }
    )
  }
end WycheproofSuite

// Hand-written over jsoniter-scala-core (no macros, so it links on Native); decode-only.
private enum Js:
  case S(v: String)
  case N(v: Double)
  case B(v: Boolean)
  case Nul
  case A(v: Vector[Js])
  case O(v: Map[String, Js])

private object Js:
  given codec: JsonValueCodec[Js] = new JsonValueCodec[Js]:
    def nullValue: Js = Js.Nul
    def encodeValue(x: Js, out: JsonWriter): Unit = sys.error("Wycheproof Js is decode-only")
    def decodeValue(in: JsonReader, default: Js): Js =
      if in.isNextToken('n') then in.readNullOrError(Js.Nul, "expected value")
      else
        in.rollbackToken()
        in.nextToken() match
          case '"'       => in.rollbackToken(); Js.S(in.readString(""))
          case 't' | 'f' => in.rollbackToken(); Js.B(in.readBoolean())
          case '['       =>
            val elems = Vector.newBuilder[Js]
            if !in.isNextToken(']') then
              in.rollbackToken()
              @tailrec def loop(): Unit =
                val _ = elems += decodeValue(in, default)
                if in.isNextToken(',') then loop()
              loop()
              if !in.isCurrentToken(']') then in.arrayEndOrCommaError()
            Js.A(elems.result())
          case '{' =>
            val fields = Map.newBuilder[String, Js]
            if !in.isNextToken('}') then
              in.rollbackToken()
              @tailrec def loop(): Unit =
                val k = in.readKeyAsString()
                val _ = fields += (k -> decodeValue(in, default))
                if in.isNextToken(',') then loop()
              loop()
              if !in.isCurrentToken('}') then in.objectEndOrCommaError()
            Js.O(fields.result())
          case _ => in.rollbackToken(); Js.N(in.readDouble())
        end match

  extension (j: Js)
    def field(k: String): Js = j match
      case Js.O(m) => m.getOrElse(k, Js.Nul)
      case _       => Js.Nul
    def arr: Vector[Js] = j match
      case Js.A(v) => v
      case _       => Vector.empty
    def str: String = j match
      case Js.S(s) => s
      case _       => ""
    def int: Int = j match
      case Js.N(n) => n.toInt
      case _       => 0
  end extension
end Js
