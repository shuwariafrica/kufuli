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

  private def hx(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  private def parse(json: String): Js = readFromString[Js](json)

  // FIPS 203 KeyGen and Decaps against the published (seed, ek, c, K) quadruples: the seed import is
  // the only way to reach a decapsulation key, so without it these vectors are unexercisable. Every
  // `invalid` case in this corpus is a seed or ciphertext length violation, which kufuli refuses at
  // its own typed constructors.
  private def runMlKem[K <: KemAlgorithm](json: String, spec: KemSpec[K])(using keys: KemKeys[K], kem: KEM[K]): IO[Unit] =
    val cases = for
      g <- parse(json).field("testGroups").arr.toList
      t <- g.field("tests").arr.toList
    yield (t.field("seed").str, t.field("c").str, t.field("result").str, t.field("tcId").int, t)
    check(cases.nonEmpty, s"ML-KEM corpus for ${spec.publicKeyLength}-byte keys is empty - vector embedding failed") *> cases
      .traverse { (seed, c, res, tc, t) =>
        if res != "valid" then
          val rejected = hb(seed).length != 64 || KemCiphertext.of(spec)(hb(c)).isLeft
          IO.pure(Option.unless(rejected)(s"tc$tc accepted a length-invalid vector"))
        else
          val ct = KemCiphertext.of(spec)(hb(c)).toOption.get
          for
            kp <- keys.fromSeed(Slice.of(hb(seed))).either.absolve
            pair <- IO.fromOption(kp.toOption)(new AssertionError(s"tc$tc seed import failed: $kp"))
            ek <- keys.raw(pair.publicKey).absolve
            shared <- kem.decapsulate(pair.privateKey, ct).absolve
            secret <- shared.use(s => hx(s.toArray)).absolve
          yield Option
            .when(hx(Array.from(ek.iterator)) != t.field("ek").str)(s"tc$tc ek mismatch")
            .orElse(Option.when(secret != t.field("K").str)(s"tc$tc shared secret mismatch"))
      }
      .flatMap(rs => check(rs.flatten.isEmpty, s"${rs.flatten.size} mismatches: ${rs.flatten.take(6).mkString("; ")}"))
  end runMlKem

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
    AEAD[A]
  ): IO[Option[Array[Byte]]] =
    SecretKey.of(spec)(k) match
      case Left(_)    => IO.pure(None)
      case Right(key) =>
        summon[AEAD[A]].open(key, Nonce.unsafe[A](iv), Slice.of(aad), Slice.of(ctTag)).either.absolve.map(_.toOption.map(_.toArray))

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
        PublicKey.parse(P256)(SEC1(Slice.of(hb(point)))).either.absolve.flatMap {
          case Right(k) =>
            Signature.of(P256)(hb(sig)) match
              case Right(s) => k.verify(Slice.of(hb(msg)), s).either.absolve.map(_.isRight)
              case Left(_)  => IO.pure(false)
          case Left(_) => IO.pure(false)
        }
    )
  }

  test("Wycheproof ML-KEM-768/1024: FIPS 203 KeyGen and Decaps over the published seeds") {
    runMlKem(Mlkem768TestJson.json, MlKem768) *> runMlKem(Mlkem1024TestJson.json, MlKem1024)
  }

  test("Wycheproof Ed25519: verify corpus") {
    runVerify(
      Ed25519TestJson.json,
      g => g.field("publicKey").field("pk").str,
      (pk, msg, sig) =>
        PublicKey.parse(Ed25519)(Raw(Slice.of(hb(pk)))).either.absolve.flatMap {
          case Right(k) =>
            Signature.of(Ed25519)(hb(sig)) match
              case Right(s) => k.verify(Slice.of(hb(msg)), s).either.absolve.map(_.isRight)
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
