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
package kufuli.jose

import scala.annotation.tailrec
import scala.annotation.targetName
import scala.concurrent.duration.FiniteDuration
import scala.util.control.NoStackTrace

import boilerplate.Slice
import boilerplate.effect.EffIO
import boilerplate.effect.UEffIO
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.*

sealed abstract class JoseError(message: String) extends Exception(message) with NoStackTrace derives CanEqual

/** A JSON value carried in a JWT's custom claims (nested objects included - DPoP's `cnf`). */
enum JoseValue derives CanEqual:
  case Str(value: String)
  case Num(value: Double)
  case Bool(value: Boolean)
  case Arr(values: List[JoseValue])
  case Obj(fields: Map[String, JoseValue])
  case Null

// JSON layer over jsoniter-scala. Emission is canonical string assembly (the RFC 7638 thumbprint
// path depends on exact member bytes); a manual streaming codec handles the untrusted parse side
// and arbitrary custom-claim values.
private object Json:
  private given codec: JsonValueCodec[JoseValue] = new JsonValueCodec[JoseValue]:
    def nullValue: JoseValue = JoseValue.Null
    // jsoniter imposes no nesting cap and the JWT payload is parsed before the signature check, so a
    // deeply nested value in an unsigned token would recurse to a StackOverflowError. Bound the depth
    // and reject as a decode error (caught as Malformed) instead.
    private inline val maxDepth = 64
    def decodeValue(in: JsonReader, default: JoseValue): JoseValue = decode(in, 0)
    private def decode(in: JsonReader, depth: Int): JoseValue =
      if in.isNextToken('n') then in.readNullOrError(JoseValue.Null, "expected value")
      else
        in.rollbackToken()
        in.nextToken() match
          case '"'       => in.rollbackToken(); JoseValue.Str(in.readString(""))
          case 't' | 'f' => in.rollbackToken(); JoseValue.Bool(in.readBoolean())
          case '['       =>
            if depth >= maxDepth then in.decodeError("nesting too deep")
            else
              val elems = List.newBuilder[JoseValue]
              if !in.isNextToken(']') then
                in.rollbackToken()
                @tailrec def loop(): Unit =
                  val _ = elems += decode(in, depth + 1)
                  if in.isNextToken(',') then loop()
                loop()
                if !in.isCurrentToken(']') then in.arrayEndOrCommaError()
              JoseValue.Arr(elems.result())
          case '{' =>
            if depth >= maxDepth then in.decodeError("nesting too deep")
            else
              val fields = Map.newBuilder[String, JoseValue]
              if !in.isNextToken('}') then
                in.rollbackToken()
                @tailrec def loop(): Unit =
                  val k = in.readKeyAsString()
                  val _ = fields += (k -> decode(in, depth + 1))
                  if in.isNextToken(',') then loop()
                loop()
                if !in.isCurrentToken('}') then in.objectEndOrCommaError()
              JoseValue.Obj(fields.result())
          case _ => in.rollbackToken(); JoseValue.Num(in.readDouble())
        end match
    def encodeValue(x: JoseValue, out: JsonWriter): Unit = x match
      case JoseValue.Str(s)  => out.writeVal(s)
      case JoseValue.Num(n)  => if n == n.toLong.toDouble then out.writeVal(n.toLong) else out.writeVal(n)
      case JoseValue.Bool(b) => out.writeVal(b)
      case JoseValue.Null    => out.writeNull()
      case JoseValue.Arr(vs) =>
        out.writeArrayStart(); vs.foreach(encodeValue(_, out)); out.writeArrayEnd()
      case JoseValue.Obj(fs) =>
        out.writeObjectStart()
        fs.toList.sortBy(_._1).foreach { (k, v) => out.writeKey(k); encodeValue(v, out) }
        out.writeObjectEnd()

  def str(s: String): String = writeToString[JoseValue](JoseValue.Str(s))
  def value(v: JoseValue): String = writeToString[JoseValue](v)
  def obj(fields: List[(String, String)]): String =
    fields.map((k, v) => s"${str(k)}:$v").mkString("{", ",", "}")
  def parse(text: String): Option[Map[String, JoseValue]] =
    try
      readFromString[JoseValue](text) match
        case JoseValue.Obj(fs) => Some(fs)
        case _                 => None
    catch case _: JsonReaderException => None
end Json

/** A JWS `alg` (RFC 7518 names verbatim), pairing the header name with what executes it: an
  * asymmetric arm carries the core [[kufuli.Scheme Scheme]] for its key algorithm, a symmetric arm
  * names its MAC. One generic sign/verify path serves every algorithm; `alg: none` is
  * unrepresentable; the arm's type parameter fixes the key type at the call site.
  */
sealed trait JWSAlg derives CanEqual:
  def name: String
object JWSAlg:
  sealed abstract class Asymmetric[K <: SignatureAlgorithm](val name: String, val scheme: Scheme[K]) extends JWSAlg
  sealed abstract class Symmetric[H <: MacAlgorithm](val name: String) extends JWSAlg

case object ES256 extends JWSAlg.Asymmetric[P256]("ES256", Ecdsa(Sha256))
case object ES384 extends JWSAlg.Asymmetric[P384]("ES384", Ecdsa(Sha384))
case object ES512 extends JWSAlg.Asymmetric[P521]("ES512", Ecdsa(Sha512))
case object EdDSA extends JWSAlg.Asymmetric[Ed25519]("EdDSA", kufuli.EdDsa)
case object PS256 extends JWSAlg.Asymmetric[Rsa]("PS256", RsaPss(Sha256))
case object RS256 extends JWSAlg.Asymmetric[Rsa]("RS256", RsaPkcs1(Sha256))
case object HS256 extends JWSAlg.Symmetric[HmacSha256]("HS256")
case object HS384 extends JWSAlg.Symmetric[HmacSha384]("HS384")
case object HS512 extends JWSAlg.Symmetric[HmacSha512]("HS512")

/** A compact-serialised JWT; sign and verify via [[JWT$ JWT]]. */
opaque type JWT = String
object JWT:
  // Payload-free rejections in the ratified class+object shape (type positions name the class).
  sealed abstract class Rejected(message: String) extends JoseError(message)
  sealed abstract class Malformed private[jose] () extends Rejected("not a JWS compact serialization")
  case object Malformed extends Malformed
  sealed abstract class BadSignature private[jose] () extends Rejected("signature verification failed")
  case object BadSignature extends BadSignature
  sealed abstract class Expired private[jose] () extends Rejected("token expired")
  case object Expired extends Expired
  sealed abstract class NotYetValid private[jose] () extends Rejected("token not yet valid")
  case object NotYetValid extends NotYetValid
  sealed abstract class IssuerMismatch private[jose] () extends Rejected("issuer mismatch")
  case object IssuerMismatch extends IssuerMismatch
  sealed abstract class AudienceMismatch private[jose] () extends Rejected("audience mismatch")
  case object AudienceMismatch extends AudienceMismatch
  sealed abstract class UntrustedAlgorithm private[jose] () extends Rejected("algorithm not in the allowlist")
  case object UntrustedAlgorithm extends UntrustedAlgorithm
  sealed abstract class UnknownKey private[jose] () extends Rejected("no usable key for this token")
  case object UnknownKey extends UnknownKey

  /** Claim set under construction: start from [[Claims.empty]] and refine with the withers
    * (`Claims.empty.subject("u").audience("api").expiresIn(1.hour).id(jti)`). `custom` claims
    * round-trip into [[Verified]] verbatim (DPoP: jti/htm/htu/cnf).
    */
  final case class Claims(
    subject: Option[String],
    issuer: Option[String],
    audiences: Set[String],
    expiresAt: Option[Long],
    notBefore: Option[Long],
    lifetime: Option[FiniteDuration],
    id: Option[String],
    custom: Map[String, JoseValue]
  )
  object Claims:
    val empty: Claims = Claims(None, None, Set.empty, None, None, None, None, Map.empty)
    given CanEqual[Claims, Claims] = CanEqual.derived
    extension (c: Claims)
      def subject(value: String): Claims = c.copy(subject = Some(value))
      def issuer(value: String): Claims = c.copy(issuer = Some(value))
      def audience(value: String): Claims = c.copy(audiences = c.audiences + value)
      def expiresAt(epochSeconds: Long): Claims = c.copy(expiresAt = Some(epochSeconds))
      def notBefore(epochSeconds: Long): Claims = c.copy(notBefore = Some(epochSeconds))

      /** Stamped as `exp = at + lifetime` at sign time. */
      def expiresIn(lifetime: FiniteDuration): Claims = c.copy(lifetime = Some(lifetime))

      /** The `jti` claim (DPoP proofs, revocation lists). */
      def id(value: String): Claims = c.copy(id = Some(value))
      def claim(name: String, value: JoseValue): Claims = c.copy(custom = c.custom.updated(name, value))
    end extension
  end Claims

  /** Audience and the algorithm allowlist are the checks whose omission is an exploit:
    * constructor-required. Optional checks refine by wither ([[Policy.issuer]], [[Policy.skew]]);
    * [[Policy.unaudienced]] is the deliberate, NAMED opt-out for audience-free internal tokens.
    */
  final case class Policy(
    audience: Option[String],
    algorithms: Set[JWSAlg],
    requiredIssuer: Option[String],
    clockSkew: Long
  )
  object Policy:
    def apply(audience: String, algorithms: Set[JWSAlg]): Policy =
      require(algorithms.nonEmpty, "the algorithm allowlist cannot be empty")
      Policy(Some(audience), algorithms, None, 0L)
    def unaudienced(algorithms: Set[JWSAlg]): Policy =
      require(algorithms.nonEmpty, "the algorithm allowlist cannot be empty")
      Policy(None, algorithms, None, 0L)
    given CanEqual[Policy, Policy] = CanEqual.derived
    extension (p: Policy)
      def issuer(value: String): Policy = p.copy(requiredIssuer = Some(value))
      def skew(seconds: Long): Policy = p.copy(clockSkew = seconds)

  final case class Verified(
    subject: Option[String],
    issuer: Option[String],
    audiences: Set[String],
    expiresAt: Option[Long],
    issuedAt: Option[Long],
    id: Option[String],
    claims: Map[String, JoseValue]
  )
  object Verified:
    given CanEqual[Verified, Verified] = CanEqual.derived

  extension (jwt: JWT) def compact: String = jwt

  /** Routing data of an UNVERIFIED token: issuer, `kid`, and the alg name ONLY - the multi-tenant
    * OIDC step that selects the key set BEFORE verification. Deliberately excludes the subject and
    * every other claim, so nothing from `peek` can be mistaken for a verification result.
    */
  final case class Unverified(issuer: Option[String], kid: Option[String], algorithm: String)
  object Unverified:
    given CanEqual[Unverified, Unverified] = CanEqual.derived
  def peek(token: String): Either[Malformed, Unverified] =
    parse(token) match
      case Right(p) => Right(Unverified(claimString(p.payload, "iss"), p.kid, p.algName))
      case Left(_)  => Left(Malformed)

  private def payloadJson(c: Claims, at: Long): String =
    val exp = c.expiresAt.orElse(c.lifetime.map(l => at + l.toSeconds))
    val fields =
      c.issuer.map(v => "iss" -> Json.str(v)).toList ++
        c.subject.map(v => "sub" -> Json.str(v)).toList ++
        (c.audiences.toList.sorted match
          case Nil      => Nil
          case a :: Nil => List("aud" -> Json.str(a))
          case as       => List("aud" -> as.map(Json.str).mkString("[", ",", "]"))) ++
        exp.map(v => "exp" -> v.toString).toList ++
        c.notBefore.map(v => "nbf" -> v.toString).toList ++
        List("iat" -> at.toString) ++
        c.id.map(v => "jti" -> Json.str(v)).toList ++
        c.custom.toList.sortBy(_._1).map((k, v) => k -> Json.value(v))
    Json.obj(fields)
  end payloadJson

  private def headerJson(alg: JWSAlg, kid: Option[String]): String =
    Json.obj(("alg" -> Json.str(alg.name)) :: kid.map(k => "kid" -> Json.str(k)).toList)

  private def signingInput(header: String, payload: String): (String, Slice) =
    val s = Base64Url.encode(header.getBytes("UTF-8")) + "." + Base64Url.encode(payload.getBytes("UTF-8"))
    (s, Slice.of(s.getBytes("US-ASCII")))

  private def assemble[A <: Algorithm](input: String, sig: Signature[A]): JWT =
    input + "." + Base64Url.encode(Array.from(sig.bytes.iterator))

  /** Sign at explicit time `at` (epoch seconds; stamps `iat`, resolves `expiresIn`). The alg fixes
    * the key type: `JWT.sign(claims, ES256, at)(p256Key)`.
    */
  def sign[K <: SignatureAlgorithm](claims: Claims, alg: JWSAlg.Asymmetric[K], at: Long)(key: PrivateKey[K])(using
    s: Signer[K]
  ): UEffIO[JWT] = sign(claims, alg, None, at)(key)
  def sign[K <: SignatureAlgorithm](claims: Claims, alg: JWSAlg.Asymmetric[K], kid: String, at: Long)(
    key: PrivateKey[K]
  )(using s: Signer[K]): UEffIO[JWT] = sign(claims, alg, Some(kid), at)(key)
  private def sign[K <: SignatureAlgorithm](claims: Claims, alg: JWSAlg.Asymmetric[K], kid: Option[String], at: Long)(
    key: PrivateKey[K]
  )(using s: Signer[K]): UEffIO[JWT] =
    val (input, bytes) = signingInput(headerJson(alg, kid), payloadJson(claims, at))
    s.sign(key, bytes, alg.scheme).map(assemble(input, _))

  @targetName("signMac")
  def sign[H <: MacAlgorithm](claims: Claims, alg: JWSAlg.Symmetric[H], at: Long)(key: SecretKey[H])(using
    m: Mac[H]
  ): UEffIO[JWT] =
    val (input, bytes) = signingInput(headerJson(alg, None), payloadJson(claims, at))
    m.sign(key, bytes).map(assemble(input, _))

  final private case class Parsed(
    algName: String,
    kid: Option[String],
    payload: Map[String, JoseValue],
    input: Slice,
    signature: Array[Byte]
  )

  private def parse(token: String): Either[Rejected, Parsed] =
    token.split('.') match
      case Array(h, p, s) =>
        for
          hb <- Base64Url.decode(h).left.map(_ => Malformed: Rejected)
          pb <- Base64Url.decode(p).left.map(_ => Malformed: Rejected)
          sb <- Base64Url.decode(s).left.map(_ => Malformed: Rejected)
          header <- Json.parse(new String(hb, "UTF-8")).toRight(Malformed)
          payload <- Json.parse(new String(pb, "UTF-8")).toRight(Malformed)
          algName <- header.get("alg") match
                       case Some(JoseValue.Str(a)) => Right(a)
                       case _                      => Left(Malformed)
        yield
          val kid = header.get("kid") match
            case Some(JoseValue.Str(k)) => Some(k)
            case _                      => None
          Parsed(algName, kid, payload, Slice.of(s"$h.$p".getBytes("US-ASCII")), sb)
      case _ => Left(Malformed)

  private def claimString(p: Map[String, JoseValue], name: String): Option[String] =
    p.get(name) match
      case Some(JoseValue.Str(s)) => Some(s)
      case _                      => None
  private def claimLong(p: Map[String, JoseValue], name: String): Option[Long] =
    p.get(name) match
      case Some(JoseValue.Num(n)) => Some(n.toLong)
      case _                      => None
  private def claimAudiences(p: Map[String, JoseValue]): Set[String] =
    p.get("aud") match
      case Some(JoseValue.Str(a))  => Set(a)
      case Some(JoseValue.Arr(vs)) => vs.collect { case JoseValue.Str(s) => s }.toSet
      case _                       => Set.empty

  private def checkClaims(parsed: Parsed, policy: Policy, now: Long): Either[Rejected, Verified] =
    val p = parsed.payload
    val auds = claimAudiences(p)
    val exp = claimLong(p, "exp")
    val nbf = claimLong(p, "nbf")
    if exp.exists(_ < now - policy.clockSkew) then Left(Expired)
    else if nbf.exists(_ > now + policy.clockSkew) then Left(NotYetValid)
    else if policy.requiredIssuer.exists(i => !claimString(p, "iss").contains(i)) then Left(IssuerMismatch)
    else if policy.audience.exists(a => !auds.contains(a)) then Left(AudienceMismatch)
    else
      val registered = Set("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
      Right(
        Verified(
          claimString(p, "sub"),
          claimString(p, "iss"),
          auds,
          exp,
          claimLong(p, "iat"),
          claimString(p, "jti"),
          p.filter((k, _) => !registered.contains(k))
        )
      )
    end if
  end checkClaims

  /** Verify against a JWKS at explicit time `now`: the token's `kid` (or the sole key) selects the
    * JWK, whose key arm must match the header algorithm - a mismatch is [[UnknownKey]],
    * indistinguishable from an absent key. Symmetric algs never verify via a public-key set.
    */
  def verify(token: String, keys: JWKS, policy: Policy, now: Long)(using
    ed: Verifier[Ed25519],
    p256: Verifier[P256],
    p384: Verifier[P384],
    p521: Verifier[P521],
    rsa: Verifier[Rsa]
  ): EffIO[Rejected, Verified] =
    EffIO.from(parse(token)).flatMap { parsed =>
      policy.algorithms.find(_.name == parsed.algName) match
        case None                            => EffIO.fail(UntrustedAlgorithm)
        case Some(alg: JWSAlg.Asymmetric[?]) =>
          val jwk = parsed.kid match
            case Some(k) => keys.find(k)
            case None    => keys.keys.headOption
          jwk match
            case None    => EffIO.fail(UnknownKey)
            case Some(j) => verifyArm(parsed, alg, j.key).flatMap(_ => EffIO.from(checkClaims(parsed, policy, now)))
        case Some(_) => EffIO.fail(UnknownKey)
    }

  private def verifyArm(parsed: Parsed, alg: JWSAlg.Asymmetric[?], key: ImportedPublicKey)(using
    ed: Verifier[Ed25519],
    p256: Verifier[P256],
    p384: Verifier[P384],
    p521: Verifier[P521],
    rsa: Verifier[Rsa]
  ): EffIO[Rejected, Unit] =
    val outcome: Either[Rejected, EffIO[SignatureRejected, Unit]] = (alg, key) match
      case (EdDSA, ImportedPublicKey.Ed(k)) =>
        Signature.fromRaw(Ed25519)(parsed.signature).map(s => ed.verify(k, parsed.input, s, EdDSA.scheme)).left.map(_ => Malformed)
      case (ES256, ImportedPublicKey.EcP256(k)) =>
        Signature.fromRaw(P256)(parsed.signature).map(s => p256.verify(k, parsed.input, s, ES256.scheme)).left.map(_ => Malformed)
      case (ES384, ImportedPublicKey.EcP384(k)) =>
        Signature.fromRaw(P384)(parsed.signature).map(s => p384.verify(k, parsed.input, s, ES384.scheme)).left.map(_ => Malformed)
      case (ES512, ImportedPublicKey.EcP521(k)) =>
        Signature.fromRaw(P521)(parsed.signature).map(s => p521.verify(k, parsed.input, s, ES512.scheme)).left.map(_ => Malformed)
      case (a @ (PS256 | RS256), ImportedPublicKey.OfRsa(k)) =>
        Signature.fromRaw(Rsa)(parsed.signature).map(s => rsa.verify(k, parsed.input, s, a.scheme)).left.map(_ => Malformed)
      case _ => Left(UnknownKey)
    outcome match
      case Left(r)  => EffIO.fail(r)
      case Right(v) => v.mapError(_ => BadSignature: Rejected)
  end verifyArm

  /** Single-key verification for the fixed-key deployment (no JWKS indirection). */
  def verify[K <: SignatureAlgorithm](token: String, alg: JWSAlg.Asymmetric[K], key: PublicKey[K], policy: Policy, now: Long)(using
    v: Verifier[K]
  ): EffIO[Rejected, Verified] =
    EffIO.from(parse(token)).flatMap { parsed =>
      if !policy.algorithms.exists(_.name == parsed.algName) then EffIO.fail(UntrustedAlgorithm)
      else if parsed.algName != alg.name then EffIO.fail(UnknownKey)
      else
        EffIO.from(sigOf(alg, parsed.signature)).flatMap { s =>
          v.verify(key, parsed.input, s, alg.scheme)
            .mapError(_ => BadSignature: Rejected)
            .flatMap(_ => EffIO.from(checkClaims(parsed, policy, now)))
        }
    }

  @targetName("verifyMac")
  def verify[H <: MacAlgorithm](token: String, alg: JWSAlg.Symmetric[H], key: SecretKey[H], policy: Policy, now: Long)(using
    m: Mac[H]
  ): EffIO[Rejected, Verified] =
    EffIO.from(parse(token)).flatMap { parsed =>
      if !policy.algorithms.exists(_.name == parsed.algName) then EffIO.fail(UntrustedAlgorithm)
      else if parsed.algName != alg.name then EffIO.fail(UnknownKey)
      else
        m.sign(key, parsed.input).flatMap { computed =>
          // through the same constant-time discipline as core MAC verify
          if Slice.of(Array.from(computed.bytes.iterator)).constantTimeEquals(Slice.of(parsed.signature))
          then EffIO.from(checkClaims(parsed, policy, now))
          else EffIO.fail(BadSignature)
        }
    }

  // Re-tag the validated octets to the algorithm the alg match proves (Signature is opaque
  // Array[Byte]; fromRaw validated the length, then the original bytes carry the algorithm K).
  private def sigOf[K <: SignatureAlgorithm](alg: JWSAlg.Asymmetric[K], bytes: Array[Byte]): Either[Rejected, Signature[K]] =
    def retag(v: Either[kufuli.Malformed, ?]): Either[kufuli.Malformed, Signature[K]] = v.map(_ => Signature.unsafe[K](bytes.clone))
    val parsed: Either[kufuli.Malformed, Signature[K]] = alg match
      case ES256 => retag(Signature.fromRaw(P256)(bytes))
      case ES384 => retag(Signature.fromRaw(P384)(bytes))
      case ES512 => retag(Signature.fromRaw(P521)(bytes))
      case EdDSA => retag(Signature.fromRaw(Ed25519)(bytes))
      case _     => retag(Signature.fromRaw(Rsa)(bytes))
    parsed.left.map(_ => Malformed)
end JWT

/** A public key in JWK form (RFC 7517/7518): the canonical JSON plus the parsed key arm. Build the
  * PUBLISHING direction with `JWK.of` (the /jwks endpoint, OIDC discovery); parse with `parse`.
  * `json` emits the canonical members (RFC 7638 ordering).
  */
final case class JWK(kid: Option[String], key: ImportedPublicKey, json: String)
object JWK:
  given CanEqual[JWK, JWK] = CanEqual.derived

  private def withKid(kid: Option[String], canonical: List[(String, String)]): String =
    Json.obj(canonical ++ kid.map(k => "kid" -> Json.str(k)).toList)

  private[jose] def canonicalEd(x: IArray[Byte]): List[(String, String)] =
    List("crv" -> Json.str("Ed25519"), "kty" -> Json.str("OKP"), "x" -> Json.str(Base64Url.encode(Array.from(x.iterator))))
  private[jose] def canonicalEc(crv: String, sec1: IArray[Byte], fieldLength: Int): List[(String, String)] =
    val x = Array.from(sec1.iterator.slice(1, 1 + fieldLength))
    val y = Array.from(sec1.iterator.drop(1 + fieldLength))
    List(
      "crv" -> Json.str(crv),
      "kty" -> Json.str("EC"),
      "x" -> Json.str(Base64Url.encode(x)),
      "y" -> Json.str(Base64Url.encode(y))
    )
  private[jose] def canonicalRsa(c: Rsa.Components): List[(String, String)] =
    List(
      "e" -> Json.str(Base64Url.encode(Array.from(c.exponent.iterator))),
      "kty" -> Json.str("RSA"),
      "n" -> Json.str(Base64Url.encode(Array.from(c.modulus.iterator)))
    )

  /** Publish an Ed25519 verification key (RFC 8037 OKP form). */
  def of(kid: String, key: PublicKey[Ed25519])(using k: EdKeys): EffIO[KeyNotExportable, JWK] =
    key.raw.map(x => JWK(Some(kid), ImportedPublicKey.Ed(key), withKid(Some(kid), canonicalEd(x))))

  /** Publish an EC verification key; the curve name follows the spec (`P-256`/`P-384`/`P-521`). */
  @targetName("ofEc")
  def of[C <: EcCurve](kid: String, key: PublicKey[C])(using k: EcKeys[C], spec: EcSpec[C]): EffIO[KeyNotExportable, JWK] =
    val crv = spec.fieldLength match
      case 32 => "P-256"
      case 48 => "P-384"
      case _  => "P-521"
    val arm: PublicKey[C] => ImportedPublicKey = spec.fieldLength match
      case 32 => c => ImportedPublicKey.EcP256(PublicKey.unsafe[P256](c.repr))
      case 48 => c => ImportedPublicKey.EcP384(PublicKey.unsafe[P384](c.repr))
      case _  => c => ImportedPublicKey.EcP521(PublicKey.unsafe[P521](c.repr))
    key.sec1.map(s => JWK(Some(kid), arm(key), withKid(Some(kid), canonicalEc(crv, s, spec.fieldLength))))

  /** Publish an RSA verification key (the JWK `n`/`e` pair). */
  @targetName("ofRsa")
  def of(kid: String, key: PublicKey[Rsa])(using k: RsaKeys): EffIO[KeyNotExportable, JWK] =
    key.components.map(c => JWK(Some(kid), ImportedPublicKey.OfRsa(key), withKid(Some(kid), canonicalRsa(c))))

  /** Parse a single JWK document; the key goes through the lifecycle imports (typed validation). */
  def parse(json: String)(using
    ed: EdKeys,
    p256: EcKeys[P256],
    rsa: RsaKeys
  ): EffIO[Malformed | InvalidKey, JWK] =
    Json.parse(json) match
      case None         => EffIO.fail(Malformed)
      case Some(fields) =>
        def str(n: String) = fields.get(n) match
          case Some(JoseValue.Str(s)) => Some(s)
          case _                      => None
        def b64(n: String): Either[Malformed, Array[Byte]] = str(n).toRight(Malformed).flatMap(Base64Url.decode)
        val kid = str("kid")
        (str("kty"), str("crv")) match
          case (Some("OKP"), Some("Ed25519")) =>
            EffIO.from(b64("x")).flatMap(x => ed.fromRaw(Slice.of(x)).map(k => JWK(kid, ImportedPublicKey.Ed(k), json)))
          case (Some("EC"), Some("P-256")) =>
            EffIO
              .from(for x <- b64("x"); y <- b64("y") yield Array[Byte](4) ++ x ++ y)
              .flatMap(pt => p256.fromSec1(Slice.of(pt)).map(k => JWK(kid, ImportedPublicKey.EcP256(k), json)))
          case (Some("RSA"), _) =>
            EffIO
              .from(for n <- b64("n"); e <- b64("e") yield (n, e))
              .flatMap((n, e) => rsa.fromComponents(Slice.of(n), Slice.of(e)).map(k => JWK(kid, ImportedPublicKey.OfRsa(k), json)))
          case _ => EffIO.fail(InvalidKey.Unsupported)
        end match
end JWK

/** A key set for verification and publication: `find` for the verify path, `json` for the /jwks
  * endpoint (RFC 7517 `{"keys": [...]}`).
  */
final case class JWKS(keys: List[JWK]):
  def find(kid: String): Option[JWK] = keys.find(_.kid.contains(kid))
  def json: String = keys.map(_.json).mkString("""{"keys":[""", ",", "]}")
object JWKS:
  given CanEqual[JWKS, JWKS] = CanEqual.derived
  def of(keys: JWK*): JWKS = JWKS(keys.toList)

private def canonJson(fields: List[(String, String)]): Slice =
  Slice.of(fields.map((k, v) => s"\"$k\":$v").mkString("{", ",", "}").getBytes("UTF-8"))
extension (pub: PublicKey[Ed25519])
  /** RFC 7638 JWK thumbprint (SHA-256 default). The explicit-spec overload admits Sha1 for
    * x5t-class digests - the only position Sha1 is allowed.
    */
  @targetName("thumbprintEd")
  def thumbprint(using EdKeys, Hash[Sha256]): EffIO[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintEdSpec")
  def thumbprint[D <: HashAlgorithm](spec: HashSpec[D])(using k: EdKeys, h: Hash[D]): EffIO[KeyNotExportable, Digest] =
    pub.raw.flatMap(x => spec.digest(canonJson(JWK.canonicalEd(x))))
extension [C <: EcCurve](pub: PublicKey[C])
  @targetName("thumbprintEc")
  def thumbprint(using EcKeys[C], EcSpec[C], Hash[Sha256]): EffIO[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintEcSpec")
  def thumbprint[D <: HashAlgorithm](hs: HashSpec[D])(using k: EcKeys[C], spec: EcSpec[C], h: Hash[D]): EffIO[KeyNotExportable, Digest] =
    val crv = spec.fieldLength match
      case 32 => "P-256"
      case 48 => "P-384"
      case _  => "P-521"
    pub.sec1.flatMap(s => hs.digest(canonJson(JWK.canonicalEc(crv, s, spec.fieldLength))))
extension (pub: PublicKey[Rsa])
  @targetName("thumbprintRsa")
  def thumbprint(using RsaKeys, Hash[Sha256]): EffIO[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintRsaSpec")
  def thumbprint[D <: HashAlgorithm](spec: HashSpec[D])(using k: RsaKeys, h: Hash[D]): EffIO[KeyNotExportable, Digest] =
    pub.components.flatMap(c => spec.digest(canonJson(JWK.canonicalRsa(c))))

/** COSE_Key (RFC 9052/9053) import - the passkey-server key seam: WebAuthn credential public keys
  * arrive as COSE, not JWK. Parse yields the same import arms as SPKI/JWK; verification then uses
  * the ordinary ops. The WebAuthn ceremony (attestation formats, authenticator data, challenge
  * binding) is out of scope - this is the key-import boundary. The supported subset is OKP/Ed25519
  * and EC2/P-256, the WebAuthn credential-key algorithms.
  */
object COSEKey:
  // Bounded CBOR reader over the COSE_Key map subset: an immutable cursor over the bytes, every
  // read bounds-checked, only definite lengths accepted, unknown map entries skipped. `None` is a
  // malformed encoding.
  final private case class Cur(b: Array[Byte], pos: Int)
  private def u8(c: Cur): Option[(Int, Cur)] =
    if c.pos >= c.b.length then None else Some(((c.b(c.pos) & 0xff), Cur(c.b, c.pos + 1)))
  // bounded to <= 8 bytes, so ordinary recursion (not tail-recursive through flatMap)
  private def readN(c: Cur, n: Int, acc: Long): Option[(Long, Cur)] =
    if n == 0 then Some((acc, c)) else u8(c).flatMap((v, c2) => readN(c2, n - 1, (acc << 8) | v.toLong))
  private def head(c: Cur): Option[(Int, Long, Cur)] =
    u8(c).flatMap { (ib, c2) =>
      val arg = (ib & 0x1f) match
        case n if n < 24 => Some((n.toLong, c2))
        case 24          => readN(c2, 1, 0)
        case 25          => readN(c2, 2, 0)
        case 26          => readN(c2, 4, 0)
        case 27          => readN(c2, 8, 0)
        case _           => None
      arg.map((a, c3) => (ib >>> 5, a, c3))
    }
  private def readInt(c: Cur): Option[(Int, Cur)] =
    head(c).flatMap { (major, arg, c2) =>
      major match
        case 0 => Some((arg.toInt, c2))
        case 1 => Some(((-1L - arg).toInt, c2))
        case _ => None
    }
  private def readBytes(c: Cur): Option[(Array[Byte], Cur)] =
    head(c).flatMap { (major, arg, c2) =>
      val len = arg.toInt
      if major != 2 || len < 0 || c2.pos + len > c2.b.length then None
      else Some((c2.b.slice(c2.pos, c2.pos + len), Cur(c2.b, c2.pos + len)))
    }
  // Skipping an unknown value recurses through nested arrays/maps; bound the nesting depth so a
  // crafted deeply-nested COSE cannot exhaust the stack (`readMap` only reads a flat top-level map).
  private inline val maxCborDepth = 64
  private def skip(c: Cur, depth: Int): Option[Cur] =
    if depth > maxCborDepth then None
    else
      head(c).flatMap { (major, arg, c2) =>
        major match
          case 0 | 1 | 7 => Some(c2)
          case 2 | 3     =>
            val len = arg.toInt
            if len < 0 || c2.pos + len > c2.b.length then None else Some(Cur(c2.b, c2.pos + len))
          case 4 => skipMany(c2, arg, depth + 1)
          case 5 => skipMany(c2, arg * 2, depth + 1)
          case _ => None
      }
  @tailrec private def skipMany(c: Cur, n: Long, depth: Int): Option[Cur] =
    if n <= 0 then Some(c)
    else
      skip(c, depth) match
        case Some(c2) => skipMany(c2, n - 1, depth)
        case None     => None

  final private case class Fields(kty: Int, crv: Int, x: Array[Byte], y: Array[Byte])
  private def readMap(cbor: Array[Byte]): Option[Fields] =
    head(Cur(cbor, 0)).flatMap { (major, count, c0) =>
      if major != 5 then None
      else
        @tailrec def loop(c: Cur, i: Long, acc: Fields): Option[Fields] =
          if i >= count then Some(acc)
          else
            readInt(c) match
              case None              => None
              case Some((label, c1)) =>
                val stepped = label match
                  case 1  => readInt(c1).map((v, c2) => (acc.copy(kty = v), c2))
                  case 3  => readInt(c1).map((_, c2) => (acc, c2))
                  case -1 => readInt(c1).map((v, c2) => (acc.copy(crv = v), c2))
                  case -2 => readBytes(c1).map((v, c2) => (acc.copy(x = v), c2))
                  case -3 => readBytes(c1).map((v, c2) => (acc.copy(y = v), c2))
                  case _  => skip(c1, 0).map(c2 => (acc, c2))
                stepped match
                  case Some((acc2, c2)) => loop(c2, i + 1, acc2)
                  case None             => None
        loop(c0, 0, Fields(Int.MinValue, Int.MinValue, Array.emptyByteArray, Array.emptyByteArray))
    }

  def parse(cbor: Array[Byte])(using ed: EdKeys, p256: EcKeys[P256]): EffIO[InvalidKey, ImportedPublicKey] =
    readMap(cbor) match
      case None    => EffIO.fail(InvalidKey.Malformed)
      case Some(f) =>
        // OKP(1)/Ed25519(6); EC2(2)/P-256(1) reassembled to an uncompressed SEC1 point.
        if f.kty == 1 && f.crv == 6 then ed.fromRaw(Slice.of(f.x)).map(ImportedPublicKey.Ed(_))
        else if f.kty == 2 && f.crv == 1 then p256.fromSec1(Slice.of(Array[Byte](4) ++ f.x ++ f.y)).map(ImportedPublicKey.EcP256(_))
        else EffIO.fail(InvalidKey.Unsupported)
end COSEKey

/** Not implemented: the shapes compile, but every operation raises rather than returning a value. */
opaque type JWE = String
object JWE:
  enum Alg derives CanEqual:
    case EcdhEs, EcdhEsA128Kw, EcdhEsA256Kw, RsaOaep256, Dir
  enum Enc derives CanEqual:
    case A128CbcHs256, A256CbcHs512, A128Gcm, A256Gcm
  sealed abstract class Rejected(message: String) extends JoseError(message)
  sealed abstract class NotJwe private[jose] () extends Rejected("not a JWE compact serialization")
  case object NotJwe extends NotJwe
  sealed abstract class DecryptionFailed private[jose] () extends Rejected("content decryption failed")
  case object DecryptionFailed extends DecryptionFailed
  sealed abstract class UntrustedAlgorithm private[jose] () extends Rejected("alg/enc not in the allowlist")
  case object UntrustedAlgorithm extends UntrustedAlgorithm
  // The shapes are retained but the operations are not implemented; they raise rather than return a
  // placeholder a caller could mistake for a real seal or open (a fake-successful decryption is worse
  // than a loud failure).
  private def unimplemented: Nothing =
    throw new UnsupportedOperationException("kufuli.jose.JWE is not implemented") // scalafix:ok DisableSyntax.throw
  def seal[C <: EcCurve](pt: Slice, recipient: PublicKey[C], alg: Alg, enc: Enc): UEffIO[JWE] =
    val _ = (pt, recipient, alg, enc)
    EffIO.suspend(unimplemented)
  @targetName("sealRsa")
  def seal(pt: Slice, recipient: PublicKey[Rsa], enc: Enc): UEffIO[JWE] =
    val _ = (pt, recipient, enc)
    EffIO.suspend(unimplemented)
  def open[C <: EcCurve](jwe: String, key: PrivateKey[C], allowed: Set[Enc]): EffIO[Rejected, Array[Byte]] =
    val _ = (jwe, key, allowed)
    EffIO.suspend(unimplemented)
  extension (jwe: JWE) def compact: String = jwe
end JWE
