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

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

import scala.annotation.tailrec
import scala.annotation.targetName
import scala.concurrent.duration.FiniteDuration

import boilerplate.Slice
import boilerplate.TypedError
import boilerplate.ValueCodec
import boilerplate.codec.Base64Url
import boilerplate.effect.Eff
import boilerplate.effect.UEff
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.*

sealed abstract class JoseError(message: String, cause: Option[Throwable]) extends TypedError(message, cause):
  def this(message: String) = this(message, None)

/** A JSON value carried in a JWT's custom claims, nesting included (DPoP's `cnf`). */
sealed abstract class JoseValue derives CanEqual
object JoseValue:
  private[jose] def wellFormed(text: String): Boolean =
    @tailrec def go(i: Int): Boolean =
      if i >= text.length then true
      else
        val c = text.charAt(i)
        if c.isHighSurrogate then i + 1 < text.length && text.charAt(i + 1).isLowSurrogate && go(i + 2)
        else if c.isLowSurrogate then false
        else go(i + 1)
    go(0)

  final case class Str(value: String) extends JoseValue:
    // In the constructor BODY, so it binds `copy` as well as `apply`. An unpaired surrogate is what
    // slicing a string through a surrogate pair leaves behind: it has no UTF-8 encoding, so the
    // failure belongs at the truncation site rather than at a remote verifier.
    require(JoseValue.wellFormed(value), "JOSE strings are well-formed UTF-16")
  final case class Num(value: Double) extends JoseValue:
    // In the constructor BODY, so it binds `copy` as well as `apply`: JSON has no literal for a
    // non-finite number, and a claim set that cannot be rendered would raise out of `sign`.
    require(value.isFinite, "JOSE numbers are finite")
  final case class Bool(value: Boolean) extends JoseValue
  final case class Arr(values: List[JoseValue]) extends JoseValue
  final case class Obj(fields: Map[String, JoseValue]) extends JoseValue:
    // A nested member name is claim-carrying text like any other, and `Claims`'s own require reaches
    // only the top level.
    require(fields.keys.forall(JoseValue.wellFormed), "JOSE member names are well-formed UTF-16")
  sealed abstract class Null private () extends JoseValue
  case object Null extends Null
end JoseValue

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
                // RFC 7515 section 4 and RFC 7519 section 4 make member names unique. Which
                // occurrence a reader keeps decides `aud`, `iss`, `exp` and `kid`, so a token whose
                // names repeat means different things to kufuli and to an intermediary.
                @tailrec def loop(seen: Set[String]): Unit =
                  val k = in.readKeyAsString()
                  if seen(k) then in.decodeError("repeated member name")
                  else
                    val _ = fields += (k -> decode(in, depth + 1))
                    if in.isNextToken(',') then loop(seen + k)
                loop(Set.empty)
                if !in.isCurrentToken('}') then in.objectEndOrCommaError()
              end if
              JoseValue.Obj(fields.result())
          case _ =>
            in.rollbackToken()
            val n = in.readDouble()
            // JSON has no literal for a non-finite double, so admitting 1e999 would let an
            // attacker-supplied header member parse and then raise when it is re-serialised.
            if n.isFinite then JoseValue.Num(n) else in.decodeError("non-finite number")
        end match
    // The codec satisfies jsoniter's read entry point; the byte form kufuli signs and hashes comes
    // from `Json.value`, which owns member ordering and escaping.
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

  // The RFC 7638 thumbprint path depends on exact member bytes, and every input has a rendering
  // here, so `sign` keeps the unfailable channel its type declares.
  def str(s: String): String =
    val b = new StringBuilder(s.length + 2)
    val _ = b.append('"')
    def escaped(c: Char): StringBuilder = b.append(f"\\u${c.toInt}%04x")
    @tailrec def go(i: Int): Unit =
      if i < s.length then
        val c = s.charAt(i)
        val _ = c match
          case '"'          => b.append("\\\"")
          case '\\'         => b.append("\\\\")
          case _ if c < ' ' => escaped(c)
          // An unpaired surrogate has no UTF-8 encoding: emitted raw it would be substituted, and
          // two distinct claim strings would sign as one. The escape carries the exact code unit.
          case _ if c.isHighSurrogate && !(i + 1 < s.length && s.charAt(i + 1).isLowSurrogate) => escaped(c)
          case _ if c.isLowSurrogate && !(i > 0 && s.charAt(i - 1).isHighSurrogate)            => escaped(c)
          case _                                                                               => b.append(c)
        go(i + 1)
    go(0)
    val _ = b.append('"')
    b.toString
  end str

  def value(v: JoseValue): String = v match
    case JoseValue.Str(s)  => str(s)
    case JoseValue.Num(n)  => if n == n.toLong.toDouble then n.toLong.toString else n.toString
    case JoseValue.Bool(b) => b.toString
    case JoseValue.Arr(vs) => vs.map(value).mkString("[", ",", "]")
    case JoseValue.Obj(fs) => obj(fs.toList.sortBy(_._1).map((k, v2) => k -> value(v2)))
    case JoseValue.Null    => "null"
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
sealed trait JwsAlg derives CanEqual:
  /** Header values this arm VERIFIES; `name` alone is what it EMITS. */
  def accepts(header: String): Boolean = header == name
  def name: String
object JwsAlg:
  sealed abstract class Asymmetric[K <: SignatureAlgorithm](val name: String, val scheme: Scheme[K]) extends JwsAlg
  sealed abstract class Symmetric[H <: MacAlgorithm](val name: String) extends JwsAlg

  private val values: List[JwsAlg] = List(ES256, ES384, ES512, EdDSA, PS256, RS256, HS256, HS384, HS512)

  /** The wire-text contract: RFC 7518/9864 registry names, serving configuration-driven algorithm
    * allowlists (`Policy` construction from configuration). Decode accepts what an arm verifies -
    * the Ed25519/EdDSA duality normalises to the arm - and encode emits the one registry name the
    * arm emits, so decode is idempotent through re-encoding.
    */
  given valueCodec: ValueCodec.Aux[JwsAlg, ValueCodec.Invalid] = ValueCodec(
    text => values.find(_.accepts(text)).toRight(ValueCodec.Invalid("not a registered JWS algorithm name")),
    alg => alg.name
  )
end JwsAlg

case object ES256 extends JwsAlg.Asymmetric[P256]("ES256", ECDSA(Sha256))
case object ES384 extends JwsAlg.Asymmetric[P384]("ES384", ECDSA(Sha384))
case object ES512 extends JwsAlg.Asymmetric[P521]("ES512", ECDSA(Sha512))

/** Emits the standards-current registry value `Ed25519` (RFC 9864) and verifies BOTH `Ed25519` and
  * the legacy polymorphic `EdDSA` into this one arm; the identifier keeps the algorithm's invariant
  * name.
  */
case object EdDSA extends JwsAlg.Asymmetric[Ed25519]("Ed25519", kufuli.Ed):
  override def accepts(header: String): Boolean = header == "Ed25519" || header == "EdDSA"
case object PS256 extends JwsAlg.Asymmetric[RSA]("PS256", RsaPss(Sha256))
case object RS256 extends JwsAlg.Asymmetric[RSA]("RS256", RsaPkcs1(Sha256))
case object HS256 extends JwsAlg.Symmetric[HmacSha256]("HS256")
case object HS384 extends JwsAlg.Symmetric[HmacSha384]("HS384")
case object HS512 extends JwsAlg.Symmetric[HmacSha512]("HS512")

/** A compact-serialised JWT; sign and verify via [[JWT$ JWT]]. */
opaque type JWT = String
object JWT:
  given CanEqual[JWT, JWT] = CanEqual.derived
  // Payload-free rejections are a class plus a co-named object, and type positions name the CLASS:
  // a union of singleton types does not survive the TypeTest reification `either`/`catchAll` rely on
// (re-tested at each toolchain adoption, last at Scala 3.9.0-RC5: still broken; drop the
// class+object shape for plain case objects when the erasure defect is fixed).
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
  sealed abstract class UnknownKey private[jose] () extends Rejected("no key for the token's kid")
  case object UnknownKey extends UnknownKey
  sealed abstract class KeyAlgorithmMismatch private[jose] () extends Rejected("key does not match the token's algorithm")
  case object KeyAlgorithmMismatch extends KeyAlgorithmMismatch
  sealed abstract class MissingExpiry private[jose] () extends Rejected("token carries no expiry")
  case object MissingExpiry extends MissingExpiry
  sealed abstract class TypeMismatch private[jose] () extends Rejected("header typ mismatch")
  case object TypeMismatch extends TypeMismatch
  sealed abstract class MissingHeaderKey private[jose] () extends Rejected("no jwk in the protected header")
  case object MissingHeaderKey extends MissingHeaderKey
  sealed abstract class UnsupportedExtension private[jose] () extends Rejected("unsupported critical header extension")
  case object UnsupportedExtension extends UnsupportedExtension

  /** Claim set under construction: start from [[Claims.empty]] and refine with the withers
    * (`Claims.empty.subject("u").audience("api").expiresIn(1.hour).id(jti)`), each of which owns
    * one registered claim name; everything else goes through `claim` (DPoP: htm/htu/cnf).
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
  ):
    // Same tier and the same reason as JoseValue.Str: every claim-carrying string kufuli owns is
    // checked where it enters, so `sign` has no ill-formed text to render.
    require(
      (subject.toList ++ issuer.toList ++ audiences ++ id.toList ++ custom.keys).forall(JoseValue.wellFormed),
      "JWT claim text is well-formed UTF-16"
    )
  end Claims
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

      /** A claim outside the registered set; a registered name (`iss`, `sub`, `aud`, `exp`, `nbf`,
        * `iat`, `jti`) belongs to its wither and is not emitted from here.
        */
      @targetName("ext_claim")
      def claim(name: String, value: JoseValue): Claims = c.copy(custom = c.custom.updated(name, value))
    end extension

    /** Non-curried form of the two-parameter [[Claims.claim]] wither. */
    def claim(c: Claims, name: String, value: JoseValue): Claims = c.claim(name, value)
  end Claims

  /** Audience and the algorithm allowlist are constructor-required - omitting either is an exploit.
    * A token carrying no `exp` is rejected by default (a never-expiring bearer token is a standing
    * credential). Optional checks refine by wither ([[Policy.issuer]], [[Policy.skew]]);
    * [[Policy.unaudienced]] and [[Policy.unexpiring]] are the named opt-outs, for audience-free
    * internal tokens and for tokens whose freshness the caller enforces another way (e.g. a DPoP
    * `iat` window).
    */
  final class Policy private (
    private[jose] val audience: Option[String],
    private[jose] val algorithms: Set[JwsAlg],
    private[jose] val requiredIssuer: Option[String],
    private[jose] val clockSkew: Long,
    private[jose] val requireExpiry: Boolean
  ):
    override def equals(other: Any): Boolean = other match
      case that: Policy =>
        audience == that.audience && algorithms == that.algorithms && requiredIssuer == that.requiredIssuer &&
        clockSkew == that.clockSkew && requireExpiry == that.requireExpiry
      case _ => false
    override def hashCode: Int = (audience, algorithms, requiredIssuer, clockSkew, requireExpiry).hashCode
  end Policy
  object Policy:
    def apply(audience: String, algorithm: JwsAlg, more: JwsAlg*): Policy =
      new Policy(Some(audience), more.toSet + algorithm, None, 0L, true)
    def unaudienced(algorithm: JwsAlg, more: JwsAlg*): Policy =
      new Policy(None, more.toSet + algorithm, None, 0L, true)

    /** Validated construction from a runtime-assembled allowlist (a configuration-loaded set); a
      * literal list uses the varargs constructors, where emptiness cannot be written.
      */
    def of(audience: String, algorithms: Set[JwsAlg]): Either[kufuli.Malformed, Policy] =
      if algorithms.isEmpty then Left(kufuli.Malformed) else Right(new Policy(Some(audience), algorithms, None, 0L, true))
    @targetName("ofUnaudienced")
    def of(algorithms: Set[JwsAlg]): Either[kufuli.Malformed, Policy] =
      if algorithms.isEmpty then Left(kufuli.Malformed) else Right(new Policy(None, algorithms, None, 0L, true))
    given CanEqual[Policy, Policy] = CanEqual.derived
    extension (p: Policy)
      def issuer(value: String): Policy = new Policy(p.audience, p.algorithms, Some(value), p.clockSkew, p.requireExpiry)
      def skew(seconds: Long): Policy = new Policy(p.audience, p.algorithms, p.requiredIssuer, seconds, p.requireExpiry)

      /** The named opt-out from expiry-by-default: accept a token that carries no `exp`. */
      def unexpiring: Policy = new Policy(p.audience, p.algorithms, p.requiredIssuer, p.clockSkew, false)
  end Policy

  /** A verified token's claims: the registered ones as typed fields, everything else in `claims`. */
  final case class Verified(
    subject: Option[String],
    issuer: Option[String],
    audiences: Set[String],
    expiresAt: Option[Long],
    notBefore: Option[Long],
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

  private val registeredClaims = Set("iss", "sub", "aud", "exp", "nbf", "iat", "jti")

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
        // RFC 7519 section 4: claim names MUST be unique. A custom entry repeating a registered name
        // would emit it twice, and a verifier taking the first duplicate reads a different token.
        c.custom.toList.sortBy(_._1).collect {
          case (k, v) if !registeredClaims.contains(k) => k -> Json.value(v)
        }
    Json.obj(fields)
  end payloadJson

  private def headerJson(alg: JwsAlg, kid: Option[String]): String =
    Json.obj(("alg" -> Json.str(alg.name)) :: kid.map(k => "kid" -> Json.str(k)).toList)

  private def signingInput(header: String, payload: String): (String, Slice) =
    val s = Base64Url.encode(header.getBytes("UTF-8")) + "." + Base64Url.encode(payload.getBytes("UTF-8"))
    (s, Slice.of(s.getBytes("US-ASCII")))

  private def assemble[A <: Algorithm](input: String, sig: Signature[A]): JWT =
    input + "." + Base64Url.encode(Array.from(sig.bytes.iterator))

  /** Sign at explicit time `at` (epoch seconds; stamps `iat`, resolves `expiresIn`). The alg fixes
    * the key type: `JWT.sign(claims, ES256, at)(p256Key)`.
    */
  def sign[K <: SignatureAlgorithm](claims: Claims, alg: JwsAlg.Asymmetric[K], at: Long)(key: PrivateKey[K])(using
    s: Signing[K]
  ): UEff[JWT] = sign(claims, alg, None, at)(key)
  def sign[K <: SignatureAlgorithm](claims: Claims, alg: JwsAlg.Asymmetric[K], kid: String, at: Long)(
    key: PrivateKey[K]
  )(using s: Signing[K]): UEff[JWT] = sign(claims, alg, Some(kid), at)(key)
  private def sign[K <: SignatureAlgorithm](claims: Claims, alg: JwsAlg.Asymmetric[K], kid: Option[String], at: Long)(
    key: PrivateKey[K]
  )(using s: Signing[K]): UEff[JWT] =
    Eff.suspend(signingInput(headerJson(alg, kid), payloadJson(claims, at))).flatMap { (input, bytes) =>
      s.sign(key, bytes, alg.scheme).map(assemble(input, _))
    }

  @targetName("signMac")
  def sign[H <: MacAlgorithm](claims: Claims, alg: JwsAlg.Symmetric[H], at: Long)(key: SecretKey[H])(using
    m: MAC[H]
  ): UEff[JWT] =
    Eff.suspend(signingInput(headerJson(alg, None), payloadJson(claims, at))).flatMap { (input, bytes) =>
      m.sign(key, bytes).map(assemble(input, _))
    }

  /** Sign with the verification key embedded in the protected header (`jwk`, canonical members
    * only) plus an explicit header `typ` - the self-keyed profile (DPoP, RFC 9449). `headerKey` is
    * the public half, type-bound to the signing family, so a cross-family embed does not compile;
    * embedding a different key of the same family is self-defeating, since the token then fails
    * verification under its own header key.
    */
  def sign(claims: Claims, alg: JwsAlg.Asymmetric[Ed25519], typ: String, headerKey: PublicKey[Ed25519], at: Long)(
    key: PrivateKey[Ed25519]
  )(using s: Signing[Ed25519], ks: EdKeys): Eff[KeyNotExportable, JWT] =
    headerKey.raw.flatMap(x => signWithHeader(claims, alg, typ, Json.obj(JWK.canonicalEd(x.bytes)), at)(key))

  @targetName("signHeaderEc")
  def sign[C <: EcCurve](claims: Claims, alg: JwsAlg.Asymmetric[C], typ: String, headerKey: PublicKey[C], at: Long)(
    key: PrivateKey[C]
  )(using s: Signing[C], ks: EcKeys[C], spec: EcSpec[C]): Eff[KeyNotExportable, JWT] =
    val crv = spec.fieldLength match
      case 32 => "P-256"
      case 48 => "P-384"
      case _  => "P-521"
    headerKey.sec1.flatMap(s1 => signWithHeader(claims, alg, typ, Json.obj(JWK.canonicalEc(crv, s1.bytes, spec.fieldLength)), at)(key))

  @targetName("signHeaderRsa")
  def sign(claims: Claims, alg: JwsAlg.Asymmetric[RSA], typ: String, headerKey: PublicKey[RSA], at: Long)(
    key: PrivateKey[RSA]
  )(using s: Signing[RSA], ks: RsaKeys): Eff[KeyNotExportable, JWT] =
    headerKey.components.flatMap(c => signWithHeader(claims, alg, typ, Json.obj(JWK.canonicalRsa(c)), at)(key))

  private def signWithHeader[K <: SignatureAlgorithm](claims: Claims, alg: JwsAlg.Asymmetric[K], typ: String, jwkJson: String, at: Long)(
    key: PrivateKey[K]
  )(using s: Signing[K]): UEff[JWT] =
    Eff
      .suspend {
        val header = Json.obj(List("alg" -> Json.str(alg.name), "jwk" -> jwkJson, "typ" -> Json.str(typ)))
        signingInput(header, payloadJson(claims, at))
      }
      .flatMap((input, bytes) => s.sign(key, bytes, alg.scheme).map(assemble(input, _)))

  final private case class Parsed(
    algName: String,
    kid: Option[String],
    header: Map[String, JoseValue],
    payload: Map[String, JoseValue],
    input: Slice,
    signature: Array[Byte]
  )

  // A token is base64url-decoded and JSON-parsed before any signature check, so its length is the
  // bound on unauthenticated work; 64 KiB is far above any deployable bearer token.
  private inline val maxTokenChars = 65536

  // RFC 7515 section 5.2 step 3 requires the octets to BE valid UTF-8. A replacing decode maps
  // distinct header bytes - distinct `kid` values - onto one string. UTF-8 never yields more chars
  // than input bytes, so underflow is the only successful result: overflow would silently truncate.
  private def utf8(bytes: Array[Byte]): Option[String] =
    val decoder = StandardCharsets.UTF_8
      .newDecoder()
      .onMalformedInput(CodingErrorAction.REPORT)
      .onUnmappableCharacter(CodingErrorAction.REPORT)
    val out = CharBuffer.allocate(bytes.length)
    if !decoder.decode(ByteBuffer.wrap(bytes), out, true).isUnderflow || !decoder.flush(out).isUnderflow then None
    else
      val _ = out.flip()
      Some(out.toString)

  // Deferred, because a 64 KiB token's base64 and JSON work is the largest thing on this path and
  // CONSTRUCTING a verify effect must stay free: a request pipeline that builds one per request and
  // hands it to a scheduler would otherwise do the parse on whatever thread built it.
  private def parsed(token: String): Eff[Rejected, Parsed] = Eff.defer(Eff.from(parse(token)))

  private def parse(token: String): Either[Rejected, Parsed] =
    // RFC 7515 section 5.2 step 1: exactly two delimiting periods. `split` drops trailing empty
    // fields, so without the count "h.p.s" and "h.p.s....." are one token under many strings.
    if token.length > maxTokenChars || token.count(_ == '.') != 2 then Left(Malformed)
    else
      token.split('.') match
        case Array(h, p, s) =>
          for
            hb <- Base64Url.decode(h).left.map(_ => Malformed: Rejected)
            pb <- Base64Url.decode(p).left.map(_ => Malformed: Rejected)
            sb <- Base64Url.decode(s).left.map(_ => Malformed: Rejected)
            header <- utf8(hb).flatMap(Json.parse).toRight(Malformed)
            payload <- utf8(pb).flatMap(Json.parse).toRight(Malformed)
            _ <- critical(header)
            algName <- header.get("alg") match
                         case Some(JoseValue.Str(a)) => Right(a)
                         case _                      => Left(Malformed)
          yield
            val kid = header.get("kid") match
              case Some(JoseValue.Str(k)) => Some(k)
              case _                      => None
            Parsed(algName, kid, header, payload, Slice.of(s"$h.$p".getBytes("US-ASCII")), sb)
        case _ => Left(Malformed)

  // RFC 7515 section 4.1.11: header parameters registered by the JWS specifications may not appear
  // in `crit`, and every name it carries must be present in the header - either is a malformed
  // header rather than an extension kufuli declines. kufuli implements no JWS extension, so a
  // well-formed `crit` is always declined.
  private val specificationHeaders =
    Set("alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit")

  private def critical(header: Map[String, JoseValue]): Either[Rejected, Unit] =
    header.get("crit") match
      case None                    => Right(())
      case Some(JoseValue.Arr(vs)) =>
        val names = vs.collect { case JoseValue.Str(n) => n }
        if names.isEmpty || names.length != vs.length then Left(Malformed)
        else if names.exists(n => specificationHeaders.contains(n) || !header.contains(n)) then Left(Malformed)
        else Left(UnsupportedExtension)
      case Some(_) => Left(Malformed)

  private def claimString(p: Map[String, JoseValue], name: String): Option[String] =
    p.get(name) match
      case Some(JoseValue.Str(s)) => Some(s)
      case _                      => None
  // A registered time claim is an RFC 7519 section 2 NumericDate: a whole number of seconds. The
  // round trip through Long is what proves the value was carried, since the narrowing saturates
  // silently, and the two extremes are the saturation results themselves.
  private def claimTime(p: Map[String, JoseValue], name: String): Either[Rejected, Option[Long]] =
    p.get(name) match
      case Some(JoseValue.Num(n)) =>
        val seconds = n.toLong
        if seconds.toDouble == n && seconds != Long.MaxValue && seconds != Long.MinValue then Right(Some(seconds))
        else Left(Malformed)
      case _ => Right(None)
  private def claimAudiences(p: Map[String, JoseValue]): Set[String] =
    p.get("aud") match
      case Some(JoseValue.Str(a))  => Set(a)
      case Some(JoseValue.Arr(vs)) => vs.collect { case JoseValue.Str(s) => s }.toSet
      case _                       => Set.empty

  private def checkClaims(parsed: Parsed, policy: Policy, now: Long): Either[Rejected, Verified] =
    val p = parsed.payload
    val auds = claimAudiences(p)
    for
      exp <- claimTime(p, "exp")
      nbf <- claimTime(p, "nbf")
      iat <- claimTime(p, "iat")
      _ <- Either.cond(!policy.requireExpiry || exp.nonEmpty, (), MissingExpiry)
      _ <- Either.cond(exp.forall(_ >= now - policy.clockSkew), (), Expired)
      _ <- Either.cond(nbf.forall(_ <= now + policy.clockSkew), (), NotYetValid)
      _ <- Either.cond(policy.requiredIssuer.forall(i => claimString(p, "iss").contains(i)), (), IssuerMismatch)
      _ <- Either.cond(policy.audience.forall(auds.contains), (), AudienceMismatch)
    yield Verified(
      claimString(p, "sub"),
      claimString(p, "iss"),
      auds,
      exp,
      nbf,
      iat,
      claimString(p, "jti"),
      p.filter((k, _) => !registeredClaims.contains(k))
    )
    end for
  end checkClaims

  /** Verify against a JwkSet at explicit time `now`: the token's `kid` selects the JWK, and a token
    * carrying no `kid` takes the first key of the set - against a rotating set that succeeds only
    * while the signing key leads. No key for the kid is [[UnknownKey]], the JwkSet refresh-on-miss
    * lever; a key whose arm does not match the header algorithm, and any symmetric alg reaching a
    * public-key set, is [[KeyAlgorithmMismatch]], which no refetch fixes.
    */
  def verify(token: String, keys: JwkSet, policy: Policy, now: Long)(using
    ed: Verifying[Ed25519],
    p256: Verifying[P256],
    p384: Verifying[P384],
    p521: Verifying[P521],
    rsa: Verifying[RSA]
  ): Eff[Rejected, Verified] =
    parsed(token).flatMap { parsed =>
      policy.algorithms.find(_.accepts(parsed.algName)) match
        case None                            => Eff.fail(UntrustedAlgorithm)
        case Some(alg: JwsAlg.Asymmetric[?]) =>
          val jwk = parsed.kid match
            case Some(k) => keys.find(k)
            case None    => keys.keys.headOption
          jwk match
            case None    => Eff.fail(UnknownKey)
            case Some(j) => verifyArm(parsed, alg, j.key).flatMap(_ => Eff.from(checkClaims(parsed, policy, now)))
        case Some(_) => Eff.fail(KeyAlgorithmMismatch)
    }

  private def verifyArm(parsed: Parsed, alg: JwsAlg.Asymmetric[?], key: ImportedPublicKey)(using
    ed: Verifying[Ed25519],
    p256: Verifying[P256],
    p384: Verifying[P384],
    p521: Verifying[P521],
    rsa: Verifying[RSA]
  ): Eff[Rejected, Unit] =
    val outcome: Either[Rejected, Eff[SignatureRejected, Unit]] = (alg, key) match
      case (EdDSA, ImportedPublicKey.Ed(k)) =>
        Signature.of(Ed25519)(parsed.signature).map(s => ed.verify(k, parsed.input, s, EdDSA.scheme)).left.map(_ => Malformed)
      case (ES256, ImportedPublicKey.EcP256(k)) =>
        Signature.of(P256)(parsed.signature).map(s => p256.verify(k, parsed.input, s, ES256.scheme)).left.map(_ => Malformed)
      case (ES384, ImportedPublicKey.EcP384(k)) =>
        Signature.of(P384)(parsed.signature).map(s => p384.verify(k, parsed.input, s, ES384.scheme)).left.map(_ => Malformed)
      case (ES512, ImportedPublicKey.EcP521(k)) =>
        Signature.of(P521)(parsed.signature).map(s => p521.verify(k, parsed.input, s, ES512.scheme)).left.map(_ => Malformed)
      case (a @ (PS256 | RS256), ImportedPublicKey.Rsa(k)) =>
        Signature.of(RSA)(parsed.signature).map(s => rsa.verify(k, parsed.input, s, a.scheme)).left.map(_ => Malformed)
      case _ => Left(KeyAlgorithmMismatch)
    outcome match
      case Left(r)  => Eff.fail(r)
      case Right(v) => v.mapError(_ => BadSignature: Rejected)
  end verifyArm

  /** Verify a token under the key carried in its own protected header (`jwk`), enforcing the
    * required header `typ` - the self-keyed profile (DPoP, RFC 9449). Success proves possession of
    * the embedded key's private half and nothing more, so the key is returned for the caller to
    * bind to an external trust statement (for DPoP, the RFC 7638 thumbprint against the access
    * token's `cnf.jkt`) - a [[Verified]] on its own is not an identity. An unusable embedded key is
    * [[Malformed]] (attacker-supplied token material whose import detail feeds no verifier
    * decision); a symmetric algorithm never verifies here ([[KeyAlgorithmMismatch]]).
    */
  def verifyWithHeaderKey(token: String, typ: String, policy: Policy, now: Long)(using
    ed: Verifying[Ed25519],
    p256: Verifying[P256],
    p384: Verifying[P384],
    p521: Verifying[P521],
    rsa: Verifying[RSA],
    edK: EdKeys,
    p256K: EcKeys[P256],
    p384K: EcKeys[P384],
    p521K: EcKeys[P521],
    rsaK: RsaKeys
  ): Eff[Rejected, (Verified, JWK)] =
    parsed(token).flatMap { parsed =>
      policy.algorithms.find(_.accepts(parsed.algName)) match
        case None                            => Eff.fail(UntrustedAlgorithm)
        case Some(alg: JwsAlg.Asymmetric[?]) =>
          val typOk = parsed.header.get("typ") match
            case Some(JoseValue.Str(t)) => t == typ
            case _                      => false
          if !typOk then Eff.fail(TypeMismatch)
          else
            parsed.header.get("jwk") match
              case Some(JoseValue.Obj(fields)) =>
                JWK
                  .parse(Json.value(JoseValue.Obj(fields)))
                  .mapError(_ => Malformed: Rejected)
                  .flatMap(jwk => verifyArm(parsed, alg, jwk.key).flatMap(_ => Eff.from(checkClaims(parsed, policy, now))).map(v => (v, jwk)))
              case _ => Eff.fail(MissingHeaderKey)
        case Some(_) => Eff.fail(KeyAlgorithmMismatch)
    }

  /** Single-key verification for the fixed-key deployment (no JwkSet indirection). */
  def verify[K <: SignatureAlgorithm](token: String, alg: JwsAlg.Asymmetric[K], key: PublicKey[K], policy: Policy, now: Long)(using
    v: Verifying[K]
  ): Eff[Rejected, Verified] =
    parsed(token).flatMap { parsed =>
      if !policy.algorithms.exists(_.accepts(parsed.algName)) then Eff.fail(UntrustedAlgorithm)
      else if !alg.accepts(parsed.algName) then Eff.fail(KeyAlgorithmMismatch)
      else
        Eff.from(sigOf(alg, parsed.signature)).flatMap { s =>
          v.verify(key, parsed.input, s, alg.scheme)
            .mapError(_ => BadSignature: Rejected)
            .flatMap(_ => Eff.from(checkClaims(parsed, policy, now)))
        }
    }

  @targetName("verifyMac")
  def verify[H <: MacAlgorithm](token: String, alg: JwsAlg.Symmetric[H], key: SecretKey[H], policy: Policy, now: Long)(using
    m: MAC[H]
  ): Eff[Rejected, Verified] =
    parsed(token).flatMap { parsed =>
      if !policy.algorithms.exists(_.accepts(parsed.algName)) then Eff.fail(UntrustedAlgorithm)
      else if !alg.accepts(parsed.algName) then Eff.fail(KeyAlgorithmMismatch)
      else
        m.sign(key, parsed.input).flatMap { computed =>
          if Slice.of(Array.from(computed.bytes.iterator)).constantTimeEquals(Slice.of(parsed.signature))
          then Eff.from(checkClaims(parsed, policy, now))
          else Eff.fail(BadSignature)
        }
    }

  // Re-tag the validated octets to the algorithm the alg match proves (Signature is opaque
  // Array[Byte]; `of` validated the length, then the original bytes carry the algorithm K).
  private def sigOf[K <: SignatureAlgorithm](alg: JwsAlg.Asymmetric[K], bytes: Array[Byte]): Either[Rejected, Signature[K]] =
    def retag(v: Either[kufuli.Malformed, ?]): Either[kufuli.Malformed, Signature[K]] = v.map(_ => Signature.unsafe[K](bytes.clone))
    val parsed: Either[kufuli.Malformed, Signature[K]] = alg match
      case ES256 => retag(Signature.of(P256)(bytes))
      case ES384 => retag(Signature.of(P384)(bytes))
      case ES512 => retag(Signature.of(P521)(bytes))
      case EdDSA => retag(Signature.of(Ed25519)(bytes))
      case _     => retag(Signature.of(RSA)(bytes))
    parsed.left.map(_ => Malformed)
end JWT

/** A public key in JWK form (RFC 7517/7518): its JSON document plus the parsed key arm. Build the
  * PUBLISHING direction with `JWK.of` (the /jwks endpoint, OIDC discovery); read the wire direction
  * with `JWK.parse`. `json` is the document this JWK came from - what `of` published (all members
  * lexicographically) or exactly what `parse` was given, including members outside the required
  * set. It is NOT an RFC 7638 canonical form: hashing it yields a thumbprint that does not match
  * the key's, which the `thumbprint` extension computes. Equality is DOCUMENT identity -
  * `(kid, json)` - because the key arm reaches Array-backed material whose `==` is reference
  * identity; KEY identity is `thumbprint`.
  */
final case class JWK(kid: Option[String], key: ImportedPublicKey, json: String):
  override def equals(other: Any): Boolean = other match
    case that: JWK => kid == that.kid && json == that.json
    case _         => false
  override def hashCode: Int = (kid, json).hashCode
object JWK:
  given CanEqual[JWK, JWK] = CanEqual.derived

  // One member order everywhere (lexicographic - the canonical writer's own), so a document kufuli
  // publishes re-parses to an EQUAL value.
  private def withKid(kid: Option[String], canonical: List[(String, String)]): String =
    Json.obj((canonical ++ kid.map(k => "kid" -> Json.str(k)).toList).sortBy(_._1))

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
  private[jose] def canonicalRsa(c: RSA.Components): List[(String, String)] =
    List(
      "e" -> Json.str(Base64Url.encode(Array.from(c.exponent.iterator))),
      "kty" -> Json.str("RSA"),
      "n" -> Json.str(Base64Url.encode(Array.from(c.modulus.iterator)))
    )

  /** Publish an Ed25519 verification key (RFC 8037 OKP form). */
  def of(kid: String, key: PublicKey[Ed25519])(using k: EdKeys): Eff[KeyNotExportable, JWK] =
    key.raw.map(x => JWK(Some(kid), ImportedPublicKey.Ed(key), withKid(Some(kid), canonicalEd(x.bytes))))

  /** Publish an EC verification key; the curve name follows the spec (`P-256`/`P-384`/`P-521`). */
  @targetName("ofEc")
  def of[C <: EcCurve](kid: String, key: PublicKey[C])(using k: EcKeys[C], spec: EcSpec[C]): Eff[KeyNotExportable, JWK] =
    val crv = spec.fieldLength match
      case 32 => "P-256"
      case 48 => "P-384"
      case _  => "P-521"
    val arm: PublicKey[C] => ImportedPublicKey = spec.fieldLength match
      case 32 => c => ImportedPublicKey.EcP256(PublicKey.unsafe[P256](c.repr))
      case 48 => c => ImportedPublicKey.EcP384(PublicKey.unsafe[P384](c.repr))
      case _  => c => ImportedPublicKey.EcP521(PublicKey.unsafe[P521](c.repr))
    key.sec1.map(s => JWK(Some(kid), arm(key), withKid(Some(kid), canonicalEc(crv, s.bytes, spec.fieldLength))))

  /** Publish an RSA verification key (the JWK `n`/`e` pair). */
  @targetName("ofRsa")
  def of(kid: String, key: PublicKey[RSA])(using k: RsaKeys): Eff[KeyNotExportable, JWK] =
    key.components.map(c => JWK(Some(kid), ImportedPublicKey.Rsa(key), withKid(Some(kid), canonicalRsa(c))))

  /** Parse a single JWK document - OKP/Ed25519, EC/P-256/P-384/P-521, RSA - through the lifecycle
    * imports, so the key is typed-validated rather than merely decoded.
    */
  def parse(json: String)(using
    ed: EdKeys,
    p256: EcKeys[P256],
    p384: EcKeys[P384],
    p521: EcKeys[P521],
    rsa: RsaKeys
  ): Eff[Malformed | InvalidKey, JWK] =
    Json.parse(json) match
      case None         => Eff.fail(Malformed)
      case Some(fields) =>
        def str(n: String) = fields.get(n) match
          case Some(JoseValue.Str(s)) => Some(s)
          case _                      => None
        def b64(n: String): Either[Malformed | InvalidKey, Array[Byte]] =
          str(n).toRight(Malformed).flatMap(t => Base64Url.decode(t).left.map(_ => Malformed))
        // RFC 7518 section 6.2.1.2/6.2.1.3: each coordinate is the full curve size, left-padded.
        // Without the check a short `x` and a long `y` reassemble into a point of the right total
        // length, so two documents name one key.
        def point(fieldLength: Int): Either[Malformed | InvalidKey, Array[Byte]] =
          for
            x <- b64("x")
            y <- b64("y")
            _ <- Either.cond(x.length == fieldLength, (), InvalidKey.WrongLength(fieldLength, x.length))
            _ <- Either.cond(y.length == fieldLength, (), InvalidKey.WrongLength(fieldLength, y.length))
          yield Array[Byte](4) ++ x ++ y
        val kid = str("kid")
        (str("kty"), str("crv")) match
          case (Some("OKP"), Some("Ed25519")) =>
            Eff.from(b64("x")).flatMap(x => PublicKey.parse(Ed25519)(Raw(Slice.of(x))).map(k => JWK(kid, ImportedPublicKey.Ed(k), json)))
          case (Some("EC"), Some("P-256")) =>
            Eff
              .from(point(P256.fieldLength))
              .flatMap(pt => PublicKey.parse(P256)(SEC1(Slice.of(pt))).map(k => JWK(kid, ImportedPublicKey.EcP256(k), json)))
          case (Some("EC"), Some("P-384")) =>
            Eff
              .from(point(P384.fieldLength))
              .flatMap(pt => PublicKey.parse(P384)(SEC1(Slice.of(pt))).map(k => JWK(kid, ImportedPublicKey.EcP384(k), json)))
          case (Some("EC"), Some("P-521")) =>
            Eff
              .from(point(P521.fieldLength))
              .flatMap(pt => PublicKey.parse(P521)(SEC1(Slice.of(pt))).map(k => JWK(kid, ImportedPublicKey.EcP521(k), json)))
          case (Some("RSA"), _) =>
            Eff
              .from(for n <- b64("n"); e <- b64("e") yield (n, e))
              .flatMap((n, e) =>
                PublicKey.of(RSA.Components(IArray.from(n), IArray.from(e))).map(k => JWK(kid, ImportedPublicKey.Rsa(k), json))
              )
          case _ => Eff.fail(InvalidKey.Unsupported)
        end match
end JWK

/** A key set for verification and publication: `find` for the verify path, `json` for the /jwks
  * endpoint (RFC 7517 `{"keys": [...]}`).
  */
final case class JwkSet(keys: List[JWK])
object JwkSet:
  given CanEqual[JwkSet, JwkSet] = CanEqual.derived
  def apply(keys: JWK*): JwkSet = new JwkSet(keys.toList)

  /** Reads an RFC 7517 `{"keys": [...]}` document - the fetched-JWKS direction of the bearer flow.
    * A member is SKIPPED only when its own declaration says kufuli does not serve it: a `kty` it
    * has no arm for, or a `crv` outside its curve set (RFC 7517 section 5: clients ignore JWKs they
    * do not understand), so a provider mixing supported and exotic keys stays consumable. ANY
    * failure on a member of a served family - a declaration that is not even readable, a
    * malformation, or a strength kufuli declines - fails the set. A skipped member's kid then
    * surfaces as `UnknownKey` at verify - the refresh signal. Member `json` re-emits canonically:
    * byte fidelity of a FOREIGN document is not preserved (kufuli's own published documents
    * round-trip exactly).
    */
  // The skip decision is made from the member's DECLARED type alone, never from a failure arm:
  // InvalidKey.Unsupported also names a key kufuli declines on STRENGTH (the RSA floor), and
  // skipping on the arm would erase that signal from an operator's set. An UNREADABLE declaration
  // is not a skip either - `kty` is REQUIRED (RFC 7517 section 4.1) and `crv` is REQUIRED of EC and
  // OKP keys (RFC 7518 section 6.2.1.1, RFC 8037 section 2), so a member missing one is malformed,
  // not exotic. Skipping it would turn an operator's typo into a permanent UnknownKey and, for the
  // consumer that refetches on UnknownKey, into an unbounded refetch loop against the provider.
  private def served(o: JoseValue.Obj): Either[Malformed, Boolean] =
    def str(n: String): Option[String] = o.fields.get(n) match
      case Some(JoseValue.Str(s)) => Some(s)
      case _                      => None
    def curve(serves: String => Boolean): Either[Malformed, Boolean] = str("crv").toRight(Malformed).map(serves)
    str("kty") match
      case None        => Left(Malformed)
      case Some("OKP") => curve(_ == "Ed25519")
      case Some("EC")  => curve(c => c == "P-256" || c == "P-384" || c == "P-521")
      case Some("RSA") => Right(true)
      case Some(_)     => Right(false)

  def parse(json: String): Eff[Malformed | InvalidKey, JwkSet] =
    Json.parse(json) match
      case None         => Eff.fail(Malformed)
      case Some(fields) =>
        fields.get("keys") match
          case Some(JoseValue.Arr(members)) =>
            members
              .foldLeft(Eff.succeed(List.empty[JWK]): Eff[Malformed | InvalidKey, List[JWK]]) { (acc, m) =>
                m match
                  case o: JoseValue.Obj =>
                    served(o) match
                      case Left(e)      => acc.flatMap(_ => Eff.fail(e))
                      case Right(false) => acc
                      case Right(true)  => acc.flatMap(ks => JWK.parse(Json.value(o)).map(k => k :: ks))
                  case _ => acc.flatMap(_ => Eff.fail(Malformed))
              }
              .map(ks => new JwkSet(ks.reverse))
          case _ => Eff.fail(Malformed)

  extension (set: JwkSet)
    def find(kid: String): Option[JWK] = set.keys.find(_.kid.contains(kid))

    /** The RFC 7517 `{"keys": [...]}` document, each member exactly as its [[JWK]] carries it. */
    def json: String = set.keys.map(_.json).mkString("""{"keys":[""", ",", "]}")
end JwkSet

private def canonJson(fields: List[(String, String)]): Slice =
  Slice.of(fields.map((k, v) => s"\"$k\":$v").mkString("{", ",", "}").getBytes("UTF-8"))
extension (pub: PublicKey[Ed25519])
  /** RFC 7638 JWK thumbprint (SHA-256 default). The explicit-spec overload admits Sha1 for
    * x5t-class digests - the only position Sha1 is allowed.
    */
  @targetName("thumbprintEd")
  def thumbprint(using EdKeys, Hash[Sha256]): Eff[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintEdSpec")
  def thumbprint[D <: HashAlgorithm](spec: HashSpec[D])(using k: EdKeys, h: Hash[D]): Eff[KeyNotExportable, Digest] =
    pub.raw.flatMap(x => spec.digest(canonJson(JWK.canonicalEd(x.bytes))))
extension [C <: EcCurve](pub: PublicKey[C])
  @targetName("thumbprintEc")
  def thumbprint(using EcKeys[C], EcSpec[C], Hash[Sha256]): Eff[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintEcSpec")
  def thumbprint[D <: HashAlgorithm](hs: HashSpec[D])(using k: EcKeys[C], spec: EcSpec[C], h: Hash[D]): Eff[KeyNotExportable, Digest] =
    val crv = spec.fieldLength match
      case 32 => "P-256"
      case 48 => "P-384"
      case _  => "P-521"
    pub.sec1.flatMap(s => hs.digest(canonJson(JWK.canonicalEc(crv, s.bytes, spec.fieldLength))))
extension (pub: PublicKey[RSA])
  @targetName("thumbprintRsa")
  def thumbprint(using RsaKeys, Hash[Sha256]): Eff[KeyNotExportable, Digest] = pub.thumbprint(Sha256)
  @targetName("thumbprintRsaSpec")
  def thumbprint[D <: HashAlgorithm](spec: HashSpec[D])(using k: RsaKeys, h: Hash[D]): Eff[KeyNotExportable, Digest] =
    pub.components.flatMap(c => spec.digest(canonJson(JWK.canonicalRsa(c))))

/** COSE_Key (RFC 9052/9053) import - the passkey-server key seam: WebAuthn credential public keys
  * arrive as COSE, not JWK. Parse yields the same import arms as SPKI/JWK; verification then uses
  * the ordinary ops. The WebAuthn ceremony (attestation formats, authenticator data, challenge
  * binding) is out of scope - this is the key-import boundary. The supported subset is OKP/Ed25519
  * and EC2/P-256, the WebAuthn credential-key algorithms.
  */
object CoseKey:
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
  // A CBOR argument is 64-bit; narrowing it silently would map 2^32 onto an empty byte string and
  // a label of 0xFFFFFFFF00000001 onto 1 (`kty`), which is a parser differential on credential keys.
  private def int32(arg: Long): Option[Int] = if arg < 0L || arg > Int.MaxValue.toLong then None else Some(arg.toInt)

  private def readInt(c: Cur): Option[(Int, Cur)] =
    head(c).flatMap { (major, arg, c2) =>
      major match
        case 0 => int32(arg).map((_, c2))
        case 1 => int32(arg).map(v => (-1 - v, c2))
        case _ => None
    }
  private def readBytes(c: Cur): Option[(Array[Byte], Cur)] =
    head(c).flatMap { (major, arg, c2) =>
      int32(arg)
        .filter(len => major == 2 && c2.pos + len <= c2.b.length && c2.pos + len >= c2.pos)
        .map(len => (c2.b.slice(c2.pos, c2.pos + len), Cur(c2.b, c2.pos + len)))
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
            int32(arg).filter(len => c2.pos + len <= c2.b.length && c2.pos + len >= c2.pos).map(len => Cur(c2.b, c2.pos + len))
          case 4 => int32(arg).flatMap(n => skipMany(c2, n.toLong, depth + 1))
          case 5 => int32(arg).flatMap(n => skipMany(c2, 2L * n.toLong, depth + 1))
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
        @tailrec def loop(c: Cur, i: Long, seen: Set[Int], acc: Fields): Option[(Fields, Cur)] =
          if i >= count then Some((acc, c))
          else
            readInt(c) match
              case None => None
              // A repeated label leaves which occurrence wins to the reader, so one encoding names
              // two keys depending on who parses it.
              case Some((label, _)) if seen(label) => None
              case Some((label, c1))               =>
                val stepped = label match
                  case 1  => readInt(c1).map((v, c2) => (acc.copy(kty = v), c2))
                  case 3  => readInt(c1).map((_, c2) => (acc, c2))
                  case -1 => readInt(c1).map((v, c2) => (acc.copy(crv = v), c2))
                  case -2 => readBytes(c1).map((v, c2) => (acc.copy(x = v), c2))
                  case -3 => readBytes(c1).map((v, c2) => (acc.copy(y = v), c2))
                  case _  => skip(c1, 0).map(c2 => (acc, c2))
                stepped match
                  case Some((acc2, c2)) => loop(c2, i + 1, seen + label, acc2)
                  case None             => None
        loop(c0, 0, Set.empty, Fields(Int.MinValue, Int.MinValue, Array.emptyByteArray, Array.emptyByteArray))
          // Bytes after the map would let one credential key be encoded many ways, and anything
          // keyed on the encoded form stops identifying the key.
          .filter((_, end) => end.pos == cbor.length)
          .map((f, _) => f)
    }

  def parse(cbor: Array[Byte])(using ed: EdKeys, p256: EcKeys[P256]): Eff[InvalidKey, ImportedPublicKey] =
    readMap(cbor) match
      case None    => Eff.fail(InvalidKey.Malformed)
      case Some(f) =>
        // OKP(1)/Ed25519(6); EC2(2)/P-256(1) reassembled to an uncompressed SEC1 point. RFC 9053
        // section 7.1.1 fixes each coordinate at the full curve size, so a short `x` padded by a
        // long `y` must not reassemble into a point of the right total length.
        if f.kty == 1 && f.crv == 6 then PublicKey.parse(Ed25519)(Raw(Slice.of(f.x))).map(ImportedPublicKey.Ed(_))
        else if f.kty == 2 && f.crv == 1 then
          if f.x.length != P256.fieldLength then Eff.fail(InvalidKey.WrongLength(P256.fieldLength, f.x.length))
          else if f.y.length != P256.fieldLength then Eff.fail(InvalidKey.WrongLength(P256.fieldLength, f.y.length))
          else PublicKey.parse(P256)(SEC1(Slice.of(Array[Byte](4) ++ f.x ++ f.y))).map(ImportedPublicKey.EcP256(_))
        else Eff.fail(InvalidKey.Unsupported)
end CoseKey
