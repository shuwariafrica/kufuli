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
package kufuli

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.codec

/** PEM textual encoding (RFC 7468): labelled base64 DER blocks. Pure value layer. `decode` reads
  * the first block; `decodeAll` reads every block (fullchain files); `encode` wraps at 64 columns.
  */
object PEM:
  /** The reader CLASSIFIES by label, so the operator-facing mistake - a certificate where a key was
    * expected - is an exhaustively-checkable match at the file boundary rather than a parse failure
    * at a door. Arms carry the format types the import doors take, so the classification happens
    * ONCE. `Other` keeps every label kufuli has no opinion about READABLE as data (a PEM file is a
    * container: `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `X509 CRL`, ...), never an error, with
    * the label preserved verbatim for the consumer's own dispatch. Traditional-format (PKCS#1/SEC1)
    * and passphrase-encrypted keys have no kufuli import door; `Other`'s preserved label is what
    * lets a consumer tell an operator to convert the file.
    */
  enum Block:
    case Certificate(der: IArray[Byte])
    case PrivateKey(key: PKCS8)
    case PublicKey(key: SPKI)
    case Other(label: String, der: IArray[Byte])

  private def payload(block: Block): (String, IArray[Byte]) = block match
    case Block.Certificate(der)  => ("CERTIFICATE", der)
    case Block.PrivateKey(key)   => ("PRIVATE KEY", key.bytes)
    case Block.PublicKey(key)    => ("PUBLIC KEY", key.bytes)
    case Block.Other(label, der) => (label, der)

  private def classify(label: String, der: IArray[Byte]): Block = label match
    case "CERTIFICATE" => Block.Certificate(der)
    case "PRIVATE KEY" => Block.PrivateKey(PKCS8(der))
    case "PUBLIC KEY"  => Block.PublicKey(SPKI(der))
    case other         => Block.Other(other, der)

  def encode(block: Block): String =
    val (label, der) = payload(block)
    val body = codec.Base64.encode(Array.from(der.iterator)).grouped(64).mkString("\n")
    s"-----BEGIN $label-----\n$body\n-----END $label-----"

  def decode(text: String): Either[Malformed, Block] =
    decodeAll(text).flatMap(_.headOption.toRight(Malformed))

  def decodeAll(text: String): Either[Malformed, List[Block]] =
    val lines = text.linesIterator.map(_.trim).filter(_.nonEmpty).toList
    @tailrec def go(rest: List[String], acc: List[Block]): Either[Malformed, List[Block]] =
      rest match
        case Nil                                                                            => Right(acc.reverse)
        case header :: tail if header.startsWith("-----BEGIN ") && header.endsWith("-----") =>
          val label = header.stripPrefix("-----BEGIN ").stripSuffix("-----")
          val footer = s"-----END $label-----"
          val (body, remainder) = tail.span(_ != footer)
          remainder match
            case `footer` :: after =>
              codec.Base64.decode(body.mkString) match
                case Right(der) => go(after, classify(label, IArray.from(der)) :: acc)
                case Left(_)    => Left(Malformed)
            case _ => Left(Malformed)
        case _ => Left(Malformed)
    go(lines, Nil)
  end decodeAll
end PEM

/** Shared, bounded DER handling for key encodings. The shared layer only PEEKS the
  * AlgorithmIdentifier of an SPKI/PKCS#8 blob to dispatch to a key family - full validation and
  * construction is backend work on the whole blob (JCA KeySpec, WebCrypto importKey, aws-lc
  * EVP_parse_*). A wire parser over untrusted bytes: every read is bounds-checked, lengths accept
  * only definite short/1/2-byte long forms, and no recursion occurs.
  */
private[kufuli] object DER:
  enum Alg derives CanEqual:
    case Ed, X, EcP256, EcP384, EcP521, Rsa

  // OID content bytes (verified against the aws-lc object registry / RFC 8410 / RFC 5480 / RFC 8017).
  private val oidEd = Array[Byte](0x2b, 0x65, 0x70) // 1.3.101.112
  private val oidX = Array[Byte](0x2b, 0x65, 0x6e) // 1.3.101.110
  private[kufuli] val oidEcPublic = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x02, 0x01) // 1.2.840.10045.2.1
  private[kufuli] val oidP256 = Array[Byte](0x2a, 0x86.toByte, 0x48, 0xce.toByte, 0x3d, 0x03, 0x01, 0x07) // 1.2.840.10045.3.1.7
  private[kufuli] val oidP384 = Array[Byte](0x2b, 0x81.toByte, 0x04, 0x00, 0x22) // 1.3.132.0.34
  private[kufuli] val oidP521 = Array[Byte](0x2b, 0x81.toByte, 0x04, 0x00, 0x23) // 1.3.132.0.35
  private[kufuli] val oidRsa = Array[Byte](0x2a, 0x86.toByte, 0x48, 0x86.toByte, 0xf7.toByte, 0x0d, 0x01, 0x01, 0x01) // 1.2.840.113549.1.1.1

  final private[kufuli] case class Tlv(contentOff: Int, contentLen: Int, next: Int)

  // Reads one definite-length TLV at `off`, requiring the given tag. Rejects indefinite and
  // long-form lengths beyond two bytes (no key encoding needs them), a length not in its shortest
  // form, and any out-of-bounds claim. Shortest-form matters beyond pedantry: a long-form encoding
  // of a small length shifts every subsequent offset, which is how a fixed-prefix reader above this
  // one can be steered onto the wrong bytes.
  private[kufuli] def read(der: Slice, off: Int, tag: Int): Either[InvalidKey, Tlv] =
    if off + 2 > der.length then Left(InvalidKey.Malformed)
    else if (der(off) & 0xff) != tag then Left(InvalidKey.Malformed)
    else
      val l0 = der(off + 1) & 0xff
      val header =
        if l0 < 0x80 then Right((l0, 2))
        else if l0 == 0x81 && off + 3 <= der.length then
          val len = der(off + 2) & 0xff
          if len < 0x80 then Left(InvalidKey.Malformed) else Right((len, 3))
        else if l0 == 0x82 && off + 4 <= der.length then
          val len = ((der(off + 2) & 0xff) << 8) | (der(off + 3) & 0xff)
          if len < 0x100 then Left(InvalidKey.Malformed) else Right((len, 4))
        else Left(InvalidKey.Malformed)
      header.flatMap { (len, hdr) =>
        val start = off + hdr
        if start + len > der.length then Left(InvalidKey.Malformed)
        else Right(Tlv(start, len, start + len))
      }

  /** As [[read]], additionally bounding the TLV by the structure that contains it - the core reader
    * bounds only by the whole buffer, so a child claiming a length past its parent would otherwise
    * count bytes the parent does not carry.
    */
  private[kufuli] def within(der: Slice, off: Int, tag: Int, limit: Int): Either[InvalidKey, Tlv] =
    read(der, off, tag).filterOrElse(_.next <= limit, InvalidKey.Malformed)

  private def oidAt(der: Slice, off: Int): Either[InvalidKey, (Slice, Int)] =
    read(der, off, 0x06).map(t => (der.slice(t.contentOff, t.next), t.next))

  private def matches(oid: Slice, expected: Array[Byte]): Boolean = oid.contentEquals(Slice.of(expected))

  private def dispatch(der: Slice, algIdOff: Int): Either[InvalidKey, Alg] =
    read(der, algIdOff, 0x30).flatMap { algId =>
      oidAt(der, algId.contentOff).flatMap { (oid, next) =>
        if matches(oid, oidEd) then Right(Alg.Ed)
        else if matches(oid, oidX) then Right(Alg.X)
        else if matches(oid, oidRsa) then Right(Alg.Rsa)
        else if matches(oid, oidEcPublic) then
          oidAt(der, next).flatMap { (curve, _) =>
            if matches(curve, oidP256) then Right(Alg.EcP256)
            else if matches(curve, oidP384) then Right(Alg.EcP384)
            else if matches(curve, oidP521) then Right(Alg.EcP521)
            else Left(InvalidKey.Unsupported)
          }
        else Left(InvalidKey.Unsupported)
      }
    }

  // The outer SEQUENCE must span the whole slice. Anything appended past it is a second encoding
  // the peek never sees: the family dispatch would report the prefix's algorithm while a permissive
  // backend parses the prefix and ignores the suffix, so two readers disagree about one blob.
  private def whole(der: Slice, outer: Tlv): Either[InvalidKey, Unit] =
    if outer.next == der.length then Right(()) else Left(InvalidKey.Malformed)

  /** Peeks the AlgorithmIdentifier of a SubjectPublicKeyInfo blob. */
  def peekSpki(der: Slice): Either[InvalidKey, Alg] =
    read(der, 0, 0x30).flatMap(outer => whole(der, outer).flatMap(_ => dispatch(der, outer.contentOff)))

  /** Peeks the AlgorithmIdentifier of a PKCS#8 PrivateKeyInfo blob (skips the version INTEGER). */
  def peekPkcs8(der: Slice): Either[InvalidKey, Alg] =
    read(der, 0, 0x30).flatMap(outer => whole(der, outer).flatMap(_ => read(der, outer.contentOff, 0x02).flatMap(v => dispatch(der, v.next))))

  /** The subjectPublicKey octets of an SPKI, located by walking the encoding: the
    * AlgorithmIdentifier is variable-length, so any fixed prefix length reads the wrong bytes for a
    * blob that is valid but not byte-identical to kufuli's own template.
    */
  def spkiPublicBits(der: Slice): Either[InvalidKey, Slice] =
    for
      outer <- read(der, 0, 0x30)
      _ <- whole(der, outer)
      algId <- read(der, outer.contentOff, 0x30)
      bits <- read(der, algId.next, 0x03)
      // A public key occupies whole octets, so the unused-bits count is present and zero, and the
      // BIT STRING is the last element of the SPKI.
      _ <-
        if bits.next == outer.next && bits.contentLen >= 1 && der(bits.contentOff) == 0.toByte then Right(())
        else Left(InvalidKey.Malformed)
    yield der.slice(bits.contentOff + 1, bits.next)

  /** Requires a stored SPKI to name exactly `alg` - the family and, for EC, the named curve.
    * Applied to a backend's own canonical re-marshalling this is what binds an import to the family
    * the caller asked for: every provider here infers the family from the encoding instead.
    */
  def requireSpki(der: Slice, alg: Alg): Either[InvalidKey, Unit] =
    peekSpki(der).flatMap(found => if found == alg then Right(()) else Left(InvalidKey.Malformed))

  /** As [[requireSpki]], over a PKCS#8 PrivateKeyInfo. */
  def requirePkcs8(der: Slice, alg: Alg): Either[InvalidKey, Unit] =
    peekPkcs8(der).flatMap(found => if found == alg then Right(()) else Left(InvalidKey.Malformed))

  /** True when one definite-length TLV of `tag` spans the whole slice - the anti-ambiguity check a
    * permissive backend does not make for itself.
    */
  def spansWhole(der: Slice, tag: Int): Boolean = read(der, 0, tag).exists(_.next == der.length)

  /** As [[spkiPublicBits]], additionally requiring the family's exact point length. */
  def spkiPublicBits(der: Slice, length: Int): Either[InvalidKey, Slice] =
    spkiPublicBits(der).flatMap(point => if point.length == length then Right(point) else Left(InvalidKey.WrongLength(length, point.length)))

  // Fixed encoding templates (RFC 8410 / RFC 5480 layouts) for byte-backed backends that build and
  // match whole SPKI/PKCS#8 blobs directly; the JCA/WebCrypto backends round-trip through their
  // platform key APIs instead.
  private[kufuli] val edSpkiPrefix: Array[Byte] =
    Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
  private[kufuli] val xSpkiPrefix: Array[Byte] =
    Array[Byte](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00)
  private[kufuli] val edPkcs8Prefix: Array[Byte] =
    Array[Byte](0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20)
  private[kufuli] val xPkcs8Prefix: Array[Byte] =
    Array[Byte](0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20)
  private[kufuli] val p256SpkiPrefix: Array[Byte] =
    Array[Byte](
      0x30,
      0x59,
      0x30,
      0x13,
      0x06,
      0x07,
      0x2a,
      0x86.toByte,
      0x48,
      0xce.toByte,
      0x3d,
      0x02,
      0x01,
      0x06,
      0x08,
      0x2a,
      0x86.toByte,
      0x48,
      0xce.toByte,
      0x3d,
      0x03,
      0x01,
      0x07,
      0x03,
      0x42,
      0x00
    )
  private[kufuli] val p384SpkiPrefix: Array[Byte] =
    Array[Byte](0x30,
                0x76,
                0x30,
                0x10,
                0x06,
                0x07,
                0x2a,
                0x86.toByte,
                0x48,
                0xce.toByte,
                0x3d,
                0x02,
                0x01,
                0x06,
                0x05,
                0x2b,
                0x81.toByte,
                0x04,
                0x00,
                0x22,
                0x03,
                0x62,
                0x00
    )
  private[kufuli] val p521SpkiPrefix: Array[Byte] =
    Array[Byte](
      0x30,
      0x81.toByte,
      0x9b.toByte,
      0x30,
      0x10,
      0x06,
      0x07,
      0x2a,
      0x86.toByte,
      0x48,
      0xce.toByte,
      0x3d,
      0x02,
      0x01,
      0x06,
      0x05,
      0x2b,
      0x81.toByte,
      0x04,
      0x00,
      0x23,
      0x03,
      0x81.toByte,
      0x86.toByte,
      0x00
    )

  // Minimal DER emitters (definite lengths up to two bytes) for the ECDSA signature codec and the
  // byte-backed backends that assemble encodings directly.
  private[kufuli] def tlv(tag: Int, content: Array[Byte]): Array[Byte] =
    val len = content.length
    require(len < 0x10000, s"DER content of $len bytes exceeds the two-byte length forms this emitter writes")
    val header =
      if len < 0x80 then Array[Byte](tag.toByte, len.toByte)
      else if len < 0x100 then Array[Byte](tag.toByte, 0x81.toByte, len.toByte)
      else Array[Byte](tag.toByte, 0x82.toByte, (len >> 8).toByte, len.toByte)
    header ++ content
  private[kufuli] def sequence(parts: Array[Byte]*): Array[Byte] =
    tlv(0x30, parts.foldLeft(Array.emptyByteArray)(_ ++ _))
  private[kufuli] def objectId(content: Array[Byte]): Array[Byte] = tlv(0x06, content)
  private[kufuli] def integer(magnitude: Array[Byte]): Array[Byte] = tlv(0x02, Array[Byte](0) ++ magnitude)
  private[kufuli] def octetString(content: Array[Byte]): Array[Byte] = tlv(0x04, content)
  private[kufuli] def bitString(content: Array[Byte]): Array[Byte] = tlv(0x03, Array[Byte](0) ++ content)
  private[kufuli] val nullValue: Array[Byte] = Array[Byte](0x05, 0x00)

  /** Strict template match: `prefix ++ payload(payloadLen)`, for byte-backed key imports. */
  private[kufuli] def payload(der: Slice, prefix: Array[Byte], payloadLen: Int): Either[InvalidKey, Slice] =
    if der.length == prefix.length + payloadLen && der.take(prefix.length).contentEquals(Slice.of(prefix))
    then Right(der.drop(prefix.length))
    else Left(InvalidKey.Malformed)
end DER
