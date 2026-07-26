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

/** RFC 4648 section 5 base64url, UNPADDED - the JOSE and web-token alphabet. `decode` admits only
  * the one canonical encoding of an octet string: padding, `+`, `/`, any non-alphabet character, an
  * impossible length (4k+1), or a short final group whose unused low bits are set is [[Malformed]].
  */
object Base64Url:
  def encode(bytes: Array[Byte]): String = Base64.encode(bytes, Base64.urlAlphabet, pad = false)
  def decode(text: String): Either[Malformed, Array[Byte]] = Base64.decode(text, Base64.urlInverse, padded = false)

/** RFC 4648 section 6 base32, UNPADDED upper case - the alphabet `otpauth://` enrolment URIs and
  * authenticator apps carry a shared secret in. `decode` admits only the one canonical encoding:
  * lower case, `=` padding, any character outside `A-Z2-7`, a length of 1, 3 or 6 modulo 8, or a
  * final symbol whose unused low bits are set is [[Malformed]]. Table-driven, so NOT constant time:
  * an enrolment secret is transcribed once by a human, never compared on a request path.
  */
object Base32:
  private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  private val inverse: Array[Int] =
    val t = Array.fill(128)(-1)
    for i <- 0 until alphabet.length do t(alphabet.charAt(i).toInt) = i
    t

  def encode(bytes: Array[Byte]): String =
    val out = new StringBuilder((bytes.length * 8 + 4) / 5)
    @tailrec def go(i: Int, acc: Int, bits: Int): Unit =
      if bits >= 5 then
        val _ = out.append(alphabet((acc >>> (bits - 5)) & 0x1f))
        go(i, acc & ((1 << (bits - 5)) - 1), bits - 5)
      else if i < bytes.length then go(i + 1, (acc << 8) | (bytes(i) & 0xff), bits + 8)
      else if bits > 0 then
        val _ = out.append(alphabet((acc << (5 - bits)) & 0x1f))
        ()
    go(0, 0, 0)
    out.toString
  end encode

  def decode(text: String): Either[Malformed, Array[Byte]] =
    val residue = text.length % 8
    // 5 bits per symbol: 1, 3 and 6 symbols carry 5, 15 and 30 bits, none of which completes an
    // octet count that 8 fewer symbols could not encode - so no octet string produces them.
    if residue == 1 || residue == 3 || residue == 6 then Left(Malformed)
    else
      val out = new Array[Byte](text.length / 8 * 5 + residue * 5 / 8)
      @tailrec def go(i: Int, acc: Int, bits: Int, o: Int): Either[Malformed, Array[Byte]] =
        if i >= text.length then
          // The final symbol's low bits reach no octet; unless they are zero one secret has many
          // spellings, and an enrolment record keyed on the string no longer identifies the secret.
          if acc != 0 then Left(Malformed) else Right(out)
        else
          val c = text.charAt(i).toInt
          val v = if c < 128 then inverse(c) else -1
          if v < 0 then Left(Malformed)
          else
            val a = (acc << 5) | v
            val b = bits + 5
            if b >= 8 then
              out(o) = ((a >>> (b - 8)) & 0xff).toByte
              go(i + 1, a & ((1 << (b - 8)) - 1), b - 8, o + 1)
            else go(i + 1, a, b, o)
      go(0, 0, 0, 0)
    end if
  end decode
end Base32

private[kufuli] object Base64:
  private[kufuli] val urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  private[kufuli] val stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  private def inverse(alphabet: String): Array[Int] =
    val t = Array.fill(128)(-1)
    for i <- 0 until alphabet.length do t(alphabet.charAt(i).toInt) = i
    t
  private[kufuli] val urlInverse = inverse(urlAlphabet)
  private[kufuli] val stdInverse = inverse(stdAlphabet)

  private[kufuli] def encode(bytes: Array[Byte], alphabet: String, pad: Boolean): String =
    val out = new StringBuilder((bytes.length + 2) / 3 * 4)
    @tailrec def full(i: Int): Int =
      if i + 3 <= bytes.length then
        val n = ((bytes(i) & 0xff) << 16) | ((bytes(i + 1) & 0xff) << 8) | (bytes(i + 2) & 0xff)
        val _ = out
          .append(alphabet((n >> 18) & 0x3f))
          .append(alphabet((n >> 12) & 0x3f))
          .append(alphabet((n >> 6) & 0x3f))
          .append(alphabet(n & 0x3f))
        full(i + 3)
      else i
    val i = full(0)
    bytes.length - i match
      case 1 =>
        val n = (bytes(i) & 0xff) << 16
        val _ = out.append(alphabet((n >> 18) & 0x3f)).append(alphabet((n >> 12) & 0x3f))
        if pad then out.append("==")
      case 2 =>
        val n = ((bytes(i) & 0xff) << 16) | ((bytes(i + 1) & 0xff) << 8)
        val _ = out.append(alphabet((n >> 18) & 0x3f)).append(alphabet((n >> 12) & 0x3f)).append(alphabet((n >> 6) & 0x3f))
        if pad then out.append('=')
      case _ => ()
    out.toString
  end encode

  private[kufuli] def encode(bytes: Array[Byte]): String = encode(bytes, stdAlphabet, pad = true)

  private[kufuli] def decode(text: String, table: Array[Int], padded: Boolean): Either[Malformed, Array[Byte]] =
    def stripped: Either[Malformed, String] =
      if !padded then Right(text)
      else if text.length % 4 != 0 then Left(Malformed)
      else
        val padding = text.length - text.lastIndexWhere(_ != '=') - 1
        if padding > 2 then Left(Malformed) else Right(text.dropRight(padding))
    stripped.flatMap { body =>
      if body.length % 4 == 1 then Left(Malformed)
      else
        // length/4*3, not length*3/4: the latter overflows Int past 715,827,882 characters and throws
        // a negative array size out of a total Either.
        val out = new Array[Byte](body.length / 4 * 3 + math.max(body.length % 4 - 1, 0))
        @tailrec def go(i: Int, o: Int): Either[Malformed, Array[Byte]] =
          if i >= body.length then Right(out)
          else
            val chunk = math.min(4, body.length - i)
            if chunk < 2 then Left(Malformed)
            else
              val values = (0 until chunk).map { j =>
                val c = body.charAt(i + j).toInt
                if c < 128 then table(c) else -1
              }
              val acc = values.foldLeft(0)((a, v) => (a << 6) | (v & 0x3f)) << (6 * (4 - chunk))
              // A short final group carries bits below its last octet that no byte receives; unless
              // they are zero one octet string has many encodings, defeating any defence keyed on the
              // encoded string - a replay cache, a denylist, a unique-token column.
              if values.exists(_ < 0) || (acc & ((1 << (8 * (4 - chunk))) - 1)) != 0 then Left(Malformed)
              else
                out(o) = ((acc >> 16) & 0xff).toByte
                if chunk >= 3 then out(o + 1) = ((acc >> 8) & 0xff).toByte
                if chunk == 4 then out(o + 2) = (acc & 0xff).toByte
                go(i + chunk, o + chunk - 1)
            end if
        go(0, 0)
    }
  end decode

  private[kufuli] def decode(text: String): Either[Malformed, Array[Byte]] = decode(text, stdInverse, padded = true)
end Base64

/** PEM textual encoding (RFC 7468): labelled base64 DER blocks. Pure value layer. `decode` reads
  * the first block; `decodeAll` reads every block (fullchain files); `encode` wraps at 64 columns.
  */
object PEM:
  final case class Block(label: String, der: IArray[Byte])
  object Block:
    given CanEqual[Block, Block] = CanEqual.derived

  def encode(block: Block): String =
    val body = Base64.encode(Array.from(block.der.iterator)).grouped(64).mkString("\n")
    s"-----BEGIN ${block.label}-----\n$body\n-----END ${block.label}-----"

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
              Base64.decode(body.mkString) match
                case Right(der) => go(after, Block(label, IArray.from(der)) :: acc)
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
private[kufuli] object Der:
  enum Alg derives CanEqual:
    case Ed, X, EcP256, EcP384, EcP521, OfRsa

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

  private def oidAt(der: Slice, off: Int): Either[InvalidKey, (Slice, Int)] =
    read(der, off, 0x06).map(t => (der.slice(t.contentOff, t.next), t.next))

  private def matches(oid: Slice, expected: Array[Byte]): Boolean = oid.contentEquals(Slice.of(expected))

  private def dispatch(der: Slice, algIdOff: Int): Either[InvalidKey, Alg] =
    read(der, algIdOff, 0x30).flatMap { algId =>
      oidAt(der, algId.contentOff).flatMap { (oid, next) =>
        if matches(oid, oidEd) then Right(Alg.Ed)
        else if matches(oid, oidX) then Right(Alg.X)
        else if matches(oid, oidRsa) then Right(Alg.OfRsa)
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
end Der
