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
package kufuli.x509

import scala.annotation.tailrec

import boilerplate.Slice
import boilerplate.ValueCodec

import kufuli.Malformed

// IPv4 occupies `lo`'s low 32 bits and IPv6 both words, so equality is value equality: an
// IArray-backed address would compare by reference under the derived CanEqual.
final private[x509] case class IpBits(hi: Long, lo: Long, v6: Boolean) derives CanEqual

/** An IPv4 or IPv6 address in network byte order, as an iPAddress SAN carries it; construct via
  * [[IpAddress$ IpAddress]].
  */
opaque type IpAddress = IpBits

object IpAddress:
  given CanEqual[IpAddress, IpAddress] = CanEqual.derived

  /** Parses a presentation-form address - a dotted quad, or RFC 4291 IPv6 text with `::`
    * compression and an optional trailing dotted quad, enclosing brackets accepted.
    */
  def parse(text: String): Either[Malformed, IpAddress] =
    val bare =
      if text.length >= 2 && text.charAt(0) == '[' && text.charAt(text.length - 1) == ']' then text.substring(1, text.length - 1)
      else text
    val parsed = if bare.indexOf(':') >= 0 then ipv6(bare) else ipv4(bare).map(v => IpBits(0L, v, v6 = false))
    parsed.toRight(Malformed)

  /** The wire-text contract: decode IS `parse`, encode the canonical presentation text. */
  given valueCodec: ValueCodec.Aux[IpAddress, Malformed] = ValueCodec(parse, render)

  /** Wraps the 4 or 16 address octets an iPAddress SAN or a TLS peer address supplies. */
  def of(bytes: Slice): Either[Malformed, IpAddress] =
    if bytes.length == 4 then Right(IpBits(0L, bigEndian(bytes, 0, 4), v6 = false))
    else if bytes.length == 16 then Right(IpBits(bigEndian(bytes, 0, 8), bigEndian(bytes, 8, 8), v6 = true))
    else Left(Malformed)

  private[x509] def wrap(packed: IpBits): IpAddress = packed

  extension (a: IpAddress)
    /** The address octets - 4 for IPv4, 16 for IPv6. */
    def bytes: IArray[Byte] =
      if a.v6 then IArray.tabulate(16)(i => (if i < 8 then a.hi >>> ((7 - i) * 8) else a.lo >>> ((15 - i) * 8)).toByte)
      else IArray.tabulate(4)(i => (a.lo >>> ((3 - i) * 8)).toByte)

    /** The canonical presentation text: a dotted quad, or RFC 5952 IPv6 (lowercase groups, the
      * leftmost longest zero run compressed).
      */
    def value: String = render(a)

    private[x509] def bits: IpBits = a
  end extension

  private def render(a: IpAddress): String =
    if !a.v6 then (0 to 3).map(i => ((a.lo >>> ((3 - i) * 8)) & 0xff).toString).mkString(".")
    else
      val gs = IArray.tabulate(8)(i => ((if i < 4 then a.hi >>> ((3 - i) * 16) else a.lo >>> ((7 - i) * 16)) & 0xffff).toInt)
      @tailrec def zeroEnd(j: Int): Int = if j < 8 && gs(j) == 0 then zeroEnd(j + 1) else j
      @tailrec def bestRun(i: Int, best: Int, bestLen: Int): (Int, Int) =
        if i >= 8 then (best, bestLen)
        else if gs(i) == 0 then
          val j = zeroEnd(i)
          if j - i > bestLen then bestRun(j, i, j - i) else bestRun(j, best, bestLen)
        else bestRun(i + 1, best, bestLen)
      val (best, bestLen) = bestRun(0, -1, 0)
      def hex(g: Int): String = Integer.toHexString(g)
      // RFC 5952 section 4.2.1: `::` stands in only for a run of two or more zero groups.
      if bestLen >= 2 then gs.take(best).map(hex).mkString(":") + "::" + gs.drop(best + bestLen).map(hex).mkString(":")
      else gs.map(hex).mkString(":")

  private def bigEndian(s: Slice, off: Int, n: Int): Long =
    (0 until n).foldLeft(0L)((acc, i) => (acc << 8) | (s(off + i) & 0xffL))

  // RFC 3986's dec-octet: a leading zero is rejected rather than read as decimal, because the
  // libc-inherited octal reading of `010` is a classifier disagreement an attacker chooses.
  private def decOctet(text: String): Option[Int] =
    if text.isEmpty || text.length > 3 || (text.length > 1 && text.charAt(0) == '0') then None
    else if !text.forall(c => c >= '0' && c <= '9') then None
    else Some(text.toInt).filter(_ <= 255)

  private[x509] def ipv4(text: String): Option[Long] =
    val parts = text.split('.')
    if parts.length != 4 || text.count(_ == '.') != 3 then None
    else parts.foldLeft(Some(0L): Option[Long])((acc, p) => acc.flatMap(v => decOctet(p).map(o => (v << 8) | o.toLong)))

  private def hex16(text: String): Option[Int] =
    def digit(c: Char): Option[Int] =
      if c >= '0' && c <= '9' then Some(c - '0')
      else if c >= 'a' && c <= 'f' then Some(c - 'a' + 10)
      else if c >= 'A' && c <= 'F' then Some(c - 'A' + 10)
      else None
    if text.isEmpty || text.length > 4 then None
    else text.foldLeft(Some(0): Option[Int])((acc, c) => acc.flatMap(v => digit(c).map(d => (v << 4) | d)))

  // One side of a `::`, or the whole address when there is none. The final token may be a dotted
  // quad (RFC 4291 section 2.2 form 3), which contributes the last two groups.
  private def groups(text: String, quadAllowed: Boolean): Option[List[Int]] =
    if text.isEmpty then Some(Nil)
    else if text.charAt(0) == ':' || text.charAt(text.length - 1) == ':' then None
    else
      val parts = text.split(':').toList
      val quad = quadAllowed && parts.last.indexOf('.') >= 0
      val hexParts = if quad then parts.init else parts
      val head = hexParts.foldLeft(Some(Nil): Option[List[Int]])((acc, p) => acc.flatMap(gs => hex16(p).map(_ :: gs))).map(_.reverse)
      if quad then head.flatMap(gs => ipv4(parts.last).map(v => gs ::: List(((v >>> 16) & 0xffff).toInt, (v & 0xffff).toInt)))
      else head

  private def ipv6(text: String): Option[IpBits] =
    val double = text.indexOf("::")
    if double >= 0 && text.indexOf("::", double + 1) >= 0 then None
    else
      val head = if double >= 0 then text.substring(0, double) else text
      val tail = if double >= 0 then text.substring(double + 2) else ""
      for
        h <- groups(head, quadAllowed = double < 0)
        t <- groups(tail, quadAllowed = double >= 0)
        // `::` stands for at least one all-zero group, so a compressed address carries at most 7.
        all <-
          if double >= 0 then Option.when(h.length + t.length <= 7)(h ::: List.fill(8 - h.length - t.length)(0) ::: t)
          else Option.when(h.length == 8)(h)
      yield IpBits(
        hi = all.take(4).foldLeft(0L)((acc, g) => (acc << 16) | g.toLong),
        lo = all.drop(4).foldLeft(0L)((acc, g) => (acc << 16) | g.toLong),
        v6 = true
      )
      end for
    end if
  end ipv6
end IpAddress

/** The identity a server chain is validated against - a DNS name or an IP literal, classified once
  * so no consumer re-solves it; construct via [[ServerId$ ServerId]].
  */
enum ServerId derives CanEqual:
  case Dns(host: Hostname)
  case Ip(addr: IpAddress)

object ServerId:
  /** Classifies a peer identity: a bracketed or colon-bearing literal is IPv6, four dot-separated
    * decimal octets are IPv4, anything else must parse as a DNS name.
    */
  def parse(text: String): Either[Malformed, ServerId] =
    if text.startsWith("[") || text.indexOf(':') >= 0 || dottedQuadShape(text) then IpAddress.parse(text).map(ServerId.Ip(_))
    else Hostname.parse(text).map(ServerId.Dns(_))

  /** The wire-text contract: decode IS `parse` (the ONE audited RFC 9525 classifier), encode the
    * identity's canonical text.
    */
  given valueCodec: ValueCodec.Aux[ServerId, Malformed] = ValueCodec(
    parse,
    { case ServerId.Dns(h) => Hostname.value(h); case ServerId.Ip(a) => IpAddress.value(a) }
  )

  private def dottedQuadShape(text: String): Boolean =
    val parts = text.split('.')
    parts.length == 4 && text.count(_ == '.') == 3 && parts.forall(p => p.nonEmpty && p.forall(c => c >= '0' && c <= '9'))
end ServerId

// The GeneralName forms RFC 5280 gives no matching rule for, plus uniformResourceIdentifier. A
// constraint naming one of these rejects any certificate presenting that form and is vacuous
// otherwise - section 4.2.1.10's process-or-reject, applied per form.
private[x509] enum UnprocessedForm derives CanEqual:
  case Uri, Other, X400, EdiParty, RegisteredId

// An iPAddress GeneralSubtree: the address and the mask the constraint pairs it with.
final private[x509] case class IpSubtree(base: IpBits, mask: IpBits)

// One AttributeTypeAndValue of a distinguished name. DER lengths are canonical, so tag plus content
// equality is whole-encoding equality.
final private[x509] case class Ava(oid: Array[Byte], tag: Int, content: Array[Byte])

// One GeneralSubtrees list, split by name form.
final private[x509] case class Subtrees(
  dns: List[String],
  ips: List[IpSubtree],
  dirNames: List[List[List[Ava]]],
  emails: List[String],
  unprocessed: Set[UnprocessedForm]
)

private[x509] object Subtrees:
  val empty: Subtrees = Subtrees(Nil, Nil, Nil, Nil, Set.empty)
  extension (s: Subtrees) def size: Int = s.dns.length + s.ips.length + s.dirNames.length + s.emails.length + s.unprocessed.size

// One certificate's NameConstraints extension, both lists parsed and validated.
final private[x509] case class NameConstraints(permitted: Subtrees, excluded: Subtrees)

// RFC 5280 section 4.2.1.10 subtree containment, per name form. Every comparison folds ASCII case
// only: DNS labels and mail domains are ASCII by construction, while `toLowerCase` follows the
// ambient locale and Unicode folding maps distinct code points (U+212A KELVIN SIGN) onto ASCII.
private[x509] object Names:
  private val printableString = 0x13
  private val utf8String = 0x0c

  def foldAscii(text: String): String = text.map(c => if c >= 'A' && c <= 'Z' then (c + 32).toChar else c)

  @tailrec private def labelsOf(text: String, from: Int, acc: List[String]): List[String] =
    val dot = text.indexOf('.', from)
    if dot < 0 then (text.substring(from) :: acc).reverse
    else labelsOf(text, dot + 1, text.substring(from, dot) :: acc)

  private def ldhLabel(label: String): Boolean =
    label.nonEmpty && label.length <= 63 &&
      label.forall(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') &&
      label.charAt(0) != '-' && label.charAt(label.length - 1) != '-'

  // Preferred name syntax. A zero-length base is the CA/Browser Forum's deny-all encoding and is
  // accepted; RFC 5280 defines no leading-dot or wildcard dNSName form, so both are rejected.
  def validDnsBase(name: String): Boolean =
    name.isEmpty || (name.length <= 253 && labelsOf(name, 0, Nil).forall(ldhLabel))

  // A dNSName SAN entry: preferred name syntax, or a single leftmost full-label wildcard.
  def validDnsName(name: String): Boolean =
    if name.startsWith("*.") then name.length > 2 && validDnsBase(name.substring(2))
    else name.nonEmpty && validDnsBase(name)

  def isWildcard(name: String): Boolean = name.startsWith("*.")

  // Whole-label suffix containment: `host.example.com` is within `example.com`, `notexample.com`
  // is not, and a zero-length base contains every name.
  def dnsWithin(name: String, base: String): Boolean =
    if base.isEmpty then true
    else
      val n = foldAscii(name)
      val b = foldAscii(base)
      n == b || (n.length > b.length && n.charAt(n.length - b.length - 1) == '.' && n.endsWith(b))

  // A wildcard SAN satisfies a permitted base only when every name it expands to does, which is
  // exactly the parent being within the base (RUSTSEC-2026-0099).
  def wildcardPermitted(pattern: String, base: String): Boolean = dnsWithin(pattern.substring(2), base)

  // A wildcard SAN violates an excluded base when some name it expands to is within that base: the
  // parent is within the base, or the base is one label below the parent (CVE-2025-61727). The
  // second disjunct cannot fire on a single-label base, which is Go's #76935 regression.
  def wildcardExcluded(pattern: String, base: String): Boolean =
    val parent = pattern.substring(2)
    dnsWithin(parent, base) || oneLabelBelow(base, parent)

  private def oneLabelBelow(base: String, parent: String): Boolean =
    val b = foldAscii(base)
    val p = foldAscii(parent)
    b.length > p.length + 1 && b.endsWith("." + p) && b.substring(0, b.length - p.length - 1).indexOf('.') < 0

  def ipWithin(name: IpBits, subtree: IpSubtree): Boolean =
    name.v6 == subtree.base.v6 &&
      (name.hi & subtree.mask.hi) == (subtree.base.hi & subtree.mask.hi) &&
      (name.lo & subtree.mask.lo) == (subtree.base.lo & subtree.mask.lo)

  // Leading-ones masks only: no CA emits a non-contiguous mask, and RFC 5280 gives the result no
  // meaning, so it is rejected rather than guessed at.
  def contiguousMask(mask: IpBits): Boolean =
    def run(word: Long): Boolean =
      val gaps = ~word
      (gaps & (gaps + 1L)) == 0L
    if mask.v6 then if mask.hi == -1L then run(mask.lo) else mask.lo == 0L && run(mask.hi)
    else
      val gaps = (~mask.lo) & 0xffffffffL
      (gaps & (gaps + 1L)) == 0L

  // RFC 5280 section 7.1: the base's RDN sequence is a leading prefix of the candidate's. An empty
  // base is a prefix of every name.
  def dnWithin(name: List[List[Ava]], base: List[List[Ava]]): Boolean =
    base.length <= name.length && base.zip(name).forall((b, n) => rdnMatch(b, n))

  private def rdnMatch(base: List[Ava], candidate: List[Ava]): Boolean =
    base.length == candidate.length && base.forall(b => candidate.exists(c => avaMatch(b, c)))

  private def avaMatch(base: Ava, candidate: Ava): Boolean =
    bytesEqual(base.oid, candidate.oid) && valueMatch(base, candidate)

  // The floor RFC 5280 section 7.1 permits: binary comparison, relaxed to caseIgnoreMatch over the
  // two string types PKIX certificates use, and only where both values are ASCII. Full RFC 4518
  // StringPrep is deliberately out - section 8 asks CAs to state constraints in the subject's own
  // encoding, and the residual mismatch it leaves is CA-side.
  private def valueMatch(base: Ava, candidate: Ava): Boolean =
    if base.tag == candidate.tag && bytesEqual(base.content, candidate.content) then true
    else
      stringType(base.tag) && stringType(candidate.tag) && ascii(base.content) && ascii(candidate.content) &&
      normalised(base.content) == normalised(candidate.content)

  private def stringType(tag: Int): Boolean = tag == printableString || tag == utf8String

  private def ascii(value: Array[Byte]): Boolean = value.forall(_ >= 0)

  private def normalised(value: Array[Byte]): String =
    val folded = foldAscii(new String(value, "US-ASCII"))
    val collapsed = folded
      .foldLeft(new StringBuilder)((sb, c) => if c == ' ' && sb.nonEmpty && sb.charAt(sb.length - 1) == ' ' then sb else sb.append(c))
      .toString
    @tailrec def from(i: Int): Int = if i < collapsed.length && collapsed.charAt(i) == ' ' then from(i + 1) else i
    @tailrec def until(i: Int): Int = if i > 0 && collapsed.charAt(i - 1) == ' ' then until(i - 1) else i
    val start = from(0)
    collapsed.substring(start, math.max(start, until(collapsed.length)))

  // RFC 5280 section 4.2.1.10 mailbox forms: a complete address, a leading-dot domain, or a bare
  // host. The local part is case-sensitive and the domain is not (section 7.5).
  def emailWithin(name: String, base: String): Boolean =
    if base.isEmpty then true
    else
      val at = name.indexOf('@')
      // The subject-DN emailAddress fallback can present an attribute value that is not a mailbox
      // at all; it is within no non-empty base.
      if at < 0 then false
      else
        val local = name.substring(0, at)
        val domain = foldAscii(name.substring(at + 1))
        val baseAt = base.indexOf('@')
        if baseAt >= 0 then base.substring(0, baseAt) == local && foldAscii(base.substring(baseAt + 1)) == domain
        else if base.startsWith(".") then
          val b = foldAscii(base)
          domain.length > b.length && domain.endsWith(b)
        else foldAscii(base) == domain

  // Exactly one `@`: a multi-`@` address leaves which separator splits it to the reader.
  def validEmail(name: String): Boolean =
    val at = name.indexOf('@')
    at >= 0 && name.indexOf('@', at + 1) < 0

  def bytesEqual(a: Array[Byte], b: Array[Byte]): Boolean = Slice.of(a).contentEquals(Slice.of(b))
end Names
