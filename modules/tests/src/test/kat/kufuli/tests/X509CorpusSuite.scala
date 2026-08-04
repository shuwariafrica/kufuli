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

import cats.effect.IO
import cats.syntax.all.*
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.tests.corpora.Vectors
import kufuli.tests.support.*
import kufuli.x509 as x5

class X509CorpusSuite extends munit.CatsEffectSuite:

  // x509-limbo's certificates are valid 1970-2969 and its cases carry no validation_time; NIST
  // PKITS section 4.13 is valid 2010-2030. Both instants are pinned, never read from a clock.
  private val limboInstant = 1_800_000_000L
  private val pkitsInstant = 1_302_825_600L

  private def parse(json: String): Js = readFromString[Js](json)

  private def certificates(pems: List[String]): Either[String, List[x5.Certificate]] =
    pems.traverse(pem => x5.Certificate.fromPem(pem).left.map(_ => s"unparseable certificate"))

  private def outcome(
    chain: List[x5.Certificate],
    anchors: List[x5.Certificate],
    at: Long,
    id: Option[x5.ServerId],
    kind: String
  ): IO[Either[x5.PathInvalid, x5.VerifiedPath]] =
    x5.TrustAnchors.of(anchors) match
      case Left(_)  => IO.pure(Left(x5.PathInvalid.UntrustedAnchor))
      case Right(t) =>
        (id, kind) match
          case (Some(peer), "SERVER") => x5.CertPath.verify(chain, t, at, peer).either
          case _                      => x5.CertPath.verifyClient(chain, t, at).either

  // The corpus's own `conflicts_with` field marks this pair as mutually exclusive: one asserts RFC
  // 5280's must-be-critical rule for NameConstraints, the other the CA/Browser Forum exception that
  // permits it non-critical. kufuli processes the extension regardless of criticality, so the
  // webpki-namespaced case is the one asserted and its counterpart is stated here, not silently
  // dropped.
  private val conflicting = "rfc5280_nc_permitted-dns-match-noncritical"

  // The only SERVER-kind case with no reference identity, and its leaf's sole SAN is a
  // directoryName, so no identity exists to present. kufuli's ServerAuth entry requires one by
  // construction and its ClientAuth entry rejects the leaf on the path-wide serverAuth EKU - so the
  // verdict is not assertable, but the property the case exists for is: the permitted directoryName
  // subtree must not be what rejects the chain.
  private val identityless = "rfc5280_nc_permitted-dn-match"

  test("x509-limbo ::nc:: - the 52 name-constraint cases") {
    val cases = Vectors.limboNameConstraints
    val results = cases.filterNot(_._1 == conflicting).traverse { (name, json) =>
      val c = parse(json)
      val expected = c.field("expected_result").str == "SUCCESS"
      val kind = c.field("validation_kind").str
      val peer = c.field("expected_peer_name")
      val chain = c.field("peer_certificate").str :: c.field("untrusted_intermediates").arr.toList.map(_.str)
      val anchors = c.field("trusted_certs").arr.toList.map(_.str)
      val id =
        if peer.field("kind").str == "DNS" || peer.field("kind").str == "IP" then x5.ServerId.of(peer.field("value").str).toOption
        else None
      (certificates(chain), certificates(anchors)) match
        // A rejected case whose own material will not parse is still a rejection, and every
        // accepted case must parse - so an unparseable chain is only a failure when SUCCESS is
        // expected.
        case (Right(certs), Right(roots)) =>
          outcome(certs, roots, limboInstant, id, kind).map { r =>
            if name == identityless then
              Option.when(r == Left(x5.PathInvalid.NameConstraintViolated))(s"$name: rejected by name constraints")
            else Option.when(r.isRight != expected)(s"$name: expected $expected, got $r")
          }
        case _ => IO.pure(Option.when(expected)(s"$name: expected SUCCESS but the case material did not parse"))
    }
    for
      _ <- check(cases.length == 52, s"the ::nc:: slice must carry 52 cases, found ${cases.length}")
      mismatches <- results.map(_.flatten)
      _ <- check(mismatches.isEmpty, s"${mismatches.length} of 51 disagreed: ${mismatches.take(8).mkString("; ")}")
    yield ()
  }

  test("NIST PKITS section 4.13 - 36 of 38 name-constraint cases") {
    val certs = Vectors.pkitsCertificates.toMap
    val cases = parse(Vectors.pkitsCases).arr.toList
    val results = cases.traverse { c =>
      val name = c.field("name").str
      val expected = c.field("shouldValidate") match
        case Js.B(b) => b
        case _       => false
      // The manifest lists the trust anchor first and the end entity last; kufuli takes the chain
      // leaf first with the anchor supplied separately.
      val path = c.field("certPath").arr.toList.map(_.str)
      val pems = path.traverse(certs.get)
      pems match
        case None       => IO.pure(Some(s"$name: a referenced certificate is not vendored"))
        case Some(list) =>
          certificates(list) match
            case Left(e)    => IO.pure(Some(s"$name: $e"))
            case Right(all) =>
              val chain = all.tail.reverse
              outcome(chain, List(all.head), pkitsInstant, None, "CLIENT")
                .map(r => Option.when(r.isRight != expected)(s"$name: expected $expected, got $r"))
    }
    for
      _ <- check(cases.length == 36, s"the section 4.13 slice must carry 36 cases, found ${cases.length}")
      _ <- check(certs.size == 55, s"the section 4.13 slice must carry 55 certificates, found ${certs.size}")
      mismatches <- results.map(_.flatten)
      _ <- check(mismatches.isEmpty, s"${mismatches.length} of 36 disagreed: ${mismatches.take(8).mkString("; ")}")
    yield ()
  }
end X509CorpusSuite
