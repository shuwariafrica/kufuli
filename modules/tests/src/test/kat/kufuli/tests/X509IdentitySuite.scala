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

import kufuli.Malformed
import kufuli.x509.Hostname
import kufuli.x509.IpAddress
import kufuli.x509.ServerId

class X509IdentitySuite extends munit.FunSuite:

  private def bytesOf(text: String): Option[List[Int]] =
    IpAddress.parse(text).toOption.map(a => a.bytes.toList.map(_ & 0xff))

  test("ServerId classifies a peer identity one way only") {
    val dns = List("example.com", "host.example.com", "xn--bcher-kva.example", "a-b.example", "EXAMPLE.com")
    dns.foreach(name => assert(ServerId.parse(name).exists { case ServerId.Dns(_) => true; case _ => false }, s"$name is a DNS name"))
    val ips = List("192.0.2.1", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1", "[2001:db8::1]", "::ffff:192.0.2.1")
    ips.foreach(name => assert(ServerId.parse(name).exists { case ServerId.Ip(_) => true; case _ => false }, s"$name is an IP literal"))
    // Anything a reader could classify two ways is rejected rather than guessed at.
    val rejected = List(
      "999.1.1.1",
      "1.2.3.4.5",
      "1.2.3",
      "010.1.1.1",
      "",
      "under_score.example",
      "-lead.example",
      "1.2.3.4:443",
      "2001:db8::1::2",
      "12345::1",
      ":1:2:3:4:5:6:7",
      "host..example",
      "*.example.com"
    )
    rejected.foreach(name => assertEquals(ServerId.parse(name), Left(Malformed), s"$name must not classify"))
  }

  test("an all-numeric final label is an IP shape, not a hostname") {
    assertEquals(Hostname.parse("1.2.3.4.5"), Left(Malformed))
    assertEquals(Hostname.parse("example.123"), Left(Malformed))
    assert(Hostname.parse("123.example").isRight, "a numeric label elsewhere is a hostname")
  }

  test("Hostname strips one root dot, folds ASCII, and holds the LDH definition") {
    assertEquals(Hostname.parse("Example.COM").map(_.value), Right("example.com"))
    assertEquals(Hostname.parse("example.com.").map(_.value), Right("example.com"))
    assertEquals(Hostname.parse("example.com.."), Left(Malformed))
    assertEquals(Hostname.parse(""), Left(Malformed))
    assertEquals(Hostname.parse("."), Left(Malformed))
    assertEquals(Hostname.parse("-lead.example"), Left(Malformed))
    assertEquals(Hostname.parse("trail-.example"), Left(Malformed))
    assertEquals(Hostname.parse("a" * 64 + ".example"), Left(Malformed))
    assert(Hostname.parse("a" * 63 + ".example").isRight, "a 63-octet label is the limit, not past it")
    assertEquals(Hostname.parse(List.fill(5)("a" * 50).mkString(".") + ".example"), Left(Malformed))
    assert(Hostname.parse("a-b.example").isRight, "an interior hyphen is LDH")
  }

  test("IpAddress reads both families in presentation and wire form") {
    assertEquals(bytesOf("192.0.2.1"), Some(List(192, 0, 2, 1)))
    assertEquals(bytesOf("::1"), Some(List(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)))
    assertEquals(bytesOf("2001:db8::1"), Some(List(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)))
    assertEquals(bytesOf("::ffff:192.0.2.1"), Some(List(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1)))
    assertEquals(bytesOf("[2001:db8::1]"), bytesOf("2001:db8::1"))
    assertEquals(bytesOf("1:2:3:4:5:6:7:8"), Some(List(0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8)))
    assertEquals(IpAddress.of(Slice.of(Array[Byte](192.toByte, 0, 2, 1))), IpAddress.parse("192.0.2.1"))
    assertEquals(IpAddress.of(Slice.of(new Array[Byte](5))), Left(Malformed))
    List("1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::1", "1:2:3:4:5:6:1.2.3.4.5", "1.2.3.4:5")
      .foreach(text => assertEquals(IpAddress.parse(text), Left(Malformed), s"$text must not parse"))
  }

  test("an IPv4-mapped IPv6 address is not the IPv4 address it embeds") {
    val mapped = IpAddress.parse("::ffff:192.0.2.1")
    val plain = IpAddress.parse("192.0.2.1")
    assert(mapped.isRight && plain.isRight, "both parse")
    assert(mapped != plain, "RFC 9525 section 6.4 keeps the families apart")
    assertEquals(IpAddress.parse("192.0.2.1"), IpAddress.parse("192.0.2.1"), "the same address compares equal")
  }
end X509IdentitySuite
