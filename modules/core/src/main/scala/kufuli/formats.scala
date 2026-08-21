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
// The owned key-encoding format types. They live in their own compilation unit, apart from the
// doors that consume them: co-located, same-file opaque transparency makes four aliases over one
// representation indistinguishable and every parameter-type-selected overload becomes ambiguous.
package kufuli

import boilerplate.Slice

// Each type OWNS its octets: construction copies in and `bytes` copies out, so the buffer behind
// the value is kufuli's alone. That ownership is what lets the import doors borrow it - a document
// that reaches a door as a view costs no allocation per import - and what lets `PKCS8`, the one
// form carrying private-key material, erase itself in place.

/** Bare key octets: an Ed25519/X25519 public key (RFC 8032/7748) or an ML-KEM encapsulation key
  * (FIPS 203). Construction is the caller's claim about bytes in hand, not a validation - the
  * import door parses.
  */
opaque type Raw = Array[Byte]

object Raw:
  def apply(bytes: IArray[Byte]): Raw = Array.from(bytes.iterator)
  def apply(bytes: Slice): Raw = bytes.toArray
  extension (r: Raw)
    def bytes: IArray[Byte] = IArray.from(r: Array[Byte])
    private[kufuli] def slice: Slice = Slice.of(r)

/** A SEC 1 section 2.3.3 elliptic-curve point encoding. Construction is the caller's claim about
  * bytes in hand, not a validation - the import door parses.
  */
opaque type SEC1 = Array[Byte]

object SEC1:
  def apply(bytes: IArray[Byte]): SEC1 = Array.from(bytes.iterator)
  def apply(bytes: Slice): SEC1 = bytes.toArray
  extension (p: SEC1)
    def bytes: IArray[Byte] = IArray.from(p: Array[Byte])
    private[kufuli] def slice: Slice = Slice.of(p)

/** A SubjectPublicKeyInfo (RFC 5280 section 4.1.2.7) DER document. Construction is the caller's
  * claim about bytes in hand, not a validation - the import door parses.
  */
opaque type SPKI = Array[Byte]

object SPKI:
  def apply(bytes: IArray[Byte]): SPKI = Array.from(bytes.iterator)
  def apply(bytes: Slice): SPKI = bytes.toArray
  extension (d: SPKI)
    def bytes: IArray[Byte] = IArray.from(d: Array[Byte])
    private[kufuli] def slice: Slice = Slice.of(d)

/** A PrivateKeyInfo (RFC 5958) DER document: plaintext private-key material, including an RSA key's
  * `d`, `p` and `q`. Construction is the caller's claim about bytes in hand, not a validation - the
  * import door parses.
  */
opaque type PKCS8 = Array[Byte]

object PKCS8:
  def apply(bytes: IArray[Byte]): PKCS8 = Array.from(bytes.iterator)
  def apply(bytes: Slice): PKCS8 = bytes.toArray
  extension (d: PKCS8)
    def bytes: IArray[Byte] = IArray.from(d: Array[Byte])

    /** Erases the document in place, once it has been imported or written out. The value owns its
      * octets, so this is the whole of what kufuli holds; a copy taken through [[bytes]], and the
      * text of any PEM encoding, are the caller's to erase in turn.
      */
    def wipe(): Unit = Slice.of(d).wipe()
    private[kufuli] def slice: Slice = Slice.of(d)
end PKCS8
