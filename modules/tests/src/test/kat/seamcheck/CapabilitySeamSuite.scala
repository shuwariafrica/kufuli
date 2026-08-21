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
// The seam negatives for capabilities the browser artifact does not provide. Asserted here rather
// than beside the universal ones because an absent instance makes `!typeChecks` hold for the wrong
// reason; every row below pairs its negative with the summon that reaches the same instance.
package seamcheck

import scala.compiletime.testing.typeChecks

import kufuli.*

class CapabilitySeamSuite extends munit.FunSuite:

  test("ML-KEM, incremental hashing and the record engine are sealed on the lanes that provide them") {
    assert(typeChecks("summon[KEM[MlKem768]]"), "the KEM instance resolves")
    assert(!typeChecks("summon[KEM[MlKem768]].encapsulate(???)"), "KEM.encapsulate is sealed")
    assert(!typeChecks("summon[KEM[MlKem768]].decapsulate(???, ???)"), "KEM.decapsulate is sealed")

    assert(typeChecks("summon[KemKeys[MlKem768]]"), "the ML-KEM lifecycle instance resolves")
    assert(!typeChecks("summon[KemKeys[MlKem768]].fromSeed(???)"), "the seed import has no public surface")
    assert(!typeChecks("summon[KemKeys[MlKem768]].fromRaw(???)"), "the FIPS 203 encapsulation-key check is unbypassable")

    assert(typeChecks("summon[Hashing[Sha256]]"), "the incremental hashing instance resolves")
    assert(!typeChecks("summon[Hashing[Sha256]].hasher"), "Hashing.hasher is sealed")
    assert(typeChecks("Sha256.hasher"), "the spec object is the public path")

    assert(typeChecks("summon[Ciphering[AesGcm256]]"), "the record engine instance resolves")
    assert(!typeChecks("summon[Ciphering[AesGcm256]].engine(???)"), "an unbudgeted record engine is unobtainable")
  }
end CapabilitySeamSuite
