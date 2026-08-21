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
// Deliberately outside `kufuli.*`: `private[kufuli]` grants package access, so the same assertion
// made from `kufuli.tests` would compile whether or not the primitive is sealed. The browser
// artifact ships no password module, which is why this row lives beside the KAT tier.
package seamcheck

import scala.compiletime.testing.typeChecks

import kufuli.password.*

class PasswordSeamSuite extends munit.FunSuite:

  test("the Argon2 primitive is unreachable from outside kufuli, while hashing is not") {
    assert(typeChecks("summon[Argon2]"), "the Argon2 instance resolves")
    assert(
      !typeChecks("summon[Argon2].hash(boilerplate.Slice.empty, boilerplate.Slice.empty, Argon2Params.default)"),
      "the primitive is sealed, so salt custody and PHC encoding cannot be bypassed"
    )
    assert(typeChecks("\"pw\".hash(Argon2Params.interactive)(using summon[Argon2], summon[kufuli.Random])"), "the audited path is public")
  }
