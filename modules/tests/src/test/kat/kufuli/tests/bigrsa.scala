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

// An RSA-8192 keypair, generated once on JDK 25 and pinned here because generating one at test time
// takes tens of seconds. Its PrivateKeyInfo is 4679 octets - larger than the staging buffer the
// Native backend used to marshal into, which made this exact key a raised defect on Native and an
// ordinary key on the JVM and Node.
object BigRsa:
  val pkcs8Base64: String =
    "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"

  val spkiBase64: String =
    "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA8Ty0y9ZDNN9m2gf3RCr6CQ8aKzRWiXimXsbXuy73/IBkj+/obaDpWRFWetvirLDyD5" +
      "aT//L9w/Mfr2D0nmpezuG5/kRSXB1qJaKud2jlnJJi8dq0MyoJhnqiCAd8O4ElPFncHr1m5Y4era448/ugfx3oJooUi+P6CYk/wvQDrnmiPODR" +
      "QedkrWghT8M06aRPBh5sQncPhUDqjCgnIX8o10+M69Eu2u5kWQrkfVU81onkygQhbbnOgNTAkXDpx/1sNd7tclGDGoabRTKfUOtzq7zGxqfQpb" +
      "lhAvzDp/uxLHRxf53UOOyzN0wBg6ztPb0wNv7Clzgpp4vI8nTVVUdfRMxM3w7RaQSmNqNmaPADOCaGVHkiNxz8O2OUf9Oos3AVEza2zQtHTeTc" +
      "i7JV63t+85A8rOJsWm1FJTQc5acBAvTSfVJlShvBYeHxKGb9QFM2k1Zq1yTu5vAhZgM0hNleUpHPfeRsPsW6wWpITNgMydsjfY3rGDZbyaQWlR" +
      "K8uX9lo2EyrZ3Vo15fXMj8mQzhDm8mQGOHb/pIdzZS+zoFzbpUpdq8/tykoUSxMAbE3YTld/7B0vbkmhfp1nBGpZY7lKYh3AjjwUDMTTyLxFze" +
      "XMzWv2wH7ceDewMCZs2xVi61U+fWdvu6nDvfQF0ess34v8rJHl4RgDPWFrE0FPGbudrpgaHpAM8Hd5yyK/n2SrmareqIBewvbk1kQRh+sU7MOm" +
      "XryxY0zzVvK9L8eNbCHGkAP13fuQizjIA3XDNf4vnENJRydfc1WjDFOwKDmxqANS5EemT7qduBNM13Rh+jlVgEKfrZa1T4HKjW+olySmJtSHdT" +
      "vjbILghPBAsdcwsvLYg/q93GDQICs5at9CnFgEUJ7u7OZH9hAnBnd9vSMl5rD7b+VojNIxuxNA37/P4See9WlhK8aDEWnsNWhWDieoHisV1G1W" +
      "4Q+I9HGJZxsa/Rr/oQT0zr573j3CV0OMAB2XGq052QBBtIOfLpGGL6g8kfMhZc+LCMl0ftzg/pOC7bzgueBQq0C7ymbzLKP4r9ZM5JedgEH5Q0" +
      "ptjq5BHI3QVWazIQE0hCkrdyT+X82xUU89hUT8hIzk7o1D22/T1LFuA7o6a5so3CmqQQ/+tAxcsFH+LVZiaLYnpKpsTn1wrAqOY0y9avvWpkOW" +
      "DyWaEo2I0xMQrG3GBqPx2bl492v+P/m+4VUl16cgRCKx+N5c3wbsqmiJiAnsMY1z9uHSs/ycneE2aDTFwdEPw7D/g9QF1dpbBL/QLPK3UEkCFn" +
      "r+C38zAehUfUEVtx2YsE0EzBm+IkU6k01pcekoEXK+6ZggxHVtSuQv+MKhSHkQmxr/Qb/x84imuZs/DyFaQRQ8YizQIDAQAB"
end BigRsa
