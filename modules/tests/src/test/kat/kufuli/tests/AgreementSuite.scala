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
import boilerplate.effect.*
import cats.effect.IO
import cats.syntax.all.*
import com.github.plokhotnyuk.jsoniter_scala.core.*

import kufuli.*
import kufuli.jose.*
import kufuli.tests.support.*
import kufuli.tests.wycheproof.*

// Every expected value here is PUBLISHED - an RFC section or a Wycheproof vector, cited per test -
// so each backend is measured against the wider world rather than against itself. A backend that
// only round-trips against itself passes its own self-consistency check while computing a value no
// other implementation agrees with.
class AgreementSuite extends munit.CatsEffectSuite:

  private def hb(s: String): Array[Byte] =
    if s.isEmpty then Array.emptyByteArray else s.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  private def parse(json: String): Js = readFromString[Js](json)

  // A vector run over an empty case list asserts nothing and still reports green, so every runner
  // here proves it had cases before it can pass.
  private def cases[A](xs: List[A], what: String): IO[List[A]] =
    check(xs.nonEmpty, s"$what: no vectors - the corpus or vector list is empty").as(xs)

  private def report(rs: List[Option[String]], what: String): IO[Unit] =
    check(rs.flatten.isEmpty, s"$what: ${rs.flatten.size} mismatches: ${rs.flatten.take(6).mkString("; ")}")

  // The ECDH and X25519 vectors publish a raw private scalar, while every backend imports a private
  // key only as PKCS#8; building the wrapper here keeps the pinned constants verbatim.
  private def tlv(tag: Int, content: Array[Byte]): Array[Byte] =
    val length =
      if content.length < 0x80 then Array(content.length.toByte)
      else if content.length < 0x100 then Array(0x81.toByte, content.length.toByte)
      else Array(0x82.toByte, (content.length >> 8).toByte, content.length.toByte)
    Array(tag.toByte) ++ length ++ content

  private def ecPkcs8(curveOid: String, scalar: Array[Byte]): Array[Byte] =
    val ec = tlv(0x30, tlv(0x02, Array(1.toByte)) ++ tlv(0x04, scalar))
    val alg = tlv(0x30, tlv(0x06, hb("2a8648ce3d0201")) ++ tlv(0x06, hb(curveOid)))
    tlv(0x30, tlv(0x02, Array(0.toByte)) ++ alg ++ tlv(0x04, ec))

  private def x25519Pkcs8(scalar: Array[Byte]): Array[Byte] =
    tlv(0x30, tlv(0x02, Array(0.toByte)) ++ tlv(0x30, tlv(0x06, hb("2b656e"))) ++ tlv(0x04, tlv(0x04, scalar)))

  private val p256Ecdh: List[(Int, String, String, String)] = List(
    (1,
     "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
     "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d27"
       + "5a014e30cf",
     "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285"
    ),
    (4,
     "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
     "04a1ecc24bf0d0053d23f5fd80ddf1735a1925039dc1176c581a7e795163c8b9ba2cb5a4e4d5109f4527575e3137b83d79a9bcb3faeff90d2aca2bed"
       + "71bb523e7e",
     "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
    ),
    (9,
     "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
     "04a492fe4b4908b6d675d687551f99c617e4e5c97aa266958953129eb381f0153b111b95c94fa1d1ecd1d41d2785c1db5195875ae98051732a59ba77"
       + "20f9089af6",
     "6522aed9ea48f2623b8eeae3e213b99da32e74c9421835804d374ce28fcca662"
    )
  )

  private val p384Ecdh: List[(Int, String, String, String)] = List(
    (1,
     "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1fb1dee4edd64356b9f21c588b75dfd81",
     "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b"
       + "3b56eadff6b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa",
     "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4de1e229da71fef0c77fe49b249190135"
    ),
    (46,
     "2bc15cf3981eab6102c39f9a925aa1309db59c2c02a54411928d73c3945d157848dc36959efef7495c8528ea284c1c97",
     "04000000000000000000000000000000000000000000000000000000001f03123b0000000000000000000000000000000071bd1e700c34075c3cade8"
       + "ce29d33724af68a7672b265a4e157055360440ab7c461b8e9ac8024e63a8b9c17c00000000",
     "ea817dff44f1944a38444498f1b6c1a70a8b913aa326bc2acc5068805d8ddd7a5e41b8ee5b8371a1cf3f7a094258e3a6"
    ),
    (48,
     "2bc15cf3981eab6102c39f9a925aa1309db59c2c02a54411928d73c3945d157848dc36959efef7495c8528ea284c1c97",
     "04000000000000000000000000000000000000000000000000000000001f03123b000000000000000000000000000000008e42e18ff3cbf8a3c35217"
       + "31d62cc8db50975898d4d9a5b1ea8faac9fbbf5482b9e4716437fdb19c57463e84ffffffff",
     "ea817dff44f1944a38444498f1b6c1a70a8b913aa326bc2acc5068805d8ddd7a5e41b8ee5b8371a1cf3f7a094258e3a6"
    )
  )

  private val p521Ecdh: List[(Int, String, String, String)] = List(
    (1,
     "01939982b529596ce77a94bc6efd03e92c21a849eb4f87b8f619d506efc9bb22e7c61640c90d598f795b64566dc6df43992ae34a1341d458574440a7"
       + "371f611c7dcd",
     "040064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9d79769ca2bdf2d4c972642926d444891a652e7f492337251adf161"
       + "3cf3077999b5ce00e04ad19cf9fd4722b0c824c069f70c3c0e7ebc5288940dfa92422152ae4a4f79183ced375afb54db1409ddf338b85bb6dbfc5950"
       + "163346bb63a90a70c5aba098f7",
     "01f1e410f2c6262bce6879a3f46dfb7dd11d30eeee9ab49852102e1892201dd10f27266c2cf7cbccc7f6885099043dad80ff57f0df96acf283fb090d"
       + "e53df95f7d87"
    ),
    (13,
     "00a2b6442a37f8a3759d2cb91df5eca75af6b89e27baf2f6cbf971dee5058ffa9d8dac805c7bc72f3718489d6a9cb2787af8c93a17ddeb1a19211ab2"
       + "3604d47b7646",
     "04012879bd210acac09dd6e24d72f5a4c0d89f2ab8e61d0661f885512a6f49ff815604d41b76af380ba34f5bbe7a54d8533a4485f5b9f029c74a06c1"
       + "e12bbec05ffc4b00f6373651d219c695e4596ccac5f1643fb754415bfe6884d591f5c761f8baed81a78581058e500e1751d9c4c6c4a7304d23219226"
       + "8ffdd4bf416df56be3f0f9e5b5",
     "0064e9248d9de718ab17084cb97d28a98b610c49ab96294d2c6d4e02244e25f95cbf55f40855ad86648ea416233fab0579ab405e87d002691f11ee69"
       + "bb61683eb673"
    ),
    (15,
     "00a2b6442a37f8a3759d2cb91df5eca75af6b89e27baf2f6cbf971dee5058ffa9d8dac805c7bc72f3718489d6a9cb2787af8c93a17ddeb1a19211ab2"
       + "3604d47b7646",
     "0401246ab3b73526c085c892056f6f33834fa5ca904f12444c4d53139bd3c075160ef53f105998c2e6be7cfe822bfd6ae409c20750226cb6f634b237"
       + "128c1c964545be01cd44d3d6961d999575bc615e973fba340cfd2dd1cd53df9de50b98ce5136640d70cb090c7ecacb8ea8fade2fd5acf511d952f720"
       + "c3208e8a0a6fd76c5e911a9162",
     "00a0f5d6d83ebfd0f5f478359f470bd21eef8455eb09dd1f88da04bd435c3d106efe8bf2aaf447ac62cf8f668301c8a2dc664cbe6fd07677e6ff80ac"
       + "d3fb39d86f5d"
    )
  )

  private val cbcHsK128 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  private val cbcHsK256 =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b"
      + "3c3d3e3f"
  private val cbcHsIv = "1af38c2dc2b96ffdd86694092341bc04"
  private val cbcHsAad = "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673"
  private val cbcHsP =
    "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d75"
      + "73742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e"
      + "76656e69656e6365"
  private val b1Ciphertext =
    "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362"
      + "c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550"
      + "a67646344427ade54b8851ffb598f7f80074b9473c82e2db"
  private val b1Tag = "652c3fa36b0a7c5b3219fab3a30bc1c4"
  private val b3Ciphertext =
    "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df82"
      + "9410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053"
      + "d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6"
  private val b3Tag = "4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5"

  // RFC 4231 test cases 1-6: (case, key, data, HMAC-SHA-384, HMAC-SHA-512).
  private val rfc4231: List[(Int, String, String, String, String)] = List(
    (1,
     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
     "4869205468657265",
     "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c20"
       + "3a126854"
    ),
    (2,
     "4a656665",
     "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a"
       + "38bce737"
    ),
    (3,
     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
     "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
     "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee894267427885"
       + "9e13292fb"
    ),
    (4,
     "0102030405060708090a0b0c0d0e0f10111213141516171819",
     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
     "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
     "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb"
       + "10a298dd"
    ),
    (5,
     "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
     "546573742057697468205472756e636174696f6e",
     "3abf34c3503b2a23a46efc619baef897",
     "415fad6271580a531d4179bc891d87a6"
    ),
    (6,
     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
       + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
       + "aaaaaaaaaaaaaaaaaaaaaa",
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
     "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
     "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a98"
       + "5d786598"
    )
  )

  private val rfc7638Modulus =
    "d2fc7b6a0a1e6c67104aeb8f88b257669b4df679ddad099b5c4a6cd9a88015b5a133bf0b856c7871b6df000b554fceb3c2ed512bb68f145c6e843475"
      + "2fab52a1cfc124408f79b58a4578c16428855789f7a249e384cb2d9fae2d67fd96fb926c198e077399fdc815c0af097dde5aadeff44de70e827f4878"
      + "432439bfeeb96068d0474fc50d6d90bf3a98dfaf1040c89c02d692ab3b3c2896609d86fd73b774ce0740647ceeeaa310bd12f985a8eb9f59fdd426ce"
      + "a5b2120f4f2a34bcab764b7e6c54d6840238bcc40587a59e66ed1f33894577635c470af75cf92c20d1da43e1bfc419e222a6f0d0bb358c5e38f9cb05"
      + "0aeafe904814f1ac1aa49cca9ea0ca83"
  private val rfc7638Thumbprint = "3736cbb1787cb8309c77ee8c3705c5e16ffb9e859715901f1e4c59b11182f57b"

  private val mlKem768Ek: String =
    "8b9a7354e8c1c17a9898f96caf99bba1c625ae0983c4d26e60c12f59bc25d756182b17979e713fff129e6c336a2317770380858129cb91a902ea5455"
      + "ca076c20e4158f393aa2783053d8acf92c3286a10436d72af3e8903ce22f8cbab18b1309aca205aa8a3da45807e5b60e6967a640a713a5b81b0d82bc"
      + "406934e3c88910cc06f09a68bce991009bb56ae233296218ff5baf1f475390b8b7494a4e083645985437f2495a073222fea058e1672034151a2e14c2"
      + "cbcb4ad9068c8e7bcb02886c4087c14bd8823ec66393fb2e12326b38e655dcab1c13cb2931358715c8be5153293229cc994a5702b7295a6a4a73249a"
      + "c5a30a32a6b91dca768c177d8fa59054e548bee40257db6962a83b64ec6de0d3be7b1812c5d99e7a38cf54eaa8413aa0bd02bf374461f29c2b6aea56"
      + "f7d33e10dbbc75bb1bf6b555213aac33e652443a186a618b6e9a293919693f1673ea159d0ee52c92d53e9a5cbd5f4c44419b5493f0286efcb9b5a2ad"
      + "56a713c4f61ed431aa987805a90475391ccd4c7a28d884bf1a926b7675b9208897a89a6384c154acca3521c32a994949b2e80b2ff2518c0bbd34184c"
      + "da443de498a05dfba9ce701bb914179a0188be0bcda6fbc2cd93afb042481b4a84d821160a1b0ade8bcb97dbaf681547cce0bca674151a261a21aa04"
      + "fda318c921c38425b775b995cd7b4eb6369f0b211da186594de815fa3b53a68043e1946468a5899b90578ad49397306f71acab67c258fa17a31893b7"
      + "2d22151ce1afee150fe550bffde8a24fe4740dd43f387c7ad20b5cca5997879536c3071574901147727341c1a6fc8043e6454903e88217f0c92b9a4a"
      + "c54a86e7909390878a35ba18c1e26b13049f41c522bc049d74db6f76caba39f23d8f07abc26a07a1caba71cb5c12fbc20a715450b2228d17b2ba985c"
      + "fe2496b033b55f300baf992964388a5422298f627ba567730ddb03a195806a5c23a1d315481c52814b0681ea3c804b02c90688c2fbbce9b17d230a42"
      + "f8b865417c9e93347f5ff624879962747c7eed886acd48a994b22064ca499c69aa4825be60260d12f63102799828b3ccebaa4340b749605017eb4598"
      + "ff13a634500a48470de9078a34106267d25a0b144d8cdb1a4d527692153da013c0ab27ae2ca955e7c66238746022d50630892933a05c283a9f4c00c9"
      + "f984646f75471081722ed3404ce60fed4a06702b8728b62d920b3224206ab0a4694f9c18e3162b529c16af04b87b4a61cd53a757906d67a139629585"
      + "d423a3b0986f29c95984e2095ea4608784b0b31c20cbc36cfd60b773389fe5a8c0958211a35b2c45f21f51a08693c19bfc388c2d677a214ccc5a7cb0"
      + "b67030fd6987503c91b0f2646985a9048489dd882bd4141f5419554eb738fa7333c5c57a4ce5541fd6b8ad454c2dea67ad1c6f848c0a44a1872e40a1"
      + "7d987075d762ba5aaa21d435dd079b989a8ee21a2ce898934a98a02d5b381c302a2d76948fa65de15666f57750d580ae1a541c700692dd0b0a6799b5"
      + "cdb893413bb89bb65182f219a4bc3c80b43bb591bcd05ac6e9a366552558ed5c5fbe7b4acfc7b23372094f6a87f26c0c46646c55a888871324fea753"
      + "6e586a5149b9b707c86ea076486a6822b9bbf59fbfcaedc13284b9813cabdd526e326a6832d3b36efc3102ef"

  private val mlKem1024Ek: String =
    "a22bc758f65682632313e5c786952a5a144e9747791a4a382c74618b879e6fd8584dc42fb103c6537384906108ece36734510ab6fb5fc68baba2eb9c"
      + "db893ef0bccc0e1a90287213ebf25b4455056055993516439af9b45fb441187b2b0169734809497e24821a888b3502469af74023b376f62b03e3e002"
      + "59f0540bd1163b67750f8a75eb127bec50031619c1bc362d2ab844baab68925884be574ea5d2cc8f694a37503592d2107ab47ba4258b9b3ab0eddc9c"
      + "4d1402785665d783b298004feb196c48228cc3a684d6950ae688054f5acb35b09c3f290a76470f548674ddaa92ff808d7a091f7795cd75503d5d6982"
      + "275c01581c1d22d491d2222e97e172809bc9d9c8c6c3875302a03901914017326440faced5bac1dcd2a9014b426f764335f31fd41a05dce58a731bb6"
      + "e362a61d712303ba1ca4eb0998e507304b6f8c887254261ab4fbca4a198bac4792894a974dd203cf7c9ab58b9402f515aac64641aba6ee133572835f"
      + "31b4ab6178ccf5c2a9ca875d8d9866bf8a282c49cf3174a89c415926f5155516baa34aa4c3b47af49ac7c6dc9323c45e69a47d79045d66181041da3c"
      + "ef619449c004bf314ef8a6a02a0819a6511dd2eb88e7336a01b947a1b5618e02865d8a9db031be34c1259fc09230f43d294baab64c5cd34856330956"
      + "4cc30912e672d7eb0ec43a7c8f94c89ab99bf4fb852fe661b4c37d6058312c9a7f3b33ce9103625d886869d79f98c6047555310ce6904ddc050d37b8"
      + "bc872d93951b703b961773696238b890a0971e90c005cc2e75628746b599f878355df2b355153b282b4dcf7b7c3167cfb48bc6002861f5d000a37323"
      + "9166449a67718a1b9dbb43ce6c18a5be227e23f999c8bbb1de6441a6e1193b5176bba03c4f8c71fdda29ee18c336d120d0c331a0a622c1827166c1aa"
      + "351bb7dca69d84bb9ec692ca62812fbe4a5f89a65ec5b6a6eb976658585f5a63541a23242f31022c4c44db400dd292227b3976cb741e708369370c95"
      + "55297433b67da83992b1e06d791aa6faa34a040332cbac151576a51c794e2b791dc3740e0f0136fb2137685ca71b3626fb6a51d8417df24083469296"
      + "85371dc1532093d38176fb8c670b7a7236bb9035923280016afb5070bb559e78a89bd6c5fc36c87e0a5443587c879aa94368ae6fa6690d38bc18274b"
      + "ab0b4b0f01accd95c0af0ba048a76880b8c842430c4541bdbdb267d39498fdd35907a58faab500a710742a63179d5c15fad0bace8bba301935e7b195"
      + "794597a206a9ad83ca73b66c18f1a25d6813a242a4d082b646d488bc63852df5b69ef08510a657d3ba5954b6a4df752237d8c5d0a429baa14be2f824"
      + "e16ca19e694de9c6251cb90958a03159914243dc5e272438e2a6500970b55390b02c3b5e52ccb7ebb2099f646f9518376417896e837c16f783ce568d"
      + "59e6c6e2068892936b6e584a6d2233e7d98506b740008b6d14e29cc878170c966f80f3c76cb96d3e7665eba6067d996bdb16a45c094d8563958a1015"
      + "ce833b3cac29d4bb3e970c0d7ae654451b378a1027340b5471790ea68575d200c8af88777e28a203c4b36b0512de6607436a34d83a6691882aa5f81c"
      + "83649f0370be6b743140fc62db1527d220cf6b66870dc674660b5856a34766fcc66f7480c383c904fc124bc608a38246ebe835b3834487611b8d2625"
      + "78364f5849c94437937fa47341a318487a23129c3636f050a0d693a7cb89f36c78502487a691142ca88d8975b4a92417bed59efea73fe3892a062ba3"
      + "84d404887c498909212a5c913e8953c4d50d87faa6bb9c3536582e39b69cfa59240dc881fed2b9450aa1715b88805966b5e52505341f98f728ef939f"
      + "7917083057a42c40ce9f364117d6b9752179f8d22c4ba3b00de31363d56ad69b92db30ae809036b93a5437598abf115496126dae81875d633e47d49c"
      + "27911892a885efd78122b90712d3576d864701a469a25b34d904113629a3231b20cdd5a2ede1188e0c411e619162820ea6f1009bf17f32e36fd71609"
      + "8b384013e60a85572d217aa1239507efdc0604379592f66de032372589404952c87552b5c3326d4cac0172c74254b792463ca428d334ee419994eb50"
      + "1b07789349b1d0c16a352ac8fef45d30da79cfa53147529149bc69b594745ff86e2ba862d128410ed993d5e6b3f011342518beb7be48573d1adb2b71"
      + "2ebe6f7b79802ff3"

  private def ecdh[C <: EcCurve](curve: EcSpec[C], curveOid: String, vectors: List[(Int, String, String, String)])(using
    EcKeys[C],
    Agreement[C]
  ): IO[Unit] =
    cases(vectors, "ecdh")
      .flatMap(_.traverse { (tc, scalar, point, expected) =>
        for
          priv <- expectRight(s"tc$tc private key")(PrivateKey.fromPkcs8(curve)(Slice.of(ecPkcs8(curveOid, hb(scalar)))))
          pub <- expectRight(s"tc$tc peer point")(PublicKey.fromSec1(curve)(Slice.of(hb(point))))
          secret <- priv.agree(pub).absolve
          got <- secret.use(s => hex(s.toArray)).absolve
        yield Option.when(got != expected)(s"tc$tc expected=$expected got=$got")
      })
      .flatMap(report(_, "ecdh"))

  test("ECDH P-256 (Wycheproof ecdh_secp256r1_ecpoint tc1/4/9): the derived secret is the published value") {
    ecdh(P256, "2a8648ce3d030107", p256Ecdh)
  }

  test("ECDH P-384 (Wycheproof ecdh_secp384r1_ecpoint tc1/46/48): the derived secret is the published value") {
    ecdh(P384, "2b81040022", p384Ecdh)
  }

  test("ECDH P-521 (Wycheproof ecdh_secp521r1_ecpoint tc1/13/15): the derived secret is the published 66-byte value") {
    ecdh(P521, "2b81040023", p521Ecdh)
  }

  test("X25519 (RFC 7748 6.1): both parties derive the published shared secret") {
    val alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    val alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    val bobPriv = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    val bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    for
      ak <- expectRight("alice private")(PrivateKey.fromPkcs8(X25519)(Slice.of(x25519Pkcs8(hb(alicePriv)))))
      bk <- expectRight("bob private")(PrivateKey.fromPkcs8(X25519)(Slice.of(x25519Pkcs8(hb(bobPriv)))))
      aq <- expectRight("alice public")(PublicKey.fromRaw(X25519)(Slice.of(hb(alicePub))))
      bq <- expectRight("bob public")(PublicKey.fromRaw(X25519)(Slice.of(hb(bobPub))))
      za <- ak.agree(bq).absolve.flatMap(_.use(s => hex(s.toArray)).absolve)
      zb <- bk.agree(aq).absolve.flatMap(_.use(s => hex(s.toArray)).absolve)
      _ <- check(za == shared, s"alice expected=$shared got=$za")
      _ <- check(zb == shared, s"bob expected=$shared got=$zb")
    yield ()
  }

  private def cbcHs[A <: AeadAlgorithm](spec: AeadSpec[A], k: String, iv: String, aad: String, p: String, e: String, t: String)(using
    AEAD[A]
  ): IO[Unit] =
    val key = SecretKey.of(spec)(hb(k)).toOption.get
    val nonce = Nonce.unsafe[A](hb(iv))
    for
      ct <- key.seal(nonce, Slice.of(hb(aad)), Slice.of(hb(p))).absolve
      _ <- check(hex(ct.toArray) == e + t, s"seal expected=${e + t} got=${hex(ct.toArray)}")
      opened <- expectRight("open")(key.open(nonce, Slice.of(hb(aad)), Slice.of(hb(e + t))))
      _ <- check(hex(opened.toArray) == p, s"open expected=$p got=${hex(opened.toArray)}")
    yield ()

  test("A128CBC-HS256 (RFC 7518 B.1): seal reproduces the published E || T and open recovers P") {
    cbcHs(A128CbcHs256, cbcHsK128, cbcHsIv, cbcHsAad, cbcHsP, b1Ciphertext, b1Tag)
  }

  test("A256CBC-HS512 (RFC 7518 B.3): seal reproduces the published E || T and open recovers P") {
    cbcHs(A256CbcHs512, cbcHsK256, cbcHsIv, cbcHsAad, cbcHsP, b3Ciphertext, b3Tag)
  }

  // RFC 4231's keys are shorter than the digest, or longer than the JOSE cap, so none of them clears
  // `SecretKey.of`'s key-length policy; the vectors anchor the MAC computation, not that policy.
  // Test case 5 publishes only the leading 128 bits, hence the prefix comparison.
  private def hmacKat[H <: MacAlgorithm](vectors: List[(Int, String, String, String)])(using MAC[H]): IO[Unit] =
    cases(vectors, "hmac")
      .flatMap(_.traverse { (tc, k, data, expected) =>
        SecretKey.unsafe[H](hb(k)).sign(Slice.of(hb(data))).absolve.map { sig =>
          val got = hex(Array.from(sig.bytes.iterator)).take(expected.length)
          Option.when(got != expected)(s"tc$tc expected=$expected got=$got")
        }
      })
      .flatMap(report(_, "hmac"))

  test("HMAC-SHA-384 (RFC 4231 4.2-4.7): the published tags") {
    hmacKat[HmacSha384](rfc4231.map((tc, k, d, s384, _) => (tc, k, d, s384)))
  }

  test("HMAC-SHA-512 (RFC 4231 4.2-4.7): the published tags") {
    hmacKat[HmacSha512](rfc4231.map((tc, k, d, _, s512) => (tc, k, d, s512)))
  }

  test("AES-KW-256 (RFC 3394 4.5/4.6): wrap reproduces the published ciphertext and unwrap recovers the key") {
    val kek = SecretKey.of(AesKw256)(hb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).toOption.get
    val data192 = "00112233445566778899aabbccddeeff0001020304050607"
    val data256 = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"
    val wrapped192 = "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"
    val wrapped256 = "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"
    for
      w192 <- expectRight("4.5 wrap")(kek.wrap(SecretKey.of(AesGcm192)(hb(data192)).toOption.get))
      _ <- check(hex(w192.toArray) == wrapped192, s"4.5 expected=$wrapped192 got=${hex(w192.toArray)}")
      u192 <- kek.unwrap(Slice.of(hb(wrapped192)), AesGcm192).either
      _ <- check(u192.exists(k => k.read(s => hex(s.toArray)) == data192), "4.5 unwrap")
      w256 <- expectRight("4.6 wrap")(kek.wrap(SecretKey.of(AesGcm256)(hb(data256)).toOption.get))
      _ <- check(hex(w256.toArray) == wrapped256, s"4.6 expected=$wrapped256 got=${hex(w256.toArray)}")
      u256 <- kek.unwrap(Slice.of(hb(wrapped256)), AesGcm256).either
      _ <- check(u256.exists(k => k.read(s => hex(s.toArray)) == data256), "4.6 unwrap")
    yield ()
  }

  // RFC 5649's own examples use a 192-bit KEK, which this surface does not offer, so the padded
  // wrapping is anchored on Wycheproof instead. The vectors carry key data of arbitrary length -
  // what KWP exists for - which the typed `wrap` extension cannot express, so the backend trait is
  // driven directly.
  private def kwpKat[W <: WrapAlgorithm](spec: WrapSpec[W], keySize: Int)(using w: Wrap[W]): IO[Unit] =
    val vectors = for
      g <- parse(AesKwpTestJson.json).field("testGroups").arr.toList
      if g.field("keySize").int == keySize
      t <- g.field("tests").arr.toList
      result = t.field("result").str
      if result == "valid" || result == "invalid"
    yield (t.field("tcId").int, t.field("key").str, t.field("msg").str, t.field("ct").str, result)
    cases(vectors, s"kwp-$keySize")
      .flatMap(_.traverse { (tc, k, msg, ct, result) =>
        SecretKey.of(spec)(hb(k)) match
          case Left(_)    => IO.pure(Option(s"tc$tc kek rejected"))
          case Right(kek) =>
            if result == "valid" then
              for
                wrapped <- w.wrap(kek, Slice.of(hb(msg))).absolve.attempt
                opened <- w.unwrap(kek, Slice.of(hb(ct))).either.attempt
              yield
                val wrapOk = wrapped.exists(s => hex(s.toArray) == ct)
                val openOk = opened.exists(_.exists(s => hex(s.toArray) == msg))
                Option.when(!wrapOk || !openOk)(s"tc$tc wrap=$wrapOk unwrap=$openOk")
            else
              w.unwrap(kek, Slice.of(hb(ct)))
                .either
                .attempt
                .map(r => Option.when(r.exists(_.isRight))(s"tc$tc invalid wrapping accepted"))
      })
      .flatMap(report(_, s"kwp-$keySize"))
  end kwpKat

  test("AES-KWP-128 (Wycheproof aes_kwp): the published wrappings, and invalid ones rejected") {
    kwpKat(AesKwp128, 128)
  }

  test("AES-KWP-256 (Wycheproof aes_kwp): the published wrappings, and invalid ones rejected") {
    kwpKat(AesKwp256, 256)
  }

  private def sealGcm[A <: AeadAlgorithm](spec: AeadSpec[A], k: String, iv: String, aad: String, msg: String)(using AEAD[A]): IO[String] =
    val key = SecretKey.of(spec)(hb(k)).toOption.get
    key.seal(Nonce.unsafe[A](hb(iv)), Slice.of(hb(aad)), Slice.of(hb(msg))).absolve.map(s => hex(s.toArray))

  test("AES-GCM (Wycheproof aes_gcm): seal reproduces the published ct || tag") {
    val vectors = for
      g <- parse(AesGcmTestJson.json).field("testGroups").arr.toList
      if g.field("ivSize").int == 96 && g.field("tagSize").int == 128
      keySize = g.field("keySize").int
      t <- g.field("tests").arr.toList
      if t.field("result").str == "valid"
    yield (t.field("tcId").int,
           keySize,
           t.field("key").str,
           t.field("iv").str,
           t.field("aad").str,
           t.field("msg").str,
           t.field("ct").str + t.field("tag").str
    )
    cases(vectors, "aes-gcm seal")
      .flatMap(_.traverse { (tc, keySize, k, iv, aad, msg, expected) =>
        val produced = keySize match
          case 128 => sealGcm(AesGcm128, k, iv, aad, msg)
          case 192 => sealGcm(AesGcm192, k, iv, aad, msg)
          case _   => sealGcm(AesGcm256, k, iv, aad, msg)
        produced.map(got => Option.when(got != expected)(s"tc$tc expected=$expected got=$got"))
      })
      .flatMap(report(_, "aes-gcm seal"))
  }

  test("JWK thumbprint (RFC 7638 3.1): the published thumbprint of the RFC's RSA key") {
    for
      key <- expectRight("rsa components")(PublicKey.fromComponents(Slice.of(hb(rfc7638Modulus)), Slice.of(hb("010001"))))
      digest <- expectRight("thumbprint")(key.thumbprint)
      _ <- check(digest.hex == rfc7638Thumbprint, s"expected=$rfc7638Thumbprint got=${digest.hex}")
    yield ()
  }

  // A published encapsulation key from another implementation entirely: it must import, export back
  // byte for byte, and encapsulate. Decapsulating a published ciphertext would pin the other half,
  // but no backend can import an ML-KEM decapsulation key through this surface.
  private def kemWire[K <: KemAlgorithm](spec: KemSpec[K], ek: String)(using KemKeys[K], KEM[K]): IO[Unit] =
    for
      pub <- expectRight("encapsulation key")(PublicKey.fromRaw(spec)(Slice.of(hb(ek))))
      exported <- expectRight("export")(pub.raw)
      _ <- check(hex(Array.from(exported.iterator)) == ek, "encapsulation key round-trips byte for byte")
      enc <- pub.encapsulate.absolve
      _ <- check(enc.ciphertext.bytes.length == spec.ciphertextLength, s"ciphertext length ${enc.ciphertext.bytes.length}")
    yield ()

  test("ML-KEM-768 (Wycheproof mlkem_768 tc1): a foreign encapsulation key imports, exports and encapsulates") {
    kemWire(MlKem768, mlKem768Ek)
  }

  test("ML-KEM-1024 (Wycheproof mlkem_1024 tc1): a foreign encapsulation key imports, exports and encapsulates") {
    kemWire(MlKem1024, mlKem1024Ek)
  }
end AgreementSuite
