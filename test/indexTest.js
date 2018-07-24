const test = require('tape')
const crypto = require('../index')
const nacl = require('tweetnacl')

const toHex = crypto.uint8ToHex
const fromHex = crypto.hexToUint8

test('getSeed', (t) => {
  t.plan(2)
  t.equal(crypto.getSeed().length, 32)
  t.equal(crypto.getSeed(666).length, 666)
})

test('hmac', (t) => {
  // https://tools.ietf.org/html/rfc4231#section-4
  const keys = [
    '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    '4a656665',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  ]
  const data = [
    '4869205468657265',
    '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    '546573742057697468205472756e636174696f6e',
    '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
    '5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e'
  ]
  const outputs = [
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
    '415fad6271580a531d4179bc891d87a6',
    '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
    'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58'
  ]
  t.plan(8)
  outputs.forEach((output, i) => {
    if (i === 4) {
      // test case 5 tests truncation to 128 bits
      t.ok(toHex(crypto.hmac(fromHex(data[i]), fromHex(keys[i]))).startsWith(output))
      return
    }
    t.equal(output, toHex(crypto.hmac(fromHex(data[i]), fromHex(keys[i]))))
  })
  t.throws(crypto.hmac.bind(null, new Uint8Array(), []), /Uint8Arrays/, 'errors if inputs are wrong type')
})

test('hkdf', (t) => {
  // https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
  var results = [{
    "IKM"   : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "salt"  : "000102030405060708090a0b0c",
    "info"  : "f0f1f2f3f4f5f6f7f8f9",
    "L"     : 42,
    "OKM"   : "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
  }, {
    "IKM"   : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    "salt"  : "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "info"  : "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "L"     : 82,
    "OKM"   : "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93"
  }, {
    "IKM"   : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    "salt"  : "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "info"  : "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "L"     : 64, // Same as above but truncated to a multiple of HMAC length.
    "OKM"   : "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235"
  }, {
    "IKM"   : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "salt"  : "",
    "info"  : "",
    "L"     : 42,
    "OKM"   : "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac"
  }, {
    "IKM"   : "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "salt"  : "",
    // "info"  : ...,       // This field intentionally blank.
    "L"     : 42,
    "OKM"   : "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac"
  }, {
    "IKM"   : "0b0b0b0b0b0b0b0b0b0b0b",
    "salt"  : "000102030405060708090a0b0c",
    "info"  : "f0f1f2f3f4f5f6f7f8f9",
    "L"     : 42,
    "OKM"   : "7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff53559bd5e3028b080f7c068"
  }, {
    "IKM"   : "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
    "info"  : "",
    "L"     : 42,
    "OKM"   : "1407d46013d98bc6decefcfee55f0f90b0c7f63d68eb1a80eaf07e953cfc0a3a5240a155d6e4daa965bb"
  }]
  t.plan(8)
  results.forEach((result) => {
    var hkdf = crypto.getHKDF(
      fromHex(result['IKM']),
      'info' in result && fromHex(result['info']),
      result['L'],
      fromHex(result['salt'])
    )
    t.equal(toHex(hkdf), result['OKM'])
  })
  t.throws(crypto.getHKDF.bind(null, new Uint8Array(1), new Uint8Array(), 16321), /Invalid extract length/, 'error when extract length is too long')
})

test('uint8ToHex', (t) => {
  t.plan(8)
  t.equal(toHex(new Uint8Array([])), '')
  t.equal(toHex(new Uint8Array([0])), '00')
  t.equal(toHex(new Uint8Array([0, 255])), '00ff')
  t.equal(toHex(new Uint8Array([30, 1, 2, 3])), '1e010203')
  const buf = new ArrayBuffer(6)
  for (let i = 0; i < 6; i++) {
    new Uint8Array(buf)[i] = [42, 30, 1, 2, 3, 73][i]
  }
  t.equal(toHex(new Uint8Array(buf, 1, 4)), '1e010203')
  t.equal(toHex(Buffer.from([30, 1, 2, 3])), '1e010203')
  t.equal(toHex(Buffer.alloc(3)), '000000')
  t.throws(toHex.bind(null, 'foo'), /Uint8Array/, 'errors if inputs are wrong type')
})

test('hexToUint8', (t) => {
  t.plan(6)
  t.deepEqual(fromHex('00'), {0: 0})
  t.deepEqual(fromHex('1'), {0: 1})
  t.deepEqual(fromHex(''), {})
  t.deepEqual(fromHex('00ff'), {0: 0, 1: 255})
  t.deepEqual(fromHex('1e010203'), {0: 30, 1: 1, 2: 2, 3: 3})
  t.throws(fromHex.bind(null, new Uint8Array(3)), /string/, 'errors if inputs are wrong type')
})

test('key derivation', (t) => {
  const HKDF_SALT = new Uint8Array([72, 203, 156, 43, 64, 229, 225, 127, 214, 158, 50, 29, 130, 186, 182, 207, 6, 108, 47, 254, 245, 71, 198, 109, 44, 108, 32, 193, 221, 126, 119, 143, 112, 113, 87, 184, 239, 231, 230, 234, 28, 135, 54, 42, 9, 243, 39, 30, 179, 147, 194, 211, 212, 239, 225, 52, 192, 219, 145, 40, 95, 19, 142, 98])
  t.plan(5)
  const key = crypto.deriveSigningKeysFromSeed(fromHex("5bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"), HKDF_SALT)
  t.equal('f58ca446f0c33ee7e8e9874466da442b2e764afd77ad46034bdff9e01f9b87d4', toHex(key.publicKey), 'gets pub key')
  t.equal('b5abda6940984c5153a2ba3653f047f98dfb19e39c3e02f07c8bbb0bd8e8872ef58ca446f0c33ee7e8e9874466da442b2e764afd77ad46034bdff9e01f9b87d4', toHex(key.secretKey), 'gets priv key')
  const message = Buffer.from('€ 123 ッッッ　あ')
  const signed = nacl.sign(message, key.secretKey)
  t.deepEqual(nacl.sign.open(signed, key.publicKey), message, 'verification success')
  signed[0] = 255
  t.deepEqual(nacl.sign.open(signed, key.publicKey), null, 'verification failure')
  t.throws(crypto.deriveSigningKeysFromSeed.bind(null, []), /Uint8Array/, 'error when input is not a Uint8Array')
})
