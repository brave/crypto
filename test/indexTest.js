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

const pair = nacl.sign.keyPair.fromSecretKey(
  Uint8Array.from(
    Buffer.from('9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c526b40b8f93fff3d897112f7ebc582b232dbd72517d082fe83cfb30ddce43d1bb', 'hex')
  )
)
const goodSignature = 'keyId="test-key-ed25519",algorithm="ed25519",headers="foo fizz",signature="lAGT9Bhde3sJp8Z1NTxmViJtG1PSoYnXV9he82z1iu//KXmCrjKYe1JOU34memKIdlxG1yJoeS2hxANRvalrBw=="'

test('signing', (t) => {
  const headers = { foo: 'bar', fizz: 'buzz' }
  t.plan(5)

  let signature = crypto.ed25519Sign('test-key-ed25519', pair.secretKey, headers);
  t.equal(signature, goodSignature)
  
  // Incorrect header
  signature = crypto.ed25519Sign('test-key-ed25519', pair.secretKey, { ...headers, fizz: 'fizz' });
  t.notEqual(signature, goodSignature)
  
  // No headers
  t.throws(crypto.ed25519Sign.bind('test-key-ed25519', pair.secretKey), 'headers are required')
  
  // No Secret Key
  t.throws(crypto.ed25519Sign.bind('test-key-ed25519', pair.secretKey, headers), 'secret key is required')
  
  // No Key ID
  t.throws(crypto.ed25519Sign.bind(null, pair.secretKey, headers), 'key ID is required')
})

test('verification', (t) => {
  t.plan(7)
  const headers = { foo: 'bar', fizz: 'buzz', signature: goodSignature }
  let verified = crypto.ed25519Verify(pair.publicKey, headers)
  t.equal(verified, true)
  
  // Miss a byte
  let testKey = pair.publicKey;
  t.throws(crypto.ed25519Verify.bind(testKey.slice(1, 2), headers), 'header signature is required')
  
  // Modify a byte
  testKey = Uint8Array.from(pair.publicKey);
  testKey[0] = 0;
  verified = crypto.ed25519Verify(testKey, headers)
  t.equal(verified, false)
  
  // Miss a header
  let bad = { foo: 'bar', signature: goodSignature }
  verified = crypto.ed25519Verify(testKey, bad)
  t.equal(verified, false)
  
  // Missing part of the signature
  bad = { ...headers }
  bad.signature = bad.signature.slice(25, goodSignature.length)
  t.equal(bad.signature, 'algorithm="ed25519",headers="foo fizz",signature="lAGT9Bhde3sJp8Z1NTxmViJtG1PSoYnXV9he82z1iu//KXmCrjKYe1JOU34memKIdlxG1yJoeS2hxANRvalrBw=="')
  verified = crypto.ed25519Verify(testKey, bad)
  t.equal(verified, false)
  
  // Missing signature
  bad = { ...headers }
  delete bad.signature
  t.throws(crypto.ed25519Verify.bind(pair.publicKey, headers), 'header signature is required')
})
