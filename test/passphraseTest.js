const test = require('tape')
const {passphrase} = require('../index')
const crypto = require('crypto')

const array16 = [255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255
]

const array32 = [255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255,
  255, 255, 255, 255
]

test('fromBytesOrHex', (t) => {
  t.plan(6)
  t.equal(passphrase.fromBytesOrHex('00000000000000000000000000000000'),
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    'bip39 hex to phrase')
  t.equal(passphrase.fromBytesOrHex('00000000000000000000000000000000', true),
    'a a a a a a a a',
    'niceware hex to phrase')
  t.equal(passphrase.fromBytesOrHex(
    new Uint8Array(array16)),
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  'bip39 uint8array to phrase')
  t.equal(passphrase.fromBytesOrHex(
    new Uint8Array(array16), true),
  'zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva',
  'niceware uint8array to phrase')
  t.equal(passphrase.fromBytesOrHex(
    Buffer.from(array32)),
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote',
  'bip39 buffer to phrase')
  t.equal(passphrase.fromBytesOrHex(
    Buffer.from(array32), true),
  'zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva',
  'niceware buffer to phrase')
})

test('toBytes32', (t) => {
  t.plan(4)
  t.deepEqual(passphrase.toBytes32('a a a a a a a a a a a a a a a a'),
    new Uint8Array(32))
  t.deepEqual(passphrase.toBytes32(' zyzzyva  zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva'),
    new Uint8Array(array32))
  t.deepEqual(passphrase.toBytes32('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'),
    new Uint8Array(array32))
  t.throws(passphrase.toBytes32.bind(null, 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'),
    /words length/,
    'errors if input is unrecognized length')
})

test('toHex32', (t) => {
  t.plan(4)
  t.equal(passphrase.toHex32('horsepox tiglon monolithic impoundment classiest propagation deviant temporize precessed sunburning pricey spied plack batcher overpassed bioengineering'),
    '65f9e2ea89dd6a8d2333ab0b3808e011a757da60a95cd201a2e40df098f111d4')
  t.equal(passphrase.toHex32(' zyzzyva  zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva zyzzyva'),
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
  t.equal(passphrase.toHex32('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'),
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
  t.throws(passphrase.toHex32.bind(null, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'), /length/, 'errors if input is unrecognized length')
})

test('original seed can be recovered', (t) => {
  const hex = '65f9e2ea89dd6a8d2333ab0b3808e011a757da60a95cd201a2e40df098f111d4'
  const bytes = crypto.randomBytes(32)
  t.plan(6)

  // Niceware tests to recover original hex, buffer, and uint8array
  t.equal(hex, passphrase.toHex32(passphrase.fromBytesOrHex(hex, true)),
    'niceware hex conversion')
  t.deepEqual(new Uint8Array(bytes), passphrase.toBytes32(passphrase.fromBytesOrHex(bytes, true)),
    'niceware buffer conversion')
  t.deepEqual(new Uint8Array(bytes),
    passphrase.toBytes32(passphrase.fromBytesOrHex(new Uint8Array(bytes), true)),
    'niceware uint8array conversion')

  // bip39 tests to recover original hex, buffer, and uint8array
  t.equal(hex, passphrase.toHex32(passphrase.fromBytesOrHex(hex)),
    'bip39 hex conversion')
  t.deepEqual(new Uint8Array(bytes), passphrase.toBytes32(passphrase.fromBytesOrHex(bytes)),
    'bip39 buffer conversion')
  t.deepEqual(new Uint8Array(bytes),
    passphrase.toBytes32(passphrase.fromBytesOrHex(new Uint8Array(bytes))),
    'bip39 uint8array conversion')
})

test('original passphrase can be recovered', (t) => {
  const nicewarePhrase = 'toothpick reproductive endpoint barbecued gainer pleadable painful adjacent nonstructural prewash strawy extendable extinguishable glimmering juxtapose concurring'
  const bipPhrase = 'magic vacuum wide review love peace century egg burden clutch heart cycle annual mixed pink awesome extra client cry brisk priority maple mountain jelly'
  t.plan(4)

  // niceware tests
  t.equal(nicewarePhrase,
    passphrase.fromBytesOrHex(passphrase.toBytes32(nicewarePhrase), true),
    'uint8array niceware conversion')
  t.equal(nicewarePhrase,
    passphrase.fromBytesOrHex(passphrase.toHex32(nicewarePhrase), true),
    'hex niceware conversion')

  // bip39 tests
  t.equal(bipPhrase,
    passphrase.fromBytesOrHex(passphrase.toBytes32(bipPhrase)),
    'uint8array bip39 conversion')
  t.equal(bipPhrase,
    passphrase.fromBytesOrHex(passphrase.toHex32(bipPhrase)),
    'hex bip39 conversion')
})
