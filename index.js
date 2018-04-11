// @flow

'use strict'

const nacl = require('tweetnacl')
const niceware = require('niceware')
const bip39 = require('bip39')

/**
 * Default seed size in bytes.
 * @const
 * @type {number}
 * @default
 */
module.exports.DEFAULT_SEED_SIZE = 32

/**
 * Implementation of HMAC SHA512 from https://github.com/dchest/tweetnacl-auth-js
 * @param {Uint8Array} message message to HMAC
 * @param {Uint8Array} key the HMAC key
 * @returns {Uint8Array}
 */
module.exports.hmac = function (message/* : Uint8Array */, key/* : Uint8Array */) {
  if (!(message instanceof Uint8Array) || !(key instanceof Uint8Array)) {
    throw new Error('Inputs must be Uint8Arrays.')
  }

  const BLOCK_SIZE = 128
  const HASH_SIZE = 64
  const buf = new Uint8Array(BLOCK_SIZE + Math.max(HASH_SIZE, message.length))
  var i, innerHash

  if (key.length > BLOCK_SIZE) {
    key = nacl.hash(key)
  }

  for (i = 0; i < BLOCK_SIZE; i++) buf[i] = 0x36
  for (i = 0; i < key.length; i++) buf[i] ^= key[i]
  buf.set(message, BLOCK_SIZE)
  innerHash = nacl.hash(buf.subarray(0, BLOCK_SIZE + message.length))

  for (i = 0; i < BLOCK_SIZE; i++) buf[i] = 0x5c
  for (i = 0; i < key.length; i++) buf[i] ^= key[i]
  buf.set(innerHash, BLOCK_SIZE)
  return nacl.hash(buf.subarray(0, BLOCK_SIZE + innerHash.length))
}

/**
 * Returns HKDF output according to rfc5869 using sha512
 * @param {Uint8Array} ikm input keying material
 * @param {Uint8Array} info context-specific info
 * @param {number} extractLength length of extracted output keying material in
 *   octets
 * @param {Uint8Array=} salt optional salt
 * @returns {Uint8Array}
 */
module.exports.getHKDF = function (ikm/* : Uint8Array */, info/* : Uint8Array */,
  extractLen, salt/* : Uint8Array */) {
  const hashLength = 512 / 8

  if (typeof extractLen !== 'number' || extractLen < 0 ||
    extractLen > hashLength * 255) {
    throw Error('Invalid extract length.')
  }

  // Extract
  if (!(salt instanceof Uint8Array) || salt.length === 0) {
    salt = new Uint8Array(hashLength)
  }
  var prk = module.exports.hmac(ikm, salt) // Pseudorandom Key

  // Expand
  var n = Math.ceil(extractLen / hashLength)
  var t = []
  t[0] = new Uint8Array()
  info = info || new Uint8Array()
  var okm = new Uint8Array(extractLen)

  let filled = 0
  for (var i = 1; i <= n; i++) {
    let prev = t[i - 1]
    let input = new Uint8Array(info.length + prev.length + 1)
    input.set(prev)
    input.set(info, prev.length)
    input.set(new Uint8Array([i]), prev.length + info.length)
    let output = module.exports.hmac(input, prk)
    t[i] = output

    let remaining = extractLen - filled
    if (remaining === 0) {
      return okm
    } else if (output.length <= remaining) {
      okm.set(output, filled)
      filled = filled + output.length
    } else {
      okm.set(output.slice(0, remaining), filled)
      return okm
    }
  }
}

/**
 * Generates a random seed.
 * @param {number=} size seed size in bytes; defaults to 32
 * @returns {Uint8Array}
 */
module.exports.getSeed = function (size/* : number */ = module.exports.DEFAULT_SEED_SIZE) {
  return nacl.randomBytes(size)
}

/**
 * Derives an Ed25519 keypair given a random seed and an optional HKDF salt.
 * Returns a nacl.sign keypair object:
 * https://github.com/dchest/tweetnacl-js#naclsignkeypair
 * @param {Uint8Array} seed random seed, recommended length 32
 * @param {Uint8Array=} salt random salt, recommended length 64
 * @returns {{secretKey: Uint8Array, publicKey: Uint8Array}}
 */
module.exports.deriveSigningKeysFromSeed = function (seed/* : Uint8Array */, salt/* : Uint8Array */) {
  if (!(seed instanceof Uint8Array)) {
    throw new Error('Seed must be Uint8Array.')
  }
  // Derive the Ed25519 signing keypair
  const output = module.exports.getHKDF(seed, new Uint8Array([0]),
    nacl.sign.seedLength, salt)
  return nacl.sign.keyPair.fromSeed(output)
}

/**
 * Converts Uint8Array or Buffer to a hex string.
 * @param {Uint8Array|Buffer} arr Uint8Array / Buffer to convert
 * @returns {string}
 */
module.exports.uint8ToHex = function (arr/* : Uint8Array | Buffer */) {
  if (!(arr instanceof Uint8Array)) {
    throw new Error('Input must be a Buffer or Uint8Array')
  }
  let buffer = arr
  if (!(arr instanceof Buffer)) {
    // Convert Uint8Array to Buffer
    buffer = Buffer.from(arr.buffer)
    // From https://github.com/feross/typedarray-to-buffer/blob/master/index.js
    if (arr.byteLength !== arr.buffer.byteLength) {
      buffer = buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength)
    }
  }
  return buffer.toString('hex')
}

/**
 * Converts hex string to a Uint8Array.
 * @param {string=} hex Hex string to convert; defaults to ''
 * @returns {Uint8Array}
 */
module.exports.hexToUint8 = function (hex/* : string */ = '') {
  if (typeof hex !== 'string') {
    throw new Error('Input must be a string')
  }
  if (hex.length % 2 !== 0) {
    hex = '0' + hex
  }
  const arr = new Uint8Array(hex.length / 2)
  for (var i = 0; i < hex.length / 2; i++) {
    arr[i] = Number('0x' + hex[2 * i] + hex[2 * i + 1])
  }
  return arr
}

// For browserify
if (typeof window === 'object') {
  window.module = module
}

/**
 * Utilities for converting keys to passphrases using bip39 or niceware
 */
module.exports.passphrase = {
  /* @exports passphrase */
  /**
   * Converts bytes to passphrase using bip39 (default) or niceware
   * @method
   * @param {Uint8Array|Buffer|string} bytes Uint8Array / Buffer / hex to convert
   * @param {boolean=} useNiceware Whether to use Niceware; defaults to false
   * @returns {string}
   */
  fromBytesOrHex: function (bytes/* : Uint8Array | string */, useNiceware/* : boolean */ = false) {
    if (useNiceware) {
      if (typeof bytes === 'string') {
        bytes = module.exports.hexToUint8(bytes)
      }
      return niceware.bytesToPassphrase(Buffer.from(bytes)).join(' ')
    } else {
      if (typeof bytes !== 'string') {
        bytes = module.exports.uint8ToHex(bytes)
      }
      return bip39.entropyToMnemonic(bytes)
    }
  },

  /**
   * Converts a 32-byte passphrase to uint8array bytes. Infers whether the
   * passphrase is bip39 or niceware based on length.
   * @method
   * @param {string} passphrase bip39/niceware phrase to convert
   * @returns {Uint8Array}
   */
  toBytes32: function (passphrase/* : string */) {
    passphrase = passphrase.trim().replace(/\s+/gi, ' ')
    const words = passphrase.split(' ')
    if (words.length === module.exports.passphrase.NICEWARE_32_BYTE_WORD_COUNT) {
      return new Uint8Array(niceware.passphraseToBytes(words))
    } else if (words.length === module.exports.passphrase.BIP39_32_BYTE_WORD_COUNT) {
      return module.exports.hexToUint8(bip39.mnemonicToEntropy(passphrase))
    } else {
      throw new Error(`Input words length ${words.length} is not 24 or 16.`)
    }
  },

  /**
   * Converts a 32-byte passphrase to hex. Infers whether the
   * passphrase is bip39 or niceware based on length.
   * @method
   * @param {string} passphrase bip39/niceware phrase to convert
   * @returns {string}
   */
  toHex32: function (passphrase/* : string */) {
    passphrase = passphrase.trim().replace(/\s+/gi, ' ')
    const words = passphrase.split(' ')
    if (words.length === module.exports.passphrase.NICEWARE_32_BYTE_WORD_COUNT) {
      const bytes = niceware.passphraseToBytes(words)
      return module.exports.uint8ToHex(bytes)
    } else if (words.length === module.exports.passphrase.BIP39_32_BYTE_WORD_COUNT) {
      return bip39.mnemonicToEntropy(passphrase)
    } else {
      throw new Error(`Input word length ${words.length} is not 24 or 16.`)
    }
  },

  /**
   * Number of niceware words corresponding to 32 bytes
   * @const
   * @type {number}
   * @default
   */
  NICEWARE_32_BYTE_WORD_COUNT: 16,

  /**
   * Number of niceware words corresponding to 32 bytes
   * @const
   * @type {number}
   * @default
   */
  BIP39_32_BYTE_WORD_COUNT: 24
}
