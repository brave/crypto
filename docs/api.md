## Members

<dl>
<dt><a href="#passphrase">passphrase</a></dt>
<dd><p>Utilities for converting keys to passphrases using bip39 or niceware</p>
</dd>
<dt><a href="#random">random</a></dt>
<dd><p>Random samplers.</p>
</dd>
</dl>

## Constants

<dl>
<dt><a href="#DEFAULT_SEED_SIZE">DEFAULT_SEED_SIZE</a> : <code>number</code></dt>
<dd><p>Default seed size in bytes.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#hmac">hmac(message, key)</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Implementation of HMAC SHA512 from <a href="https://github.com/dchest/tweetnacl-auth-js">https://github.com/dchest/tweetnacl-auth-js</a></p>
</dd>
<dt><a href="#getHKDF">getHKDF(ikm, info, extractLen, [salt])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Returns HKDF output according to rfc5869 using sha512</p>
</dd>
<dt><a href="#getSeed">getSeed([size])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Generates a random seed.</p>
</dd>
<dt><a href="#deriveSigningKeysFromSeed">deriveSigningKeysFromSeed(seed, [salt])</a> ⇒ <code>Object</code></dt>
<dd><p>Derives an Ed25519 keypair given a random seed and an optional HKDF salt.
Returns a nacl.sign keypair object:
<a href="https://github.com/dchest/tweetnacl-js#naclsignkeypair">https://github.com/dchest/tweetnacl-js#naclsignkeypair</a></p>
</dd>
<dt><a href="#uint8ToHex">uint8ToHex(arr)</a> ⇒ <code>string</code></dt>
<dd><p>Converts Uint8Array or Buffer to a hex string.</p>
</dd>
<dt><a href="#hexToUint8">hexToUint8([hex])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Converts hex string to a Uint8Array.</p>
</dd>
</dl>

<a name="passphrase"></a>

## passphrase
Utilities for converting keys to passphrases using bip39 or niceware

**Kind**: global variable  

* [passphrase](#passphrase)
    * [.NICEWARE_32_BYTE_WORD_COUNT](#passphrase.NICEWARE_32_BYTE_WORD_COUNT) : <code>number</code>
    * [.BIP39_32_BYTE_WORD_COUNT](#passphrase.BIP39_32_BYTE_WORD_COUNT) : <code>number</code>
    * [.fromBytesOrHex(bytes, [useNiceware])](#passphrase.fromBytesOrHex) ⇒ <code>string</code>
    * [.toBytes32(passphrase)](#passphrase.toBytes32) ⇒ <code>Uint8Array</code>
    * [.toHex32(passphrase)](#passphrase.toHex32) ⇒ <code>string</code>

<a name="passphrase.NICEWARE_32_BYTE_WORD_COUNT"></a>

### passphrase.NICEWARE\_32\_BYTE\_WORD\_COUNT : <code>number</code>
Number of niceware words corresponding to 32 bytes

**Kind**: static constant of [<code>passphrase</code>](#passphrase)  
**Default**: <code>16</code>  
<a name="passphrase.BIP39_32_BYTE_WORD_COUNT"></a>

### passphrase.BIP39\_32\_BYTE\_WORD\_COUNT : <code>number</code>
Number of niceware words corresponding to 32 bytes

**Kind**: static constant of [<code>passphrase</code>](#passphrase)  
**Default**: <code>24</code>  
<a name="passphrase.fromBytesOrHex"></a>

### passphrase.fromBytesOrHex(bytes, [useNiceware]) ⇒ <code>string</code>
Converts bytes to passphrase using bip39 (default) or niceware

**Kind**: static method of [<code>passphrase</code>](#passphrase)  

| Param | Type | Description |
| --- | --- | --- |
| bytes | <code>Uint8Array</code> \| <code>Buffer</code> \| <code>string</code> | Uint8Array / Buffer / hex to convert |
| [useNiceware] | <code>boolean</code> | Whether to use Niceware; defaults to false |

<a name="passphrase.toBytes32"></a>

### passphrase.toBytes32(passphrase) ⇒ <code>Uint8Array</code>
Converts a 32-byte passphrase to uint8array bytes. Infers whether the
passphrase is bip39 or niceware based on length.

**Kind**: static method of [<code>passphrase</code>](#passphrase)  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | bip39/niceware phrase to convert |

<a name="passphrase.toHex32"></a>

### passphrase.toHex32(passphrase) ⇒ <code>string</code>
Converts a 32-byte passphrase to hex. Infers whether the
passphrase is bip39 or niceware based on length.

**Kind**: static method of [<code>passphrase</code>](#passphrase)  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | bip39/niceware phrase to convert |

<a name="random"></a>

## random
Random samplers.

**Kind**: global variable  

* [random](#random)
    * [.uniform(n)](#random.uniform) ⇒ <code>number</code>
    * [.uniform_01()](#random.uniform_01) ⇒ <code>number</code>

<a name="random.uniform"></a>

### random.uniform(n) ⇒ <code>number</code>
Sample uniformly at random from nonnegative integers below a
specified bound.

**Kind**: static method of [<code>random</code>](#random)  

| Param | Type | Description |
| --- | --- | --- |
| n | <code>number</code> | exclusive upper bound, positive integer at most 2^53 |

<a name="random.uniform_01"></a>

### random.uniform\_01() ⇒ <code>number</code>
Sample uniformly at random from floating-point numbers in [0, 1].

**Kind**: static method of [<code>random</code>](#random)  
<a name="DEFAULT_SEED_SIZE"></a>

## DEFAULT\_SEED\_SIZE : <code>number</code>
Default seed size in bytes.

**Kind**: global constant  
**Default**: <code>32</code>  
<a name="hmac"></a>

## hmac(message, key) ⇒ <code>Uint8Array</code>
Implementation of HMAC SHA512 from https://github.com/dchest/tweetnacl-auth-js

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Uint8Array</code> | message to HMAC |
| key | <code>Uint8Array</code> | the HMAC key |

<a name="getHKDF"></a>

## getHKDF(ikm, info, extractLen, [salt]) ⇒ <code>Uint8Array</code>
Returns HKDF output according to rfc5869 using sha512

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| ikm | <code>Uint8Array</code> | input keying material |
| info | <code>Uint8Array</code> | context-specific info |
| extractLen | <code>number</code> | length of extracted output keying material in   octets |
| [salt] | <code>Uint8Array</code> | optional salt |

<a name="getSeed"></a>

## getSeed([size]) ⇒ <code>Uint8Array</code>
Generates a random seed.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| [size] | <code>number</code> | seed size in bytes; defaults to 32 |

<a name="deriveSigningKeysFromSeed"></a>

## deriveSigningKeysFromSeed(seed, [salt]) ⇒ <code>Object</code>
Derives an Ed25519 keypair given a random seed and an optional HKDF salt.
Returns a nacl.sign keypair object:
https://github.com/dchest/tweetnacl-js#naclsignkeypair

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| seed | <code>Uint8Array</code> | random seed, recommended length 32 |
| [salt] | <code>Uint8Array</code> | random salt, recommended length 64 |

<a name="uint8ToHex"></a>

## uint8ToHex(arr) ⇒ <code>string</code>
Converts Uint8Array or Buffer to a hex string.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| arr | <code>Uint8Array</code> \| <code>Buffer</code> | Uint8Array / Buffer to convert |

<a name="hexToUint8"></a>

## hexToUint8([hex]) ⇒ <code>Uint8Array</code>
Converts hex string to a Uint8Array.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| [hex] | <code>string</code> | Hex string to convert; defaults to '' |

