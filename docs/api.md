## Functions

<dl>
<dt><a href="#hmac">hmac(message, key)</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Implementation of HMAC SHA512 from <a href="https://github.com/dchest/tweetnacl-auth-js">https://github.com/dchest/tweetnacl-auth-js</a></p>
</dd>
<dt><a href="#getHKDF">getHKDF(ikm, info, extractLength, [salt])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Returns HKDF output according to rfc5869 using sha512</p>
</dd>
<dt><a href="#getSeed">getSeed([size])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Generates a random seed.</p>
</dd>
<dt><a href="#deriveSigningKeysFromSeed">deriveSigningKeysFromSeed(seed, [salt])</a></dt>
<dd><p>Derives an Ed25519 keypair given a random seed and an optional HKDF salt.</p>
</dd>
<dt><a href="#uint8ToHex">uint8ToHex(arr)</a> ⇒ <code>string</code></dt>
<dd><p>Converts Uint8Array or Buffer to a hex string.</p>
</dd>
<dt><a href="#hexToUint8">hexToUint8([hex])</a> ⇒ <code>Uint8Array</code></dt>
<dd><p>Converts hex string to a Uint8Array.</p>
</dd>
</dl>

<a name="hmac"></a>

## hmac(message, key) ⇒ <code>Uint8Array</code>
Implementation of HMAC SHA512 from https://github.com/dchest/tweetnacl-auth-js

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Uint8Array</code> | message to HMAC |
| key | <code>Uint8Array</code> | the HMAC key |

<a name="getHKDF"></a>

## getHKDF(ikm, info, extractLength, [salt]) ⇒ <code>Uint8Array</code>
Returns HKDF output according to rfc5869 using sha512

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| ikm | <code>Uint8Array</code> | input keying material |
| info | <code>Uint8Array</code> | context-specific info |
| extractLength | <code>number</code> | length of extracted output keying material in   octets |
| [salt] | <code>Uint8Array</code> | optional salt |

<a name="getSeed"></a>

## getSeed([size]) ⇒ <code>Uint8Array</code>
Generates a random seed.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| [size] | <code>number</code> | seed size in bytes; defaults to 32 |

<a name="deriveSigningKeysFromSeed"></a>

## deriveSigningKeysFromSeed(seed, [salt])
Derives an Ed25519 keypair given a random seed and an optional HKDF salt.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| seed | <code>Uint8Array</code> | random seed, recommended length 32 |
| [salt] | <code>Uint8Array</code> | random salt, recommended length 64 |

<a name="uint8ToHex"></a>

## uint8ToHex(arr) ⇒ <code>string</code>
Converts Uint8Array or Buffer to a hex string.

**Kind**: global function  

| Param | Type |
| --- | --- |
| arr | <code>Uint8Array</code> | 

<a name="hexToUint8"></a>

## hexToUint8([hex]) ⇒ <code>Uint8Array</code>
Converts hex string to a Uint8Array.

**Kind**: global function  

| Param | Type |
| --- | --- |
| [hex] | <code>string</code> | 

