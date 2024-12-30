[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / verifySignature

# Function: verifySignature()

> **verifySignature**(`message`, `signature`, `publicKey`): `Promise`\<`boolean`\>

Verifies a message signature

## Parameters

### message

`string`

The original message

### signature

`string`

The hex-encoded signature to verify

### publicKey

`string`

The hex-encoded public key to verify against

## Returns

`Promise`\<`boolean`\>

True if the signature is valid, false otherwise

## Example

```ts
const isValid = await verifySignature("Hello Nostr!", signature, publicKey);
console.log(isValid); // true or false
```

## Defined in

[index.ts:638](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L638)
