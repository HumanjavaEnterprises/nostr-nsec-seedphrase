[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / fromHex

# Function: fromHex()

> **fromHex**(`privateKeyHex`): [`KeyPair`](../interfaces/KeyPair.md)

Creates a key pair from a hex private key

## Parameters

### privateKeyHex

`string`

The hex-encoded private key

## Returns

[`KeyPair`](../interfaces/KeyPair.md)

A key pair containing private and public keys in various formats

## Throws

If the private key is invalid

## Example

```ts
const keyPair = fromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
console.log(keyPair.publicKey); // corresponding public key
console.log(keyPair.nsec);      // bech32 nsec private key
console.log(keyPair.npub);      // bech32 npub public key
```

## Defined in

[index.ts:175](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L175)
