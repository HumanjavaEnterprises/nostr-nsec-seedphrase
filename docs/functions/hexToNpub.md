[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / hexToNpub

# Function: hexToNpub()

> **hexToNpub**(`publicKeyHex`): `string`

Converts a hex public key to bech32 npub format

## Parameters

### publicKeyHex

`string`

The hex-encoded public key

## Returns

`string`

The bech32-encoded npub public key

## Throws

If the public key is invalid

## Example

```ts
const npub = hexToNpub("1234567890abcdef...");
console.log(npub); // "npub1..."
```

## Defined in

[index.ts:573](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L573)
