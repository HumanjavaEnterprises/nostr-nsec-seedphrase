[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / npubToHex

# Function: npubToHex()

> **npubToHex**(`npub`): `string`

Converts a bech32 npub public key to hex format

## Parameters

### npub

`string`

The bech32-encoded npub public key

## Returns

`string`

The hex-encoded public key

## Throws

If the npub key is invalid

## Example

```ts
const hex = npubToHex("npub1...");
console.log(hex); // "1234567890abcdef..."
```

## Defined in

[index.ts:550](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L550)
