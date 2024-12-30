[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / privateKeyToNpub

# Function: privateKeyToNpub()

> **privateKeyToNpub**(`privateKey`): `string`

Converts a private key to bech32 npub format

## Parameters

### privateKey

`string`

The hex-encoded private key

## Returns

`string`

The bech32-encoded npub public key

## Throws

If the private key is invalid

## Example

```ts
const npub = privateKeyToNpub("1234567890abcdef...");
console.log(npub); // "npub1..."
```

## Defined in

[index.ts:515](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L515)
