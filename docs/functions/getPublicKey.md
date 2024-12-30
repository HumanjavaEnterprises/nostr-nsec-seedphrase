[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / getPublicKey

# Function: getPublicKey()

> **getPublicKey**(`privateKey`): `string`

Derives a public key from a private key

## Parameters

### privateKey

`string`

The hex-encoded private key

## Returns

`string`

The hex-encoded public key

## Example

```ts
const pubkey = getPublicKey("1234567890abcdef...");
console.log(pubkey); // hex public key
```

## Defined in

[index.ts:212](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L212)
