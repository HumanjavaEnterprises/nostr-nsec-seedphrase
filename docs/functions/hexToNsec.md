[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / hexToNsec

# Function: hexToNsec()

> **hexToNsec**(`privateKeyHex`): `string`

Converts a hex private key to bech32 nsec format

## Parameters

### privateKeyHex

`string`

The hex-encoded private key

## Returns

`string`

The bech32-encoded nsec private key

## Throws

If the private key is invalid

## Example

```ts
const nsec = hexToNsec("1234567890abcdef...");
console.log(nsec); // "nsec1..."
```

## Defined in

[index.ts:592](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L592)
