[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / nsecToPrivateKey

# Function: nsecToPrivateKey()

> **nsecToPrivateKey**(`nsec`): `string`

Converts a bech32 nsec private key to hex format

## Parameters

### nsec

`string`

The bech32-encoded nsec private key

## Returns

`string`

The hex-encoded private key

## Throws

If the nsec key is invalid

## Example

```ts
const hex = nsecToPrivateKey("nsec1...");
console.log(hex); // "1234567890abcdef..."
```

## Defined in

[index.ts:667](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L667)
