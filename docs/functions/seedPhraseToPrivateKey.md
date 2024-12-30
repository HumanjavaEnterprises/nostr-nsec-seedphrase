[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / seedPhraseToPrivateKey

# Function: seedPhraseToPrivateKey()

> **seedPhraseToPrivateKey**(`seedPhrase`): `string`

Converts a BIP39 seed phrase to a private key

## Parameters

### seedPhrase

`string`

The BIP39 seed phrase to convert

## Returns

`string`

The hex-encoded private key

## Throws

If the seed phrase is invalid

## Example

```ts
const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
console.log(privateKey); // hex private key
```

## Defined in

[index.ts:489](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L489)
