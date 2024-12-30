[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / getEntropyFromSeedPhrase

# Function: getEntropyFromSeedPhrase()

> **getEntropyFromSeedPhrase**(`seedPhrase`): `Uint8Array`

Converts a BIP39 seed phrase to its entropy value

## Parameters

### seedPhrase

`string`

The BIP39 seed phrase to convert

## Returns

`Uint8Array`

The entropy value

## Throws

If the seed phrase is invalid

## Example

```ts
const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
console.log(entropy); // Uint8Array
```

## Defined in

[index.ts:85](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L85)
