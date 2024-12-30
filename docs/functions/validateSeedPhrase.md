[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / validateSeedPhrase

# Function: validateSeedPhrase()

> **validateSeedPhrase**(`seedPhrase`): `boolean`

Validates a BIP39 seed phrase

## Parameters

### seedPhrase

`string`

The seed phrase to validate

## Returns

`boolean`

True if the seed phrase is valid, false otherwise

## Example

```ts
const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
console.log(isValid); // true
```

## Defined in

[index.ts:102](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L102)
