[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / seedPhraseToKeyPair

# Function: seedPhraseToKeyPair()

> **seedPhraseToKeyPair**(`seedPhrase`): [`KeyPair`](../interfaces/KeyPair.md)

Converts a BIP39 seed phrase to a Nostr key pair

## Parameters

### seedPhrase

`string`

The BIP39 seed phrase to convert

## Returns

[`KeyPair`](../interfaces/KeyPair.md)

A key pair containing private and public keys in various formats

## Throws

If the seed phrase is invalid or key generation fails

## Example

```ts
const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
console.log(keyPair.privateKey); // hex private key
console.log(keyPair.publicKey);  // hex public key
console.log(keyPair.nsec);       // bech32 nsec private key
console.log(keyPair.npub);       // bech32 npub public key
```

## Defined in

[index.ts:122](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L122)
