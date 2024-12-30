[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / generateKeyPairWithSeed

# Function: generateKeyPairWithSeed()

> **generateKeyPairWithSeed**(): [`KeyPair`](../interfaces/KeyPair.md)

Generates a new key pair with a random seed phrase

## Returns

[`KeyPair`](../interfaces/KeyPair.md)

A new key pair containing private and public keys in various formats

## Example

```ts
const keyPair = generateKeyPairWithSeed();
console.log(keyPair.seedPhrase); // random seed phrase
console.log(keyPair.privateKey);  // hex private key
console.log(keyPair.publicKey);   // hex public key
```

## Defined in

[index.ts:159](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L159)
