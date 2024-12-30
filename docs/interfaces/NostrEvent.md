[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / NostrEvent

# Interface: NostrEvent

Represents a signed Nostr event

## See

https://github.com/nostr-protocol/nips/blob/master/01.md

## Properties

### content

> **content**: `string`

Event content (arbitrary string)

#### Defined in

[index.ts:43](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L43)

***

### created\_at

> **created\_at**: `number`

Unix timestamp in seconds

#### Defined in

[index.ts:37](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L37)

***

### id

> **id**: `string`

Event ID (32-bytes lowercase hex of the sha256 of the serialized event data)

#### Defined in

[index.ts:33](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L33)

***

### kind

> **kind**: `number`

Event kind (integer)

#### Defined in

[index.ts:39](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L39)

***

### pubkey

> **pubkey**: `string`

Event creator's public key (32-bytes lowercase hex)

#### Defined in

[index.ts:35](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L35)

***

### sig

> **sig**: `string`

Event signature (64-bytes hex of the schnorr signature of the sha256 hash of the serialized event data)

#### Defined in

[index.ts:45](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L45)

***

### tags

> **tags**: `string`[][]

Array of arrays of strings (event tags)

#### Defined in

[index.ts:41](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L41)
