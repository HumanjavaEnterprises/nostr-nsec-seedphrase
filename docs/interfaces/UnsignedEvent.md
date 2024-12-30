[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / UnsignedEvent

# Interface: UnsignedEvent

Represents an unsigned Nostr event before signing

## Properties

### content

> **content**: `string`

Event content (arbitrary string)

#### Defined in

[index.ts:62](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L62)

***

### created\_at

> **created\_at**: `number`

Unix timestamp in seconds

#### Defined in

[index.ts:56](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L56)

***

### kind

> **kind**: `number`

Event kind (integer)

#### Defined in

[index.ts:58](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L58)

***

### pubkey

> **pubkey**: `string`

Event creator's public key (32-bytes lowercase hex)

#### Defined in

[index.ts:54](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L54)

***

### tags

> **tags**: `string`[][]

Array of arrays of strings (event tags)

#### Defined in

[index.ts:60](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L60)
