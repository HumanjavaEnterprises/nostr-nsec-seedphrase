[nostr-nsec-seedphrase - v0.4.2](../README.md) / [Exports](../modules.md) / UnsignedEvent

# Interface: UnsignedEvent

Represents an unsigned Nostr event before signing

## Table of contents

### Properties

- [content](UnsignedEvent.md#content)
- [created\_at](UnsignedEvent.md#created_at)
- [kind](UnsignedEvent.md#kind)
- [pubkey](UnsignedEvent.md#pubkey)
- [tags](UnsignedEvent.md#tags)

## Properties

### content

• **content**: `string`

Event content (arbitrary string)

#### Defined in

[index.ts:73](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L73)

___

### created\_at

• **created\_at**: `number`

Unix timestamp in seconds

#### Defined in

[index.ts:67](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L67)

___

### kind

• **kind**: `number`

Event kind (integer)

#### Defined in

[index.ts:69](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L69)

___

### pubkey

• **pubkey**: `string`

Event creator's public key (32-bytes lowercase hex)

#### Defined in

[index.ts:65](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L65)

___

### tags

• **tags**: `string`[][]

Array of arrays of strings (event tags)

#### Defined in

[index.ts:71](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L71)
