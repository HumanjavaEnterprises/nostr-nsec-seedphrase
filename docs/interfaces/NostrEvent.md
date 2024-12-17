[nostr-nsec-seedphrase - v0.4.2](../README.md) / [Exports](../modules.md) / NostrEvent

# Interface: NostrEvent

Represents a signed Nostr event

**`See`**

https://github.com/nostr-protocol/nips/blob/master/01.md

## Table of contents

### Properties

- [content](NostrEvent.md#content)
- [created\_at](NostrEvent.md#created_at)
- [id](NostrEvent.md#id)
- [kind](NostrEvent.md#kind)
- [pubkey](NostrEvent.md#pubkey)
- [sig](NostrEvent.md#sig)
- [tags](NostrEvent.md#tags)

## Properties

### content

• **content**: `string`

Event content (arbitrary string)

#### Defined in

[index.ts:54](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L54)

___

### created\_at

• **created\_at**: `number`

Unix timestamp in seconds

#### Defined in

[index.ts:48](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L48)

___

### id

• **id**: `string`

Event ID (32-bytes lowercase hex of the sha256 of the serialized event data)

#### Defined in

[index.ts:44](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L44)

___

### kind

• **kind**: `number`

Event kind (integer)

#### Defined in

[index.ts:50](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L50)

___

### pubkey

• **pubkey**: `string`

Event creator's public key (32-bytes lowercase hex)

#### Defined in

[index.ts:46](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L46)

___

### sig

• **sig**: `string`

Event signature (64-bytes hex of the schnorr signature of the sha256 hash of the serialized event data)

#### Defined in

[index.ts:56](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L56)

___

### tags

• **tags**: `string`[][]

Array of arrays of strings (event tags)

#### Defined in

[index.ts:52](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L52)
