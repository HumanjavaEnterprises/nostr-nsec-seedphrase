[nostr-nsec-seedphrase - v0.4.2](README.md) / Exports

# nostr-nsec-seedphrase - v0.4.2

## Table of contents

### Interfaces

- [KeyPair](interfaces/KeyPair.md)
- [NostrEvent](interfaces/NostrEvent.md)
- [UnsignedEvent](interfaces/UnsignedEvent.md)

### Functions

- [configureHMAC](modules.md#configurehmac)
- [createEvent](modules.md#createevent)
- [fromHex](modules.md#fromhex)
- [generateKeyPairWithSeed](modules.md#generatekeypairwithseed)
- [generateSeedPhrase](modules.md#generateseedphrase)
- [getEntropyFromSeedPhrase](modules.md#getentropyfromseedphrase)
- [hexToNpub](modules.md#hextonpub)
- [hexToNsec](modules.md#hextonsec)
- [npubToHex](modules.md#npubtohex)
- [nsecToHex](modules.md#nsectohex)
- [seedPhraseToKeyPair](modules.md#seedphrasetokeypair)
- [signEvent](modules.md#signevent)
- [signMessage](modules.md#signmessage)
- [validateSeedPhrase](modules.md#validateseedphrase)
- [verifyEvent](modules.md#verifyevent)
- [verifySignature](modules.md#verifysignature)

## Functions

### configureHMAC

▸ **configureHMAC**(): `void`

Configures secp256k1 with HMAC for WebSocket utilities
This is required for some WebSocket implementations

#### Returns

`void`

**`Example`**

```ts
configureHMAC();
```

#### Defined in

[index.ts:429](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L429)

___

### createEvent

▸ **createEvent**(`content`, `kind`, `privateKey`, `tags?`): `Promise`\<[`NostrEvent`](interfaces/NostrEvent.md)\>

Creates a new signed Nostr event

#### Parameters

| Name | Type | Default value | Description |
| :------ | :------ | :------ | :------ |
| `content` | `string` | `undefined` | The event content |
| `kind` | `number` | `undefined` | The event kind (1 for text note, etc.) |
| `privateKey` | `string` | `undefined` | The hex-encoded private key to sign with |
| `tags?` | `string`[][] | `[]` | Optional event tags |

#### Returns

`Promise`\<[`NostrEvent`](interfaces/NostrEvent.md)\>

The signed event

**`Throws`**

If event creation or signing fails

**`Example`**

```ts
const event = await createEvent(
  "Hello Nostr!",
  1,
  privateKey,
  [["t", "nostr"]]
);
console.log(event); // complete signed event
```

#### Defined in

[index.ts:479](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L479)

___

### fromHex

▸ **fromHex**(`privateKeyHex`): [`KeyPair`](interfaces/KeyPair.md)

Creates a key pair from a hex private key

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `privateKeyHex` | `string` | The hex-encoded private key |

#### Returns

[`KeyPair`](interfaces/KeyPair.md)

A key pair containing private and public keys in various formats

**`Throws`**

If the private key is invalid

**`Example`**

```ts
const keyPair = fromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
console.log(keyPair.publicKey); // corresponding public key
console.log(keyPair.nsec);      // bech32 nsec private key
console.log(keyPair.npub);      // bech32 npub public key
```

#### Defined in

[index.ts:190](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L190)

___

### generateKeyPairWithSeed

▸ **generateKeyPairWithSeed**(): [`KeyPair`](interfaces/KeyPair.md)

Generates a new key pair with a random seed phrase

#### Returns

[`KeyPair`](interfaces/KeyPair.md)

A new key pair containing private and public keys in various formats

**`Example`**

```ts
const keyPair = generateKeyPairWithSeed();
console.log(keyPair.seedPhrase); // random seed phrase
console.log(keyPair.privateKey);  // hex private key
console.log(keyPair.publicKey);   // hex public key
```

#### Defined in

[index.ts:168](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L168)

___

### generateSeedPhrase

▸ **generateSeedPhrase**(): `string`

Generates a new BIP39 seed phrase

#### Returns

`string`

A random 12-word BIP39 mnemonic seed phrase

**`Example`**

```ts
const seedPhrase = generateSeedPhrase();
console.log(seedPhrase); // "witch collapse practice feed shame open despair creek road again ice least"
```

#### Defined in

[index.ts:83](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L83)

___

### getEntropyFromSeedPhrase

▸ **getEntropyFromSeedPhrase**(`seedPhrase`): `string`

Converts a BIP39 seed phrase to its entropy value

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `seedPhrase` | `string` | The BIP39 seed phrase to convert |

#### Returns

`string`

The hex-encoded entropy value

**`Throws`**

If the seed phrase is invalid

**`Example`**

```ts
const entropy = getEntropyFromSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
console.log(entropy); // "0123456789abcdef0123456789abcdef"
```

#### Defined in

[index.ts:96](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L96)

___

### hexToNpub

▸ **hexToNpub**(`publicKeyHex`): `string`

Converts a hex public key to bech32 npub format

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `publicKeyHex` | `string` | The hex-encoded public key |

#### Returns

`string`

The bech32-encoded npub public key

**`Throws`**

If the public key is invalid

**`Example`**

```ts
const npub = hexToNpub("1234567890abcdef...");
console.log(npub); // "npub1..."
```

#### Defined in

[index.ts:272](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L272)

___

### hexToNsec

▸ **hexToNsec**(`privateKeyHex`): `string`

Converts a hex private key to bech32 nsec format

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `privateKeyHex` | `string` | The hex-encoded private key |

#### Returns

`string`

The bech32-encoded nsec private key

**`Throws`**

If the private key is invalid

**`Example`**

```ts
const nsec = hexToNsec("1234567890abcdef...");
console.log(nsec); // "nsec1..."
```

#### Defined in

[index.ts:291](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L291)

___

### npubToHex

▸ **npubToHex**(`npub`): `string`

Converts a bech32 npub public key to hex format

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `npub` | `string` | The bech32-encoded npub public key |

#### Returns

`string`

The hex-encoded public key

**`Throws`**

If the npub key is invalid

**`Example`**

```ts
const hex = npubToHex("npub1...");
console.log(hex); // "1234567890abcdef..."
```

#### Defined in

[index.ts:249](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L249)

___

### nsecToHex

▸ **nsecToHex**(`nsec`): `string`

Converts a bech32 nsec private key to hex format

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `nsec` | `string` | The bech32-encoded nsec private key |

#### Returns

`string`

The hex-encoded private key

**`Throws`**

If the nsec key is invalid

**`Example`**

```ts
const hex = nsecToHex("nsec1...");
console.log(hex); // "1234567890abcdef..."
```

#### Defined in

[index.ts:226](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L226)

___

### seedPhraseToKeyPair

▸ **seedPhraseToKeyPair**(`seedPhrase`): [`KeyPair`](interfaces/KeyPair.md)

Converts a BIP39 seed phrase to a Nostr key pair

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `seedPhrase` | `string` | The BIP39 seed phrase to convert |

#### Returns

[`KeyPair`](interfaces/KeyPair.md)

A key pair containing private and public keys in various formats

**`Throws`**

If the seed phrase is invalid or key generation fails

**`Example`**

```ts
const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
console.log(keyPair.privateKey); // hex private key
console.log(keyPair.publicKey);  // hex public key
console.log(keyPair.nsec);       // bech32 nsec private key
console.log(keyPair.npub);       // bech32 npub public key
```

#### Defined in

[index.ts:135](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L135)

___

### signEvent

▸ **signEvent**(`event`, `privateKey`): `Promise`\<`string`\>

Signs a Nostr event

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `event` | [`UnsignedEvent`](interfaces/UnsignedEvent.md) | The event to sign |
| `privateKey` | `string` | The hex-encoded private key to sign with |

#### Returns

`Promise`\<`string`\>

The hex-encoded signature

**`Throws`**

If signing fails

**`Example`**

```ts
const signature = await signEvent({
  pubkey: "...",
  created_at: Math.floor(Date.now() / 1000),
  kind: 1,
  tags: [],
  content: "Hello Nostr!"
}, privateKey);
```

#### Defined in

[index.ts:372](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L372)

___

### signMessage

▸ **signMessage**(`message`, `privateKey`): `Promise`\<`string`\>

Signs a message with a private key

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | The message to sign |
| `privateKey` | `string` | The hex-encoded private key to sign with |

#### Returns

`Promise`\<`string`\>

The hex-encoded signature

**`Throws`**

If signing fails

**`Example`**

```ts
const signature = await signMessage("Hello Nostr!", privateKey);
console.log(signature); // hex-encoded signature
```

#### Defined in

[index.ts:311](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L311)

___

### validateSeedPhrase

▸ **validateSeedPhrase**(`seedPhrase`): `boolean`

Validates a BIP39 seed phrase

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `seedPhrase` | `string` | The seed phrase to validate |

#### Returns

`boolean`

True if the seed phrase is valid, false otherwise

**`Example`**

```ts
const isValid = validateSeedPhrase("witch collapse practice feed shame open despair creek road again ice least");
console.log(isValid); // true
```

#### Defined in

[index.ts:112](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L112)

___

### verifyEvent

▸ **verifyEvent**(`event`): `Promise`\<`boolean`\>

Verifies a Nostr event signature

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `event` | [`NostrEvent`](interfaces/NostrEvent.md) | The event to verify |

#### Returns

`Promise`\<`boolean`\>

True if the signature is valid, false otherwise

**`Example`**

```ts
const isValid = await verifyEvent(event);
console.log(isValid); // true or false
```

#### Defined in

[index.ts:398](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L398)

___

### verifySignature

▸ **verifySignature**(`message`, `signature`, `publicKey`): `Promise`\<`boolean`\>

Verifies a message signature

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `message` | `string` | The original message |
| `signature` | `string` | The hex-encoded signature to verify |
| `publicKey` | `string` | The hex-encoded public key to verify against |

#### Returns

`Promise`\<`boolean`\>

True if the signature is valid, false otherwise

**`Example`**

```ts
const isValid = await verifySignature("Hello Nostr!", signature, publicKey);
console.log(isValid); // true or false
```

#### Defined in

[index.ts:337](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/82dc31d49db09b8dba7ff55e6136b06bb1b16a3e/src/index.ts#L337)
