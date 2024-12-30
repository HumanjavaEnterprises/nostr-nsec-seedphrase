[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / createEvent

# Function: createEvent()

> **createEvent**(`content`, `kind`, `privateKey`, `tags`?): `Promise`\<[`NostrEvent`](../interfaces/NostrEvent.md)\>

Creates a new signed Nostr event

## Parameters

### content

`string`

The event content

### kind

`number`

The event kind (1 for text note, etc.)

### privateKey

`string`

The hex-encoded private key to sign with

### tags?

`string`[][] = `[]`

Optional event tags

## Returns

`Promise`\<[`NostrEvent`](../interfaces/NostrEvent.md)\>

The signed event

## Throws

If event creation or signing fails

## Example

```ts
const event = await createEvent(
  "Hello Nostr!",
  1,
  privateKey,
  [["t", "nostr"]]
);
console.log(event); // complete signed event
```

## Defined in

[index.ts:453](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L453)
