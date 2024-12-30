[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / signEvent

# Function: signEvent()

> **signEvent**(`event`, `privateKey`): `Promise`\<`string`\>

Signs a Nostr event

## Parameters

### event

[`UnsignedEvent`](../interfaces/UnsignedEvent.md)

The event to sign

### privateKey

`string`

The hex-encoded private key to sign with

## Returns

`Promise`\<`string`\>

The hex-encoded signature

## Throws

If signing fails

## Example

```ts
const signature = await signEvent({
  pubkey: "...",
  created_at: Math.floor(Date.now() / 1000),
  kind: 1,
  tags: [],
  content: "Hello Nostr!"
}, privateKey);
```

## Defined in

[index.ts:346](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L346)
