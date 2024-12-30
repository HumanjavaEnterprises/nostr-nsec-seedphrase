[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / verifyEvent

# Function: verifyEvent()

> **verifyEvent**(`event`): `Promise`\<`boolean`\>

Verifies a Nostr event signature

## Parameters

### event

[`NostrEvent`](../interfaces/NostrEvent.md)

The event to verify

## Returns

`Promise`\<`boolean`\>

True if the signature is valid, false otherwise

## Example

```ts
const isValid = await verifyEvent(event);
console.log(isValid); // true or false
```

## Defined in

[index.ts:372](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L372)
