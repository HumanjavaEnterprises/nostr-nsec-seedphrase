[**nostr-nsec-seedphrase v0.6.0**](../README.md)

***

[nostr-nsec-seedphrase](../globals.md) / signMessage

# Function: signMessage()

> **signMessage**(`message`, `privateKey`): `Promise`\<`string`\>

Signs a message with a private key

## Parameters

### message

`string`

The message to sign

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
const signature = await signMessage("Hello Nostr!", privateKey);
console.log(signature); // hex-encoded signature
```

## Defined in

[index.ts:612](https://github.com/HumanjavaEnterprises/nostr-nsec-seedphrase/blob/885e04e5180059d4aa901af59d633038a53240cb/src/index.ts#L612)
