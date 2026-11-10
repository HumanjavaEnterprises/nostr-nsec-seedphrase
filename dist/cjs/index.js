"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  NIP06_DERIVATION_PATH: () => NIP06_DERIVATION_PATH,
  configureHMAC: () => configureHMAC,
  createEvent: () => createEvent,
  fromHex: () => fromHex,
  fromNcryptsec: () => fromNcryptsec,
  generateKeyPairWithSeed: () => generateKeyPairWithSeed,
  generateSeedPhrase: () => generateSeedPhrase,
  getCompressedPublicKey: () => getCompressedPublicKey,
  getEntropyFromSeedPhrase: () => getEntropyFromSeedPhrase,
  getNip06DerivationPath: () => getNip06DerivationPath,
  getPublicKey: () => getPublicKey,
  hexToNpub: () => hexToNpub,
  hexToNsec: () => hexToNsec,
  nip19: () => nip19,
  npubToHex: () => npubToHex,
  nsecToHex: () => nsecToHex,
  nsecToPrivateKey: () => nsecToPrivateKey,
  privateKeyToNpub: () => privateKeyToNpub,
  privateKeyToNsec: () => privateKeyToNsec,
  seedPhraseToKeyPair: () => seedPhraseToKeyPair,
  seedPhraseToKeyPairLegacy: () => seedPhraseToKeyPairLegacy,
  seedPhraseToPrivateKey: () => seedPhraseToPrivateKey,
  seedPhraseToPrivateKeyLegacy: () => seedPhraseToPrivateKeyLegacy,
  signEvent: () => signEvent,
  signMessage: () => signMessage,
  toNcryptsec: () => toNcryptsec,
  validateSeedPhrase: () => validateSeedPhrase,
  verifyEvent: () => verifyEvent,
  verifySignature: () => verifySignature
});
module.exports = __toCommonJS(index_exports);
var import_bip39 = require("@scure/bip39");
var import_english = require("@scure/bip39/wordlists/english.js");
var import_bip32 = require("@scure/bip32");
var import_secp256k1 = require("@noble/curves/secp256k1.js");
var import_utils = require("@noble/hashes/utils.js");
var import_sha2 = require("@noble/hashes/sha2.js");
var import_hmac = require("@noble/hashes/hmac.js");
var import_bech32 = require("bech32");
var import_nip49 = require("nostr-crypto-utils/nip49");
var generateMnemonic = () => (0, import_bip39.generateMnemonic)(import_english.wordlist, 128);
var validateMnemonic = (m) => (0, import_bip39.validateMnemonic)(m, import_english.wordlist);
function generateSeedPhrase() {
  return generateMnemonic();
}
function getEntropyFromSeedPhrase(seedPhrase) {
  if (!validateMnemonic(seedPhrase)) {
    throw new Error("Invalid seed phrase");
  }
  return (0, import_bip39.mnemonicToEntropy)(seedPhrase, import_english.wordlist);
}
function validateSeedPhrase(seedPhrase) {
  return validateMnemonic(seedPhrase);
}
var NIP06_DERIVATION_PATH = "m/44'/1237'/0'/0/0";
function getNip06DerivationPath(account = 0) {
  if (!Number.isInteger(account) || account < 0 || account > 2147483647) {
    throw new Error(
      "Invalid account index: must be an integer from 0 to 2147483647"
    );
  }
  return `m/44'/1237'/${account}'/0/0`;
}
function deriveNip06PrivateKey(seedPhrase, options) {
  if (options == null) options = {};
  if (typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError(
      "Invalid options: expected an object like { account, passphrase }"
    );
  }
  const { account = 0, passphrase = "" } = options;
  const path = getNip06DerivationPath(account);
  if (typeof passphrase !== "string") {
    throw new Error("Invalid passphrase: must be a string");
  }
  if (!validateMnemonic(seedPhrase)) {
    throw new Error("Invalid seed phrase");
  }
  const seed = (0, import_bip39.mnemonicToSeedSync)(seedPhrase, passphrase);
  const child = import_bip32.HDKey.fromMasterSeed(seed).derive(path);
  seed.fill(0);
  if (!child.privateKey || child.privateKey.length !== 32) {
    throw new Error("Failed to derive NIP-06 private key");
  }
  const privateKeyHex = (0, import_utils.bytesToHex)(child.privateKey);
  child.wipePrivateData();
  return privateKeyHex;
}
function seedPhraseToKeyPair(seedPhrase, options) {
  const privateKeyHex = deriveNip06PrivateKey(seedPhrase, options);
  const publicKeyBytes = import_secp256k1.schnorr.getPublicKey((0, import_utils.hexToBytes)(privateKeyHex));
  const publicKey = (0, import_utils.bytesToHex)(publicKeyBytes);
  const nsec = nip19.nsecEncode(privateKeyHex);
  const npub = nip19.npubEncode(publicKey);
  return {
    privateKey: privateKeyHex,
    publicKey,
    nsec,
    npub,
    seedPhrase
  };
}
function seedPhraseToPrivateKeyLegacy(seedPhrase) {
  const entropy = getEntropyFromSeedPhrase(seedPhrase);
  const privateKeyBytes = (0, import_sha2.sha256)(entropy);
  entropy.fill(0);
  const privateKeyHex = (0, import_utils.bytesToHex)(privateKeyBytes);
  privateKeyBytes.fill(0);
  return privateKeyHex;
}
function seedPhraseToKeyPairLegacy(seedPhrase) {
  const privateKeyHex = seedPhraseToPrivateKeyLegacy(seedPhrase);
  const publicKeyBytes = import_secp256k1.schnorr.getPublicKey((0, import_utils.hexToBytes)(privateKeyHex));
  const publicKey = (0, import_utils.bytesToHex)(publicKeyBytes);
  return {
    privateKey: privateKeyHex,
    publicKey,
    nsec: nip19.nsecEncode(privateKeyHex),
    npub: nip19.npubEncode(publicKey),
    seedPhrase
  };
}
function generateKeyPairWithSeed() {
  const seedPhrase = generateMnemonic();
  return seedPhraseToKeyPair(seedPhrase);
}
function fromHex(privateKeyHex) {
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKeyHex);
  if (!import_secp256k1.secp256k1.utils.isValidSecretKey(privateKeyBytes)) {
    privateKeyBytes.fill(0);
    throw new Error("Invalid private key");
  }
  const publicKeyBytes = import_secp256k1.schnorr.getPublicKey(privateKeyBytes);
  privateKeyBytes.fill(0);
  const publicKey = (0, import_utils.bytesToHex)(publicKeyBytes);
  const nsec = nip19.nsecEncode(privateKeyHex);
  const npub = nip19.npubEncode(publicKey);
  return {
    privateKey: privateKeyHex,
    publicKey,
    nsec,
    npub,
    seedPhrase: ""
    // No seed phrase for hex-imported keys
  };
}
function getPublicKey(privateKey) {
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKey);
  const publicKeyBytes = import_secp256k1.schnorr.getPublicKey(privateKeyBytes);
  privateKeyBytes.fill(0);
  return (0, import_utils.bytesToHex)(publicKeyBytes);
}
function getCompressedPublicKey(privateKey) {
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKey);
  const publicKeyBytes = import_secp256k1.secp256k1.getPublicKey(privateKeyBytes, true);
  privateKeyBytes.fill(0);
  return (0, import_utils.bytesToHex)(publicKeyBytes);
}
function encode32(prefix, hex, what) {
  const data = (0, import_utils.hexToBytes)(hex);
  if (data.length !== 32) {
    throw new Error(
      `Invalid ${what}: ${prefix} requires exactly 32 bytes, got ${data.length}`
    );
  }
  return import_bech32.bech32.encode(prefix, import_bech32.bech32.toWords(data), 1e3);
}
function decode32(prefix, str) {
  const { prefix: got, words } = import_bech32.bech32.decode(str, 1e3);
  if (got !== prefix) throw new Error(`Invalid ${prefix}: wrong prefix`);
  const data = Uint8Array.from(import_bech32.bech32.fromWords(words));
  if (data.length !== 32) {
    throw new Error(
      `Invalid ${prefix}: expected a 32-byte payload, got ${data.length} bytes`
    );
  }
  return data;
}
function assertValidSecretKey(data) {
  if (!import_secp256k1.secp256k1.utils.isValidSecretKey(data)) {
    throw new Error("Invalid private key: must be 32 bytes with 0 < d < n");
  }
}
var nip19 = {
  /**
   * Encodes a public key into npub format
   * @param {string} pubkey - The hex-encoded 32-byte x-only public key
   * @returns {string} The bech32-encoded npub string
   * @throws {Error} If the key is not exactly 32 bytes of hex
   */
  npubEncode(pubkey) {
    return encode32("npub", pubkey, "public key");
  },
  /**
   * Decodes an npub string to hex format
   * @param {string} npub - The bech32-encoded npub string
   * @returns {string} The hex-encoded public key
   * @throws {Error} If the prefix is wrong or the payload is not 32 bytes
   */
  npubDecode(npub) {
    return (0, import_utils.bytesToHex)(decode32("npub", npub));
  },
  /**
   * Encodes a private key into nsec format
   * @param {string} privkey - The hex-encoded 32-byte private key
   * @returns {string} The bech32-encoded nsec string
   * @throws {Error} If the key is not 32 bytes or not in the range 0 < d < n
   */
  nsecEncode(privkey) {
    const data = (0, import_utils.hexToBytes)(privkey);
    try {
      assertValidSecretKey(data);
      return import_bech32.bech32.encode("nsec", import_bech32.bech32.toWords(data), 1e3);
    } finally {
      data.fill(0);
    }
  },
  /**
   * Decodes an nsec string to hex format
   * @param {string} nsec - The bech32-encoded nsec string
   * @returns {string} The hex-encoded private key
   * @throws {Error} If the prefix is wrong, the payload is not 32 bytes, or
   *   the key is not in the range 0 < d < n
   */
  nsecDecode(nsec) {
    const data = decode32("nsec", nsec);
    try {
      assertValidSecretKey(data);
      return (0, import_utils.bytesToHex)(data);
    } finally {
      data.fill(0);
    }
  },
  /**
   * Encodes an event ID into note format
   * @param {string} eventId - The hex-encoded 32-byte event ID
   * @returns {string} The bech32-encoded note string
   * @throws {Error} If the id is not exactly 32 bytes of hex
   */
  noteEncode(eventId) {
    return encode32("note", eventId, "event id");
  },
  /**
   * Decodes a note string to hex format
   * @param {string} note - The bech32-encoded note string
   * @returns {string} The hex-encoded event ID
   * @throws {Error} If the prefix is wrong or the payload is not 32 bytes
   */
  noteDecode(note) {
    return (0, import_utils.bytesToHex)(decode32("note", note));
  },
  /**
   * Decodes any bech32-encoded Nostr entity without checking its prefix or
   * length. Prefer the typed decoders above, which validate both.
   * @param {string} bech32str - The bech32-encoded string
   * @returns {{ type: string; data: Uint8Array }} Object containing the decoded type and data
   * @property {string} type - The bech32 prefix (e.g. npub, nsec, note)
   * @property {Uint8Array} data - The raw decoded data
   */
  decode(bech32str) {
    const { prefix, words } = import_bech32.bech32.decode(bech32str, 1e3);
    return { type: prefix, data: Uint8Array.from(import_bech32.bech32.fromWords(words)) };
  }
};
function getEventHash(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content
  ]);
  return (0, import_utils.bytesToHex)((0, import_sha2.sha256)(new TextEncoder().encode(serialized)));
}
async function signEvent(event, privateKey) {
  const eventHash = getEventHash(event);
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKey);
  const signature = import_secp256k1.schnorr.sign((0, import_utils.hexToBytes)(eventHash), privateKeyBytes);
  privateKeyBytes.fill(0);
  return (0, import_utils.bytesToHex)(signature);
}
async function verifyEvent(event) {
  if (!event.id || !event.pubkey || !event.sig) {
    return false;
  }
  const hash = getEventHash(event);
  if (hash !== event.id) {
    return false;
  }
  return import_secp256k1.schnorr.verify(
    (0, import_utils.hexToBytes)(event.sig),
    (0, import_utils.hexToBytes)(hash),
    (0, import_utils.hexToBytes)(event.pubkey)
  );
}
function configureHMAC() {
  const hmacFunction = (key, ...messages) => {
    const h = import_hmac.hmac.create(import_sha2.sha256, key);
    messages.forEach((msg) => h.update(msg));
    return h.digest();
  };
  const hmacSyncFunction = (key, ...messages) => {
    const h = import_hmac.hmac.create(import_sha2.sha256, key);
    messages.forEach((msg) => h.update(msg));
    return h.digest();
  };
  if ("utils" in import_secp256k1.secp256k1 && typeof import_secp256k1.secp256k1.utils?.hmacSha256Sync !== "undefined") {
    import_secp256k1.secp256k1.utils.hmacSha256 = hmacFunction;
    import_secp256k1.secp256k1.utils.hmacSha256Sync = hmacSyncFunction;
  }
}
async function createEvent(content, kind, privateKey, tags = []) {
  const publicKey = getPublicKey(privateKey);
  const event = {
    pubkey: publicKey,
    created_at: Math.floor(Date.now() / 1e3),
    kind,
    tags,
    content
  };
  const id = getEventHash(event);
  const sig = await signEvent(event, privateKey);
  return {
    ...event,
    id,
    sig
  };
}
function seedPhraseToPrivateKey(seedPhrase, options) {
  return seedPhraseToKeyPair(seedPhrase, options).privateKey;
}
function privateKeyToNsec(privateKey) {
  return nip19.nsecEncode(privateKey);
}
function privateKeyToNpub(privateKey) {
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKey);
  const publicKey = import_secp256k1.schnorr.getPublicKey(privateKeyBytes);
  privateKeyBytes.fill(0);
  return nip19.npubEncode((0, import_utils.bytesToHex)(publicKey));
}
function nsecToHex(nsec) {
  const hexPrivateKey = nip19.nsecDecode(nsec);
  return hexPrivateKey;
}
function npubToHex(npub) {
  return nip19.npubDecode(npub);
}
function hexToNpub(publicKeyHex) {
  return nip19.npubEncode(publicKeyHex);
}
function hexToNsec(privateKeyHex) {
  return nip19.nsecEncode(privateKeyHex);
}
async function signMessage(message, privateKey) {
  const messageBytes = new TextEncoder().encode(message);
  const messageHash = (0, import_sha2.sha256)(messageBytes);
  const messageHashHex = (0, import_utils.bytesToHex)(messageHash);
  const privateKeyBytes = (0, import_utils.hexToBytes)(privateKey);
  const signature = import_secp256k1.schnorr.sign((0, import_utils.hexToBytes)(messageHashHex), privateKeyBytes);
  privateKeyBytes.fill(0);
  return (0, import_utils.bytesToHex)(signature);
}
async function verifySignature(message, signature, publicKey) {
  const messageBytes = new TextEncoder().encode(message);
  const messageHash = (0, import_sha2.sha256)(messageBytes);
  const messageHashHex = (0, import_utils.bytesToHex)(messageHash);
  return import_secp256k1.schnorr.verify(
    (0, import_utils.hexToBytes)(signature),
    (0, import_utils.hexToBytes)(messageHashHex),
    (0, import_utils.hexToBytes)(publicKey)
  );
}
function nsecToPrivateKey(nsec) {
  return nip19.nsecDecode(nsec);
}
function toNcryptsec(privateKeyHex, password, logn = 16) {
  const secretBytes = (0, import_utils.hexToBytes)(privateKeyHex);
  try {
    assertValidSecretKey(secretBytes);
    return (0, import_nip49.encrypt)(secretBytes, password, logn);
  } finally {
    secretBytes.fill(0);
  }
}
function fromNcryptsec(ncryptsec, password) {
  const secretBytes = (0, import_nip49.decrypt)(ncryptsec, password);
  const hex = (0, import_utils.bytesToHex)(secretBytes);
  secretBytes.fill(0);
  return hex;
}
