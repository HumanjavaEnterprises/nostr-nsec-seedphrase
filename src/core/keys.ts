import * as secp256k1 from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";
import { pino } from "pino";
import { KeyPair } from "../types/keys.js";
import {
  generateSeedPhrase,
  validateSeedPhrase,
  getEntropyFromSeedPhrase,
} from "../bips/bip39.js";
import { hexToNpub, hexToNsec } from "../nips/nip-19.js";

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: {
    target: "pino-pretty",
    options: {
      colorize: true,
    },
  },
});

/**
 * Derives a public key from a private key
 * @param {string} privateKey - The hex-encoded private key
 * @returns {string} The hex-encoded public key
 * @example
 * const pubkey = getPublicKey("1234567890abcdef...");
 * console.log(pubkey); // hex public key
 */
export function getPublicKey(privateKey: string): string {
  try {
    const pubkey = bytesToHex(secp256k1.getPublicKey(privateKey, true));
    return pubkey;
  } catch (error) {
    logger.error("Failed to derive public key:", error);
    throw new Error("Failed to derive public key");
  }
}

/**
 * Creates a key pair from a hex private key
 * @param {string} privateKeyHex - The hex-encoded private key
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the private key is invalid
 * @example
 * const keyPair = fromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
 * console.log(keyPair.publicKey); // corresponding public key
 * console.log(keyPair.nsec);      // bech32 nsec private key
 * console.log(keyPair.npub);      // bech32 npub public key
 */
export function fromHex(privateKeyHex: string): KeyPair {
  try {
    if (!privateKeyHex || privateKeyHex.length !== 64) {
      throw new Error("Invalid private key format");
    }

    const pubkeyHex = getPublicKey(privateKeyHex);
    const pubkeyBytes = hexToBytes(pubkeyHex);
    const publicKey = {
      hex: pubkeyHex,
      compressed: pubkeyBytes,
      schnorr: pubkeyBytes.slice(1),
      npub: hexToNpub(pubkeyHex),
    };
    const nsec = hexToNsec(privateKeyHex);

    return {
      privateKey: privateKeyHex,
      publicKey,
      nsec,
      seedPhrase: "", // No seed phrase for hex-derived keys
    };
  } catch (error) {
    logger.error("Failed to create key pair from hex:", error);
    throw new Error("Failed to create key pair from hex");
  }
}

/**
 * Generates a new key pair with a random seed phrase
 * @returns {KeyPair} A new key pair containing private and public keys in various formats
 * @example
 * const keyPair = generateKeyPairWithSeed();
 * console.log(keyPair.seedPhrase); // random seed phrase
 * console.log(keyPair.privateKey);  // hex private key
 * console.log(keyPair.publicKey);   // hex public key
 */
export function generateKeyPairWithSeed(): KeyPair {
  try {
    const seedPhrase = generateSeedPhrase();
    if (!validateSeedPhrase(seedPhrase)) {
      throw new Error("Generated invalid seed phrase");
    }
    return seedPhraseToKeyPair(seedPhrase);
  } catch (error) {
    logger.error("Failed to generate key pair with seed:", error);
    throw new Error("Failed to generate key pair with seed");
  }
}

/**
 * Converts a BIP39 seed phrase to a Nostr key pair
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {KeyPair} A key pair containing private and public keys in various formats
 * @throws {Error} If the seed phrase is invalid or key generation fails
 * @example
 * const keyPair = seedPhraseToKeyPair("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(keyPair.privateKey); // hex private key
 * console.log(keyPair.publicKey);  // hex public key
 * console.log(keyPair.nsec);       // bech32 nsec private key
 * console.log(keyPair.npub);       // bech32 npub public key
 */
export function seedPhraseToKeyPair(seedPhrase: string): KeyPair {
  try {
    if (!validateSeedPhrase(seedPhrase)) {
      throw new Error("Invalid seed phrase");
    }

    const privateKey = seedPhraseToPrivateKey(seedPhrase);
    const pubkeyHex = getPublicKey(privateKey);
    const pubkeyBytes = hexToBytes(pubkeyHex);
    const publicKey = {
      hex: pubkeyHex,
      compressed: pubkeyBytes,
      schnorr: pubkeyBytes.slice(1),
      npub: hexToNpub(pubkeyHex),
    };
    const nsec = hexToNsec(privateKey);

    return {
      privateKey,
      publicKey,
      nsec,
      seedPhrase,
    };
  } catch (error) {
    logger.error("Failed to convert seed phrase to key pair:", error);
    throw new Error("Failed to convert seed phrase to key pair");
  }
}

/**
 * Converts a BIP39 seed phrase to a private key
 * @param {string} seedPhrase - The BIP39 seed phrase to convert
 * @returns {string} The hex-encoded private key
 * @throws {Error} If the seed phrase is invalid
 * @example
 * const privateKey = seedPhraseToPrivateKey("witch collapse practice feed shame open despair creek road again ice least");
 * console.log(privateKey); // hex private key
 */
export function seedPhraseToPrivateKey(seedPhrase: string): string {
  try {
    if (!validateSeedPhrase(seedPhrase)) {
      throw new Error("Invalid seed phrase");
    }

    const entropy = getEntropyFromSeedPhrase(seedPhrase);
    const privateKey = bytesToHex(sha256(entropy));
    entropy.fill(0); // zero sensitive material
    return privateKey;
  } catch (error) {
    logger.error("Failed to convert seed phrase to private key:", error);
    throw new Error("Failed to convert seed phrase to private key");
  }
}
