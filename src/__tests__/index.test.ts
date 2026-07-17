// These tests run against REAL crypto (no mocks). Public keys are 32-byte
// x-only per BIP-340. Known-answer vectors are loaded from the shared,
// language-neutral vector file at test/vectors/nostr-vectors.json.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect, beforeAll } from "vitest";
import {
  generateKeyPairWithSeed,
  seedPhraseToKeyPair,
  seedPhraseToPrivateKey,
  validateSeedPhrase,
  getPublicKey,
  getCompressedPublicKey,
  privateKeyToNpub,
  nsecToHex,
  npubToHex,
  hexToNsec,
  hexToNpub,
  signMessage,
  verifySignature,
  createEvent,
  verifyEvent,
  configureHMAC,
  fromHex,
  nip19,
} from "../index.js";

const vectors = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../test/vectors/nostr-vectors.json", import.meta.url),
    ),
    "utf-8",
  ),
);

const alice = vectors.keypairs.alice;
const bob = vectors.keypairs.bob;
const libSeed = vectors.library_seedphrase;

/**
 * Tests for the nostr-nsec-seedphrase library (real crypto, no mocks).
 *
 * @version 0.8.0
 */
describe("nostr-nsec-seedphrase", () => {
  beforeAll(() => {
    configureHMAC();
  });

  describe("Seed phrase validation", () => {
    it("validates a real BIP39 mnemonic", () => {
      expect(validateSeedPhrase(libSeed.mnemonic)).toBe(true);
      expect(validateSeedPhrase("invalid seed phrase")).toBe(false);
    });
  });

  describe("Known-answer: x-only public keys (BIP-340)", () => {
    it("getPublicKey returns the 32-byte x-only key for alice (priv=..01)", () => {
      const pub = getPublicKey(alice.privateKey);
      expect(pub).toBe(alice.xonlyPubkey);
      expect(pub).toMatch(/^[0-9a-f]{64}$/); // 32 bytes, NOT 66/33-byte compressed
    });

    it("getPublicKey returns the x-only key for bob (priv=..02)", () => {
      expect(getPublicKey(bob.privateKey)).toBe(bob.xonlyPubkey);
    });

    it("getCompressedPublicKey still exposes the 33-byte compressed key", () => {
      const c = getCompressedPublicKey(alice.privateKey);
      expect(c).toBe(alice.compressedPubkey);
      expect(c).toMatch(/^[0-9a-f]{66}$/);
    });

    it("fromHex derives the x-only pubkey and matching npub", () => {
      const kp = fromHex(alice.privateKey);
      expect(kp.privateKey).toBe(alice.privateKey);
      expect(kp.publicKey).toBe(alice.xonlyPubkey);
      expect(kp.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(kp.npub).toBe(alice.npub);
    });

    it("privateKeyToNpub yields the x-only npub", () => {
      expect(privateKeyToNpub(alice.privateKey)).toBe(alice.npub);
    });

    it("seedPhraseToKeyPair derives an x-only pubkey (library sha256-entropy KAT)", () => {
      const kp = seedPhraseToKeyPair(libSeed.mnemonic);
      expect(kp.privateKey).toBe(libSeed.privateKey);
      expect(kp.publicKey).toBe(libSeed.xonlyPubkey);
      expect(kp.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(kp.npub).toBe(libSeed.npub);
      expect(seedPhraseToPrivateKey(libSeed.mnemonic)).toBe(libSeed.privateKey);
    });
  });

  describe("NIP-19 encoding (real bech32)", () => {
    it("round-trips npub <-> hex for alice", () => {
      expect(hexToNpub(alice.xonlyPubkey)).toBe(alice.npub);
      expect(npubToHex(alice.npub)).toBe(alice.xonlyPubkey);
    });

    it("round-trips nsec <-> hex for alice", () => {
      const nsec = hexToNsec(alice.privateKey);
      expect(nsec).toBe(alice.nsec);
      expect(nsecToHex(nsec)).toBe(alice.privateKey);
    });

    it("rejects a 33-byte compressed key when encoding an npub", () => {
      expect(() => nip19.npubEncode(alice.compressedPubkey)).toThrow();
      expect(() => hexToNpub(alice.compressedPubkey)).toThrow();
    });
  });

  describe("Message signing (real schnorr)", () => {
    it("signs and verifies a message with the x-only pubkey", async () => {
      const message = "Hello, Nostr!";
      const sig = await signMessage(message, alice.privateKey);
      expect(sig).toMatch(/^[0-9a-f]{128}$/);
      expect(await verifySignature(message, sig, alice.xonlyPubkey)).toBe(true);
    });

    it("fails verification for the wrong message", async () => {
      const sig = await signMessage("Hello, Nostr!", alice.privateKey);
      expect(await verifySignature("Wrong message", sig, alice.xonlyPubkey)).toBe(
        false,
      );
    });
  });

  describe("Event handling (createEvent -> verifyEvent round-trip)", () => {
    it("creates and verifies an event with real schnorr", async () => {
      const event = await createEvent("Hello, Nostr!", 1, alice.privateKey, [
        ["t", "test"],
      ]);
      expect(event.pubkey).toBe(alice.xonlyPubkey);
      expect(event.pubkey).toMatch(/^[0-9a-f]{64}$/);
      expect(event.kind).toBe(1);
      expect(event.content).toBe("Hello, Nostr!");
      expect(event.tags).toEqual([["t", "test"]]);
      expect(event.id).toMatch(/^[0-9a-f]{64}$/);
      expect(event.sig).toMatch(/^[0-9a-f]{128}$/);

      // This is the core regression: with a 33-byte compressed key,
      // schnorr.verify THROWS. With x-only it round-trips to true.
      expect(await verifyEvent(event)).toBe(true);
    });

    it("computes the known-answer event id from the shared vector", async () => {
      const ex = vectors.nip01_events.example;
      // Recreate the exact serialized event and confirm the deterministic id.
      const { createHash } = await import("node:crypto");
      const serialized = JSON.stringify([
        0,
        ex.pubkey,
        ex.created_at,
        ex.kind,
        ex.tags,
        ex.content,
      ]);
      const id = createHash("sha256").update(serialized).digest("hex");
      expect(id).toBe(ex.id);
    });

    it("detects tampered events", async () => {
      const event = await createEvent("Hello, Nostr!", 1, alice.privateKey);
      event.content = "Tampered content";
      expect(await verifyEvent(event)).toBe(false);
    });
  });

  describe("HMAC configuration", () => {
    it("configures HMAC without errors", () => {
      expect(() => configureHMAC()).not.toThrow();
    });
  });

  describe("Random key generation", () => {
    it("produces x-only keys that sign and verify", async () => {
      const keyPair = generateKeyPairWithSeed();

      expect(keyPair.privateKey).toMatch(/^[0-9a-f]{64}$/);
      expect(keyPair.publicKey).toMatch(/^[0-9a-f]{64}$/); // x-only, not 66
      expect(keyPair.nsec).toMatch(/^nsec1/);
      expect(keyPair.npub).toMatch(/^npub1/);

      const message = "Test message";
      const signature = await signMessage(message, keyPair.privateKey);
      expect(await verifySignature(message, signature, keyPair.publicKey)).toBe(
        true,
      );
    });
  });
});
