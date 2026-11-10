// Regression tests for the 2026-11-10 review findings (N2, N5, N6).
// All mnemonics below are PUBLIC test vectors (the official NIP-06 spec
// mnemonics). The account-1 and passphrase expectations were computed
// independently with a pure-stdlib Python BIP-39/BIP-32/BIP-340
// implementation and cross-checked with @scure/bip32 + @scure/bip39 directly.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  NIP06_DERIVATION_PATH,
  getNip06DerivationPath,
  hexToNpub,
  hexToNsec,
  nip19,
  npubToHex,
  nsecToHex,
  seedPhraseToKeyPair,
  seedPhraseToPrivateKey,
  validateSeedPhrase,
  generateKeyPairWithSeed,
  toNcryptsec,
} from "../src/index.js";
import { bech32 } from "bech32";
import { hexToBytes } from "@noble/hashes/utils.js";

const M1 =
  "leader monkey parrot ring guide accident before fence cannon height naive bean";
const M2 =
  "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";

// Curve order n of secp256k1.
const CURVE_N =
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

describe("N2: NIP-06 account index and BIP-39 passphrase", () => {
  it("default call is unchanged (official vector 1, account 0, no passphrase)", () => {
    const kp = seedPhraseToKeyPair(M1);
    expect(kp.privateKey).toBe(
      "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
    );
    expect(kp.publicKey).toBe(
      "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
    );
    // explicit defaults give the same result
    expect(seedPhraseToKeyPair(M1, { account: 0, passphrase: "" })).toEqual(kp);
    expect(seedPhraseToKeyPair(M1, {})).toEqual(kp);
  });

  it("default call is unchanged (official vector 2, 24 words)", () => {
    expect(seedPhraseToPrivateKey(M2)).toBe(
      "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
    );
  });

  it("builds the NIP-06 path for an account", () => {
    expect(getNip06DerivationPath()).toBe(NIP06_DERIVATION_PATH);
    expect(getNip06DerivationPath(0)).toBe("m/44'/1237'/0'/0/0");
    expect(getNip06DerivationPath(7)).toBe("m/44'/1237'/7'/0/0");
  });

  it("derives account 1 (independent vector)", () => {
    const kp = seedPhraseToKeyPair(M1, { account: 1 });
    expect(kp.privateKey).toBe(
      "3790c23940f62b23754115ef70f16e63cca8e9015a532b8a891171ccdadcf910",
    );
    expect(kp.publicKey).toBe(
      "d977a6cf0f831dc4720780b5f51460eaf6dca08e32d1f6e89b60344d63af4e04",
    );
    expect(kp.npub).toBe(hexToNpub(kp.publicKey));
  });

  it("derives with a BIP-39 passphrase (independent vector)", () => {
    expect(seedPhraseToPrivateKey(M1, { passphrase: "TREZOR" })).toBe(
      "3e8ef6dcb3fd0d9fe65ae48accd01a3058677b033de5310c4d8b6c28377aada8",
    );
  });

  it("derives with account + unicode passphrase (NFKD, independent vector)", () => {
    const kp = seedPhraseToKeyPair(M2, {
      account: 5,
      passphrase: "nostr passphrase ünïcode",
    });
    expect(kp.privateKey).toBe(
      "502ce36ffe67eaacb4c6cd8a54dd5578435560b7a7b09c5578ad12af5a2ea2d2",
    );
    expect(kp.publicKey).toBe(
      "f81a3ca1e46083088b3aacc1fbaf83d53ed97539abd50197e5bbbb07a04a8b7e",
    );
  });

  it("accepts the largest hardened account index", () => {
    expect(seedPhraseToPrivateKey(M1, { account: 2147483647 })).toBe(
      "3349ef5d5c4ccffb35d4b0074ddac8df33a24d9d883c1aa7b4b8e0c437cf1683",
    );
  });

  it("rejects invalid account indexes", () => {
    for (const account of [-1, 1.5, 2147483648, Number.NaN]) {
      expect(() => seedPhraseToKeyPair(M1, { account })).toThrow(/account/);
      expect(() => getNip06DerivationPath(account)).toThrow(/account/);
    }
  });
});

describe("N5: no console output from library calls", () => {
  afterEach(() => vi.restoreAllMocks());

  it("validateSeedPhrase, conversions and failures stay silent", () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map(
      (m) => vi.spyOn(console, m).mockImplementation(() => {}),
    );
    validateSeedPhrase(M1);
    validateSeedPhrase("not a seed phrase");
    const kp = generateKeyPairWithSeed();
    nsecToHex(kp.nsec);
    npubToHex(kp.npub);
    hexToNsec(kp.privateKey);
    hexToNpub(kp.publicKey);
    expect(() => seedPhraseToKeyPair("bad words")).toThrow();
    expect(() => nsecToHex("nsec1invalid")).toThrow();
    for (const s of spies) expect(s).not.toHaveBeenCalled();
  });
});

describe("N6: NIP-19 helpers reject wrong-length / out-of-range input", () => {
  // bech32 of 3 raw bytes (010203) under each prefix, built with the
  // package's own codec bypass below to avoid needing a second library.
  const short = (prefix: string) => {
    // bech32 for [0x01,0x02,0x03]; checksum computed per BIP-173.
    const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const polymod = (values: number[]) => {
      const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
      let chk = 1;
      for (const v of values) {
        const b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
      }
      return chk;
    };
    const hrpExpand = (h: string) => [
      ...[...h].map((c) => c.charCodeAt(0) >> 5),
      0,
      ...[...h].map((c) => c.charCodeAt(0) & 31),
    ];
    // 0x010203 -> 5-bit words
    const words = [0, 4, 0, 16, 6];
    const pm = polymod([...hrpExpand(prefix), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
    const checksum = [0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31);
    return (
      prefix + "1" + [...words, ...checksum].map((w) => CHARSET[w]).join("")
    );
  };

  it("hexToNsec('00ff') throws", () => {
    expect(() => hexToNsec("00ff")).toThrow();
  });

  it("nsec encode rejects zero and the curve order", () => {
    expect(() => hexToNsec("00".repeat(32))).toThrow();
    expect(() => hexToNsec(CURVE_N)).toThrow();
    expect(() => nip19.nsecEncode(CURVE_N)).toThrow();
  });

  it("npub / note encode reject non-32-byte input", () => {
    expect(() => hexToNpub("00ff")).toThrow();
    expect(() => nip19.noteEncode("00ff")).toThrow();
    expect(() => nip19.noteEncode("ab".repeat(33))).toThrow();
  });

  it("decoders reject 3-byte payloads", () => {
    expect(() => npubToHex(short("npub"))).toThrow();
    expect(() => nip19.npubDecode(short("npub"))).toThrow();
    expect(() => nsecToHex(short("nsec"))).toThrow();
    expect(() => nip19.nsecDecode(short("nsec"))).toThrow();
    expect(() => nip19.noteDecode(short("note"))).toThrow();
  });

  it("valid 32-byte values still round-trip", () => {
    const id = "ab".repeat(32);
    expect(nip19.noteDecode(nip19.noteEncode(id))).toBe(id);
    const sk = "00".repeat(31) + "01";
    expect(nsecToHex(hexToNsec(sk))).toBe(sk);
  });
});

describe("checker nits: options validation, toNcryptsec, nsecDecode range", () => {
  it("null/undefined options mean defaults", () => {
    const base = seedPhraseToPrivateKey(M1);
    expect(seedPhraseToPrivateKey(M1, null)).toBe(base);
    expect(seedPhraseToPrivateKey(M1, undefined)).toBe(base);
  });

  it("non-object options throw a clear TypeError", () => {
    for (const bad of ["TREZOR", 1, true, [1]]) {
      expect(() => seedPhraseToKeyPair(M1, bad as any)).toThrow(TypeError);
      expect(() => seedPhraseToKeyPair(M1, bad as any)).toThrow(/options/);
    }
  });

  it("toNcryptsec rejects short, zero and out-of-range keys", () => {
    expect(() => toNcryptsec("00ff", "pw", 1)).toThrow(/Invalid private key/);
    expect(() => toNcryptsec("00".repeat(32), "pw", 1)).toThrow(
      /Invalid private key/,
    );
    expect(() => toNcryptsec(CURVE_N, "pw", 1)).toThrow(/Invalid private key/);
  });

  it("nsecDecode rejects an out-of-range (d >= n) key", () => {
    // bech32 nsec of the curve order, built without the range-checking encoder
    const words = bech32.toWords(hexToBytes(CURVE_N));
    const nsecN = bech32.encode("nsec", words, 1000);
    expect(() => nip19.nsecDecode(nsecN)).toThrow(/Invalid private key/);
    expect(() => nsecToHex(nsecN)).toThrow(/Invalid private key/);
    const zero = bech32.encode(
      "nsec",
      bech32.toWords(new Uint8Array(32)),
      1000,
    );
    expect(() => nip19.nsecDecode(zero)).toThrow(/Invalid private key/);
  });
});
