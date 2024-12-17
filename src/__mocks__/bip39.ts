// Mock implementation of bip39 for testing
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

const VALID_SEED_PHRASE = "witch collapse practice feed shame open despair creek road again ice least";
const VALID_ENTROPY = "000102030405060708090a0b0c0d0e0f";

export function generateMnemonic(): string {
  return VALID_SEED_PHRASE;
}

export function validateMnemonic(mnemonic: string): boolean {
  console.log("Mock validateMnemonic called with:", mnemonic);
  
  // Accept the specific test mnemonic or any 12-word phrase
  if (mnemonic === VALID_SEED_PHRASE) {
    console.log("Valid test phrase detected");
    return true;
  }
  
  const words = mnemonic.split(" ");
  const isValid = words.length === 12 && words.every(word => word.length > 0);
  console.log(`Validation result for "${mnemonic}": ${isValid}`);
  return isValid;
}

export function mnemonicToEntropy(mnemonic: string): string {
  console.log("Mock mnemonicToEntropy called with:", mnemonic);
  
  if (!validateMnemonic(mnemonic)) {
    throw new Error("Invalid mnemonic");
  }
  
  // For testing, return a fixed valid entropy for our test seed phrase
  if (mnemonic === VALID_SEED_PHRASE) {
    console.log("Returning test entropy");
    return VALID_ENTROPY;
  }
  
  // For other valid phrases, generate a deterministic entropy
  console.log("Generating deterministic entropy");
  const words = mnemonic.split(" ");
  const entropy = new Uint8Array(16); // 16 bytes = 128 bits
  for (let i = 0; i < 16; i++) {
    entropy[i] = (i + 1) % 256; // Simple deterministic pattern
  }
  return bytesToHex(entropy);
}
