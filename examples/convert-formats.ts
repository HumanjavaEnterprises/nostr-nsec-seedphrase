/**
 * Format Conversion Example — nostr-nsec-seedphrase
 *
 * Demonstrates converting between hex and bech32 (nsec/npub) key formats.
 */
import {
  generateKeyPairWithSeed,
  hexToNsec,
  hexToNpub,
  nsecToHex,
  npubToHex,
} from 'nostr-nsec-seedphrase';

async function main() {
  // Generate a key pair to get hex keys
  const keyPair = generateKeyPairWithSeed();

  // Convert hex private key to nsec
  const nsec = hexToNsec(keyPair.privateKey);
  console.log('nsec from hex:', nsec);

  // Convert hex public key to npub
  const npub = hexToNpub(keyPair.publicKey);
  console.log('npub from hex:', npub);

  // Convert back: nsec to hex
  const privateKeyHex = nsecToHex(nsec);
  console.log('Hex from nsec:', privateKeyHex);
  console.log('Round-trip match:', privateKeyHex === keyPair.privateKey);

  // Convert back: npub to hex
  const publicKeyHex = npubToHex(npub);
  console.log('Hex from npub:', publicKeyHex);
  console.log('Round-trip match:', publicKeyHex === keyPair.publicKey);
}

main().catch(console.error);
