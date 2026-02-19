/**
 * Key Generation Example — nostr-nsec-seedphrase
 *
 * Demonstrates generating a new Nostr key pair with a BIP-39 seed phrase.
 */
import {
  generateKeyPairWithSeed,
  seedPhraseToKeyPair,
  validateSeedPhrase,
} from 'nostr-nsec-seedphrase';

async function main() {
  // Generate a new key pair with a seed phrase
  const keyPair = generateKeyPairWithSeed();
  console.log('Seed phrase:', keyPair.seedPhrase);
  console.log('nsec:', keyPair.nsec);
  console.log('npub:', keyPair.npub);

  // Validate the seed phrase
  const isValid = validateSeedPhrase(keyPair.seedPhrase);
  console.log('Seed phrase valid:', isValid);

  // Recover a key pair from an existing seed phrase
  const recovered = await seedPhraseToKeyPair(keyPair.seedPhrase);
  console.log('Recovered private key (hex):', recovered.privateKey);
  console.log('Recovered public key (hex):', recovered.publicKey);
  console.log('Recovered nsec:', recovered.nsec);
  console.log('Recovered npub:', recovered.npub);
}

main().catch(console.error);
