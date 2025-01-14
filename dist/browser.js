// Re-export everything from index
export * from './index';
// Add browser-specific implementations or overrides here
import { Buffer } from 'buffer';
if (typeof window !== 'undefined') {
    window.Buffer = Buffer;
}
// Add any browser-specific initialization code here
const isBrowser = typeof window !== 'undefined';
if (isBrowser) {
    // Initialize any browser-specific features
    console.log('NostrNsecSeedphrase loaded in browser environment');
}
