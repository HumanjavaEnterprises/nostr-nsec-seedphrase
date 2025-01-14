"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
// Re-export everything from index
__exportStar(require("./index"), exports);
// Add browser-specific implementations or overrides here
const buffer_1 = require("buffer");
if (typeof window !== 'undefined') {
    window.Buffer = buffer_1.Buffer;
}
// Add any browser-specific initialization code here
const isBrowser = typeof window !== 'undefined';
if (isBrowser) {
    // Initialize any browser-specific features
    console.log('NostrNsecSeedphrase loaded in browser environment');
}
