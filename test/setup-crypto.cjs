const { webcrypto } = require('node:crypto');
const { TextDecoder, TextEncoder } = require('util');

if (typeof globalThis.crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: false,
    enumerable: false,
    configurable: true,
  });
} else if (!globalThis.crypto && webcrypto) {
  globalThis.crypto = webcrypto;
}

if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = TextEncoder;
}

if (typeof globalThis.TextDecoder === 'undefined') {
  globalThis.TextDecoder = TextDecoder;
}
