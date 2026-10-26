/**
 * Test-only entry point (`@zk2fa/crypto/testing`). Fixed nonces are used exclusively to reproduce
 * spec/test-vectors.json. Application code MUST NOT import this module; ESLint forbids it.
 */
export { sealWithNonce } from "./envelope.js";
export { encryptItemWithNonce } from "./item.js";
export { createBackupWith } from "./backup.js";
