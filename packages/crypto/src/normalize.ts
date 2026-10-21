import { type Bytes, utf8 } from "./encoding.js";

/** spec/crypto.md §2 */
export function normalizePassword(password: string): Bytes {
  return utf8(password.normalize("NFKC"));
}

/** spec/crypto.md §2 */
export function normalizeEmail(email: string): string {
  return email.trim().normalize("NFKC").toLowerCase();
}
