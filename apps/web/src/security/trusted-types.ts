/**
 * Trusted Types default policy (docs/DECISIONS.md D-040). The CSP requires Trusted Types for every
 * script sink and allows only this policy. It accepts same-origin script URLs (the crypto worker,
 * the service worker, lazy chunks) and refuses HTML and script strings, so no code path can turn
 * text into markup or code.
 */
interface TrustedTypePolicyOptions {
  createHTML?: (input: string) => string;
  createScript?: (input: string) => string;
  createScriptURL?: (input: string) => string;
}

interface TrustedTypesFactory {
  createPolicy(name: string, options: TrustedTypePolicyOptions): unknown;
}

export function sameOriginScriptUrl(input: string, origin: string): string {
  const url = new URL(input, origin);
  if (url.origin !== origin) throw new TypeError("Blocked cross-origin script URL");
  return url.href;
}

export function installTrustedTypesPolicy(): void {
  const tt = (globalThis as { trustedTypes?: TrustedTypesFactory }).trustedTypes;
  if (!tt) return;
  tt.createPolicy("default", {
    createScriptURL: (input) => sameOriginScriptUrl(input, location.origin),
    createHTML: () => {
      throw new TypeError("HTML strings are not allowed");
    },
    createScript: () => {
      throw new TypeError("Script strings are not allowed");
    },
  });
}
