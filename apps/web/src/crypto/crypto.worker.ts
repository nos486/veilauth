/// <reference lib="webworker" />
import { CryptoError } from "@zk2fa/crypto";
import { CryptoHandler } from "./handler";
import type { CryptoRequestMessage, CryptoResponseMessage } from "./protocol";

const handler = new CryptoHandler();
const scope = self as unknown as DedicatedWorkerGlobalScope;

scope.onmessage = (event: MessageEvent<CryptoRequestMessage>) => {
  const { id, op, req } = event.data;
  handler.handle(op, req).then(
    (res) => {
      scope.postMessage({ id, ok: true, res } satisfies CryptoResponseMessage);
    },
    (e: unknown) => {
      // Only the stable error code crosses the boundary: no message text, no key material.
      const code = e instanceof CryptoError ? e.code : "INTERNAL";
      scope.postMessage({ id, ok: false, code } satisfies CryptoResponseMessage);
    },
  );
};
