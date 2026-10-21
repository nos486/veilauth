import type { CryptoClient } from "../src/crypto/client";
import { CryptoWorkerError } from "../src/crypto/client";
import { CryptoHandler } from "../src/crypto/handler";
import type { CryptoOp, CryptoOps } from "../src/crypto/protocol";
import { CryptoError } from "@zk2fa/crypto";

/** Runs the worker's handler in-process, with the same error mapping as the real worker. */
export class DirectCryptoClient implements CryptoClient {
  readonly handler = new CryptoHandler();
  async call<K extends CryptoOp>(op: K, req: CryptoOps[K]["req"]): Promise<CryptoOps[K]["res"]> {
    try {
      return structuredClone(await this.handler.handle(op, structuredClone(req)));
    } catch (e: unknown) {
      throw new CryptoWorkerError(e instanceof CryptoError ? e.code : "INTERNAL");
    }
  }
}

export const STRONG_PASSWORD = "Velvet orbit lantern quarry 42!";
