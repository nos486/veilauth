import type { CryptoOp, CryptoOps, CryptoRequestMessage, CryptoResponseMessage } from "./protocol";

export class CryptoWorkerError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "CryptoWorkerError";
    this.code = code;
  }
}

export interface CryptoClient {
  call<K extends CryptoOp>(op: K, req: CryptoOps[K]["req"]): Promise<CryptoOps[K]["res"]>;
}

/** Typed RPC to the crypto Web Worker. Argon2id runs there, so the UI never freezes. */
export class WorkerCryptoClient implements CryptoClient {
  private readonly worker: Worker;
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();

  constructor() {
    this.worker = new Worker(new URL("./crypto.worker.ts", import.meta.url), {
      type: "module",
      name: "veilauth-crypto",
    });
    this.worker.onmessage = (event: MessageEvent<CryptoResponseMessage>) => {
      const msg = event.data;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.ok) p.resolve(msg.res);
      else p.reject(new CryptoWorkerError(msg.code));
    };
    this.worker.onerror = () => {
      for (const p of this.pending.values()) p.reject(new CryptoWorkerError("WORKER_FAILED"));
      this.pending.clear();
    };
  }

  call<K extends CryptoOp>(op: K, req: CryptoOps[K]["req"]): Promise<CryptoOps[K]["res"]> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.worker.postMessage({ id, op, req } satisfies CryptoRequestMessage<K>);
    });
  }
}
