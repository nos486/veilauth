import "./security/zod-jitless";
import { installTrustedTypesPolicy } from "./security/trusted-types";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ControllerContext } from "./app/context";
import { VaultController } from "./app/controller";
import { WorkerCryptoClient } from "./crypto/client";
import { setupUpdates } from "./pwa/update";
import { LocalStore } from "./store/db";
import "./index.css";

installTrustedTypesPolicy();

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000, gcTime: 60_000 } },
});

async function start(): Promise<void> {
  const store = await LocalStore.open();
  const controller = new VaultController(new WorkerCryptoClient(), store);
  const rootEl = document.getElementById("root");
  if (!rootEl) throw new Error("#root missing");
  createRoot(rootEl).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ControllerContext.Provider value={controller}>
          <App />
        </ControllerContext.Provider>
      </QueryClientProvider>
    </StrictMode>,
  );
  await controller.boot();
  setupUpdates(controller);
}

void start();
