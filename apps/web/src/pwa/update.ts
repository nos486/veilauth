import { registerSW } from "virtual:pwa-register";
import type { VaultController } from "../app/controller";

const CHECK_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Website-style updates (docs/DECISIONS.md D-018): the service worker fetches new builds in the
 * background; a new build activates at once while locked, and on the next lock while unlocked.
 */
export function setupUpdates(controller: VaultController): void {
  if (!("serviceWorker" in navigator)) return;
  const updateSW = registerSW({
    immediate: true,
    onNeedRefresh() {
      controller.setPendingUpdate(() => {
        void updateSW(true);
      });
    },
    onRegisteredSW(_url, registration) {
      if (!registration) return;
      const check = () => {
        if (registration.installing || !navigator.onLine) return;
        void registration.update();
      };
      setInterval(check, CHECK_INTERVAL_MS);
      window.addEventListener("focus", check);
    },
  });
}
