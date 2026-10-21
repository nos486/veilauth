import { lazy, Suspense, useEffect, useRef } from "react";
import { useController } from "./app/context";
import { type DeviceSettings, loadSettings } from "./app/settings";
import { Spinner } from "./components/ui";
import { t } from "./i18n";
import { About } from "./screens/About";
import { EditToken } from "./screens/EditToken";
import { LogIn } from "./screens/LogIn";
import { Settings } from "./screens/Settings";
import { Trash } from "./screens/Trash";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { Welcome } from "./screens/Welcome";
import { useApp } from "./store/app";

// Heavier screens (QR decoding, QR rendering) load on demand.
const AddToken = lazy(() => import("./screens/AddToken").then((m) => ({ default: m.AddToken })));
const SignUp = lazy(() => import("./screens/SignUp").then((m) => ({ default: m.SignUp })));

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

/**
 * Auto-lock (build spec §6): after idle time, after the tab has been hidden for a grace period,
 * and on Ctrl/Cmd+L.
 */
function useAutoLock(unlocked: boolean, settings: React.RefObject<DeviceSettings>) {
  const controller = useController();
  useEffect(() => {
    if (!unlocked) return;
    let lastActivity = Date.now();
    let hiddenAt: number | null = null;
    const lock = () => {
      void controller.lock("locked");
    };
    const onActivity = () => {
      lastActivity = Date.now();
    };
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        lock();
      }
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") hiddenAt = Date.now();
      else {
        const s = settings.current;
        if (hiddenAt !== null && s && Date.now() - hiddenAt > s.hiddenGraceSeconds * 1000) lock();
        hiddenAt = null;
        lastActivity = Date.now();
      }
    };
    const timer = setInterval(() => {
      const s = settings.current;
      if (!s) return;
      const now = Date.now();
      if (now - lastActivity > s.autoLockSeconds * 1000) lock();
      else if (hiddenAt !== null && now - hiddenAt > s.hiddenGraceSeconds * 1000) lock();
    }, 1000);
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, onActivity, { passive: true });
    window.addEventListener("keydown", onKey);
    document.addEventListener("visibilitychange", onVisibility);
    const onFocus = () => {
      void controller.syncNow();
    };
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(timer);
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, onActivity);
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
    };
  }, [unlocked, controller, settings]);
}

function Loading() {
  return (
    <main className="flex min-h-dvh items-center justify-center" aria-busy="true">
      <Spinner />
      <span className="sr-only">{t("common.loading")}</span>
    </main>
  );
}

export function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Screens />
    </Suspense>
  );
}

function Screens() {
  const phase = useApp((s) => s.phase);
  const screen = useApp((s) => s.screen);
  const settings = useRef<DeviceSettings>(loadSettings());
  useAutoLock(phase === "unlocked", settings);

  switch (phase) {
    case "loading":
      return <Loading />;
    case "welcome":
      return <Welcome />;
    case "signup":
      return <SignUp />;
    case "login":
      return <LogIn />;
    case "locked":
      return <Unlock />;
    case "unlocked":
      switch (screen.name) {
        case "vault":
          return <Vault />;
        case "add":
          return <AddToken />;
        case "edit":
          return <EditToken key={screen.id} id={screen.id} />;
        case "trash":
          return <Trash />;
        case "settings":
          return (
            <Settings
              onSettingsChanged={(s) => {
                settings.current = s;
              }}
            />
          );
        case "about":
          return <About />;
      }
  }
}
