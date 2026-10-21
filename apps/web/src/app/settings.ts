/** Per-device preferences (not secret, kept in localStorage). */
export interface DeviceSettings {
  /** idle auto-lock in seconds (the web app has no "never": build spec §2) */
  autoLockSeconds: number;
  /** lock after the tab has been hidden this long, in seconds */
  hiddenGraceSeconds: number;
  hideCodes: boolean;
}

export const AUTO_LOCK_CHOICES = [30, 60, 300, 900] as const;

const DEFAULTS: DeviceSettings = { autoLockSeconds: 300, hiddenGraceSeconds: 30, hideCodes: false };
const KEY = "veilauth.settings";

export function loadSettings(): DeviceSettings {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw === null) return { ...DEFAULTS };
    const parsed = JSON.parse(raw) as Partial<DeviceSettings>;
    return {
      autoLockSeconds: (AUTO_LOCK_CHOICES as readonly number[]).includes(
        parsed.autoLockSeconds ?? -1,
      )
        ? (parsed.autoLockSeconds ?? DEFAULTS.autoLockSeconds)
        : DEFAULTS.autoLockSeconds,
      hiddenGraceSeconds: DEFAULTS.hiddenGraceSeconds,
      hideCodes: parsed.hideCodes === true,
    };
  } catch (e: unknown) {
    // Storage blocked or corrupt: fall back to the safe defaults.
    if (e instanceof SyntaxError || e instanceof DOMException) return { ...DEFAULTS };
    throw e;
  }
}

export function saveSettings(s: DeviceSettings): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch (e: unknown) {
    if (!(e instanceof DOMException)) throw e;
  }
}
