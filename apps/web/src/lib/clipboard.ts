const CLEAR_AFTER_MS = 30_000;
let clearTimer: ReturnType<typeof setTimeout> | undefined;
let lastCopied: string | null = null;

/** Copies a code and clears the clipboard after 30 s when the browser lets us (build spec §6). */
export async function copySensitive(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  lastCopied = text;
  clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    void clearClipboard();
  }, CLEAR_AFTER_MS);
}

export async function clearClipboard(): Promise<void> {
  clearTimeout(clearTimer);
  if (lastCopied === null) return;
  lastCopied = null;
  try {
    await navigator.clipboard.writeText("");
  } catch (e: unknown) {
    // Writing needs focus; when the tab is in the background the code simply stays until replaced.
    if (!(e instanceof DOMException)) throw e;
  }
}
