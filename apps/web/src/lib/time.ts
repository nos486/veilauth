/**
 * Server-corrected clock. TOTP codes use the server's time (GET /time), so a device whose clock is
 * off still shows the right code. The offset is the midpoint estimate of one round trip.
 */
let offsetMs = 0;

export function serverNow(): number {
  return Date.now() + offsetMs;
}

export function clockOffset(): number {
  return offsetMs;
}

export function setClockOffset(sentAt: number, serverTime: number, receivedAt: number): void {
  const rtt = receivedAt - sentAt;
  // Ignore samples from very slow round trips; they say little about the true offset.
  if (rtt < 0 || rtt > 10_000) return;
  offsetMs = Math.round(serverTime - (sentAt + receivedAt) / 2);
}

export function resetClockOffset(): void {
  offsetMs = 0;
}
