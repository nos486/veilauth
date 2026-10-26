import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { type Browser, type BrowserContext, expect, type Page, test } from "@playwright/test";
import { generateCode, parseOtpAuthUri } from "@zk2fa/otp";
import QRCode from "qrcode";

/**
 * Build spec §8.1 web E2E: sign up → add by QR image → second browser sees the code → change
 * password → the old session dies → encrypted backup and restore. Then the zero-knowledge audit:
 * a dump of D1 contains none of the token data or passwords.
 */

const run = Date.now().toString(36);
const EMAIL = `e2e-${run}@example.test`;
const PASSWORD = `Velvet orbit ${run} lantern quarry!`;
const NEW_PASSWORD = `Granite meadow ${run} cobalt whisper?`;
const BACKUP_PASSWORD = `Saffron ${run} tundra beacon parcel`;
const ISSUER = `Zyqfor ${run}`;
const ACCOUNT = `kestrel-${run}@example.test`;
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // gitleaks:allow (RFC 6238 test secret)
const URI = `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(ACCOUNT)}?secret=${SECRET}&issuer=${encodeURIComponent(ISSUER)}`;

const d1State = fileURLToPath(new URL("../../worker/.wrangler/e2e-state/v3/d1/", import.meta.url));

/** Every byte of the local D1 database files (main file and WAL), as one searchable string. */
function rawD1Bytes(dir: string): string {
  return readdirSync(dir)
    .map((name) => join(dir, name))
    .map((p) => (statSync(p).isDirectory() ? rawD1Bytes(p) : readFileSync(p).toString("latin1")))
    .join("\n");
}

/** WCAG 2.1 AA checks (axe-core, the engine behind Lighthouse's accessibility audit). */
async function expectAccessible(page: Page, where: string) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(violations.map((v) => `${where}: ${v.id} (${String(v.nodes.length)})`)).toEqual([]);
}

async function newPage(
  browser: Browser,
  colorScheme: "light" | "dark" = "light",
): Promise<{ context: BrowserContext; page: Page; violations: string[] }> {
  const context = await browser.newContext({ colorScheme });
  const page = await context.newPage();
  const violations: string[] = [];
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      const w = window as unknown as { __csp?: string[] };
      w.__csp ??= [];
      w.__csp.push(
        `${e.violatedDirective} ${e.blockedURI} ${e.sourceFile}:${String(e.lineNumber)}:${String(e.columnNumber)} ${e.sample}`,
      );
    });
  });
  page.on("console", (msg) => {
    const text = msg.text();
    if (/Content Security Policy|Trusted Type|integrity/i.test(text)) violations.push(text);
  });
  page.on("pageerror", (err) => {
    violations.push(`pageerror: ${err.message}`);
  });
  return { context, page, violations };
}

async function cspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? []);
}

async function expectedCodes(): Promise<string[]> {
  const params = parseOtpAuthUri(URI);
  const now = Date.now();
  const codes = await Promise.all([-30_000, 0, 30_000].map((d) => generateCode(params, now + d)));
  return codes.map((c) => `${c.slice(0, 3)} ${c.slice(3)}`);
}

async function logIn(page: Page, password: string) {
  await page.getByLabel("E-mail").fill(EMAIL);
  await page.getByLabel("Master password").fill(password);
  await page.getByRole("button", { name: "Log in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Codes" })).toBeVisible({ timeout: 60_000 });
}

test("sign up, add by QR, sync to a second browser, change password, zero-knowledge dump", async ({
  browser,
}) => {
  const a = await newPage(browser);
  const b = await newPage(browser, "dark");

  // ---- sign up with the recovery-key step
  await a.page.goto("/");
  await expectAccessible(a.page, "welcome");
  await a.page.getByRole("button", { name: "Create an account" }).click();
  await a.page.getByLabel("E-mail").fill(EMAIL);
  await a.page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await a.page.getByLabel("Repeat the password").fill(PASSWORD);
  await expect(a.page.getByText(/^(Strong|Very strong)\./)).toBeVisible();
  await a.page.getByLabel(/I understand that nobody can recover/).check();
  await expectAccessible(a.page, "sign up");
  await a.page.getByRole("button", { name: "Continue" }).click();

  const wordList = a.page.getByTestId("recovery-words");
  await expect(wordList).toBeVisible({ timeout: 60_000 });
  const words = (await wordList.locator("li span:last-child").allTextContents()).map((w) =>
    w.trim(),
  );
  expect(words).toHaveLength(24);
  await expectAccessible(a.page, "recovery words");
  await a.page.getByLabel(/I have saved my recovery key/).check();
  await a.page.getByRole("button", { name: "Continue" }).click();

  for (const label of await a.page.getByLabel(/^Word #\d+$/).all()) {
    const id = await label.getAttribute("id");
    const text = await a.page.locator(`label[for="${id ?? ""}"]`).textContent();
    const n = Number(/#(\d+)/.exec(text ?? "")?.[1]);
    await label.fill(words[n - 1] ?? "");
  }
  await a.page.getByRole("button", { name: "Create account" }).click();
  await expect(a.page.getByRole("heading", { name: "Codes" })).toBeVisible({ timeout: 30_000 });

  // ---- add a token from a QR code image
  await a.page.getByRole("button", { name: "Add", exact: true }).click();
  await expectAccessible(a.page, "add");
  const png = await QRCode.toBuffer(URI, { margin: 4, width: 400 });
  await a.page
    .getByTestId("qr-file")
    .setInputFiles({ name: "qr.png", mimeType: "image/png", buffer: png });
  await expect(a.page.getByRole("heading", { name: "Add these codes?" })).toBeVisible();
  await expect(a.page.getByText(ISSUER)).toBeVisible();
  await a.page.getByRole("button", { name: "Add 1" }).click();
  const rowA = a.page.getByRole("listitem").filter({ hasText: ISSUER });
  await expect(rowA).toBeVisible();
  await expect
    .poll(async () =>
      (await expectedCodes()).includes((await rowA.getByTestId("code").textContent()) ?? ""),
    )
    .toBe(true);
  await expectAccessible(a.page, "vault");
  // wait until the push has landed
  await expect(a.page.getByRole("button", { name: "Sync now" })).toHaveAttribute("title", "Synced");

  // ---- a second browser logs in and sees the same code
  await b.page.goto("/");
  await b.page.getByRole("button", { name: "Log in" }).click();
  await logIn(b.page, PASSWORD);
  const rowB = b.page.getByRole("listitem").filter({ hasText: ISSUER });
  await expect(rowB).toBeVisible();
  await expect
    .poll(async () =>
      (await expectedCodes()).includes((await rowB.getByTestId("code").textContent()) ?? ""),
    )
    .toBe(true);

  await expectAccessible(b.page, "vault (dark)");

  // ---- change the password in browser A
  await a.page.getByRole("button", { name: "Settings" }).click();
  await expect(a.page.getByText("Web browser (this browser)")).toBeVisible();
  await expectAccessible(a.page, "settings");
  await a.page.getByLabel("Current password").fill(PASSWORD);
  await a.page.getByLabel("New password").fill(NEW_PASSWORD);
  await a.page.getByLabel("Repeat the password").fill(NEW_PASSWORD);
  await a.page.getByRole("button", { name: "Change password" }).click();
  await expect(a.page.getByText("Password changed.")).toBeVisible({ timeout: 60_000 });

  // ---- browser B's session is dead: the next sync sends it to the log-in screen
  await b.page.getByRole("button", { name: "Sync now" }).click();
  await expect(b.page.getByText(/Your session ended/)).toBeVisible();
  await expect(b.page.getByRole("heading", { name: "Log in" })).toBeVisible();
  await expectAccessible(b.page, "log in (dark)");
  // the old password no longer works, the new one does, and the token is still there
  await b.page.getByLabel("Master password").fill(PASSWORD);
  await b.page.getByRole("button", { name: "Log in", exact: true }).click();
  await expect(b.page.getByText("E-mail or password is incorrect.")).toBeVisible({
    timeout: 60_000,
  });
  await logIn(b.page, NEW_PASSWORD);
  await expect(b.page.getByRole("listitem").filter({ hasText: ISSUER })).toBeVisible();

  // ---- encrypted backup: download, then restore it (the code is already there, so it is skipped)
  await b.page.getByRole("button", { name: "Settings" }).click();
  const dialog = b.page.getByRole("dialog");
  await b.page.getByRole("button", { name: "Download backup" }).click();
  await dialog.getByLabel("Backup password").fill(BACKUP_PASSWORD);
  await dialog.getByLabel("Repeat the password").fill(BACKUP_PASSWORD);
  await expectAccessible(b.page, "backup (dark)");
  const downloadEvent = b.page.waitForEvent("download", { timeout: 60_000 });
  await dialog.getByRole("button", { name: "Encrypt and download" }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/^veilauth-backup-\d{4}-\d{2}-\d{2}\.json$/);
  const backupPath = await download.path();
  const backup = readFileSync(backupPath, "utf8");
  expect(JSON.parse(backup)).toMatchObject({ format: "veilauth-backup", version: 1 });
  for (const needle of [ISSUER, ACCOUNT, SECRET]) expect(backup).not.toContain(needle);
  await dialog.getByRole("button", { name: "Done" }).click();

  await b.page.getByRole("button", { name: "Restore from backup" }).click();
  await dialog.getByTestId("backup-file").setInputFiles(backupPath);
  await dialog.getByLabel("Backup password").fill(`${BACKUP_PASSWORD}x`);
  await dialog.getByRole("button", { name: "Open backup" }).click();
  await expect(dialog.getByText("Wrong password.")).toBeVisible({ timeout: 60_000 });
  await dialog.getByLabel("Backup password").fill(BACKUP_PASSWORD);
  await dialog.getByRole("button", { name: "Open backup" }).click();
  await expect(dialog.getByText(/holds 1 code\(s\)/)).toBeVisible({ timeout: 60_000 });
  await dialog.getByRole("button", { name: "Add codes to my vault" }).click();
  await expect(dialog.getByText("Added 0 code(s). 1 were already in your vault.")).toBeVisible();
  await dialog.getByRole("button", { name: "Done" }).click();

  // ---- reload locks; unlock works with the new password from the offline cache
  await a.page.reload();
  await expect(a.page.getByRole("heading", { name: "Unlock your vault" })).toBeVisible();
  await expectAccessible(a.page, "unlock");
  await a.page.getByLabel("Master password").fill(NEW_PASSWORD);
  await a.page.getByRole("button", { name: "Unlock" }).click();
  await expect(a.page.getByRole("listitem").filter({ hasText: ISSUER })).toBeVisible({
    timeout: 60_000,
  });

  // ---- no CSP / Trusted Types / SRI problems in either browser
  expect([...a.violations, ...(await cspViolations(a.page))]).toEqual([]);
  expect([...b.violations, ...(await cspViolations(b.page))]).toEqual([]);

  await a.context.close();
  await b.context.close();

  // ---- zero-knowledge audit on the raw bytes of the local D1 database (including free pages and WAL)
  const dump = rawD1Bytes(d1State);
  const haystack = dump.toLowerCase();
  // The e-mail is the only plaintext identifier by design; finding it proves the scan sees the data.
  expect(haystack.includes(EMAIL.toLowerCase())).toBe(true);
  const leaked = [
    ISSUER,
    ACCOUNT,
    SECRET,
    PASSWORD,
    NEW_PASSWORD,
    BACKUP_PASSWORD,
    words.join(" "),
  ].filter((needle) => haystack.includes(needle.toLowerCase()));
  expect(leaked).toEqual([]);
});
