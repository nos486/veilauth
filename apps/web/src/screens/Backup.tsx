import type { BackupContents } from "@zk2fa/crypto";
import { type FormEvent, useState } from "react";
import { useController } from "../app/context";
import { PasswordStrengthMeter, usePasswordStrength } from "../components/PasswordStrength";
import { Button, ErrorText, InfoText, Modal, PasswordField, Section } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { MIN_LENGTH, MIN_SCORE } from "../lib/strength";
import { useApp } from "../store/app";

/** Largest file the restore picker reads (a full vault is well under 8 MiB). */
const MAX_FILE_BYTES = 12 * 1024 * 1024;

export function backupFileName(now: Date): string {
  const d = now.toISOString().slice(0, 10);
  return `veilauth-backup-${d}.json`;
}

function download(text: string, name: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

/** Settings section: download an encrypted backup file, or add the codes from one. */
export function Backup() {
  return (
    <Section title={t("backup.title")}>
      <p className="text-xs text-slate-600 dark:text-slate-400">{t("backup.explain")}</p>
      <div className="flex flex-wrap gap-2">
        <CreateBackup />
        <RestoreBackup />
      </div>
    </Section>
  );
}

function CreateBackup() {
  const controller = useController();
  const email = useApp((s) => s.email);
  const count = useApp((s) => s.tokens.filter((x) => x.value.trashedAt === null).length);
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const strength = usePasswordStrength(password, [email, "veilauth"]);
  const tooWeak = password.length < MIN_LENGTH || (strength?.score ?? 0) < MIN_SCORE;

  const close = () => {
    setOpen(false);
    setPassword("");
    setConfirm("");
    setError(null);
    setDone(false);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (tooWeak) {
      setError(t("signup.tooWeak", { min: MIN_LENGTH }));
      return;
    }
    if (password !== confirm) {
      setError(t("signup.mismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const file = await controller.createBackup(password);
      download(file, backupFileName(new Date()));
      setPassword("");
      setConfirm("");
      setDone(true);
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button
        variant="secondary"
        disabled={count === 0}
        onClick={() => {
          setOpen(true);
        }}
      >
        {t("backup.create")}
      </Button>
      <Modal open={open} title={t("backup.createTitle")} onClose={close}>
        {done ? (
          <>
            <InfoText>{t("backup.saved")}</InfoText>
            <div className="flex justify-end">
              <Button onClick={close}>{t("backup.close")}</Button>
            </div>
          </>
        ) : (
          <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)}>
            <p className="text-sm">{t("backup.createBody", { n: count })}</p>
            <PasswordField
              label={t("backup.password")}
              autoComplete="new-password"
              required
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
            <PasswordStrengthMeter strength={strength} />
            <PasswordField
              label={t("field.confirmPassword")}
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => {
                setConfirm(e.target.value);
              }}
            />
            <ErrorText>{error}</ErrorText>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={close}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" busy={busy}>
                {busy ? t("backup.working") : t("backup.download")}
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </>
  );
}

function RestoreBackup() {
  const controller = useController();
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  const [password, setPassword] = useState("");
  const [contents, setContents] = useState<BackupContents | null>(null);
  const [result, setResult] = useState<{ added: number; skipped: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

  const close = () => {
    setOpen(false);
    setFile(null);
    setPassword("");
    setContents(null);
    setResult(null);
    setError(null);
  };

  const pick = async (f: File) => {
    setError(null);
    setContents(null);
    if (f.size > MAX_FILE_BYTES) {
      setFile(null);
      setError(t("error.INVALID_BACKUP"));
      return;
    }
    setFile({ name: f.name, text: await f.text() });
  };

  const unlockFile = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError(t("backup.noFile"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setContents(await controller.openBackup(file.text, password));
      setPassword("");
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!contents) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await controller.restoreBackup(contents.tokens));
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  let body: React.ReactNode;
  if (result) {
    body = (
      <>
        <InfoText>
          {t("backup.restored", { added: result.added, skipped: result.skipped })}
        </InfoText>
        <div className="flex justify-end">
          <Button onClick={close}>{t("backup.close")}</Button>
        </div>
      </>
    );
  } else if (contents) {
    body = (
      <>
        <p className="text-sm">
          {t("backup.preview", {
            n: contents.tokens.length,
            when: fmt.format(contents.exportedAt),
          })}
        </p>
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={close}>
            {t("common.cancel")}
          </Button>
          <Button
            busy={busy}
            disabled={contents.tokens.length === 0}
            onClick={() => void restore()}
          >
            {t("backup.restore")}
          </Button>
        </div>
      </>
    );
  } else {
    body = (
      <form className="flex flex-col gap-3" onSubmit={(e) => void unlockFile(e)}>
        <p className="text-sm">{t("backup.restoreBody")}</p>
        <label className="flex min-h-11 cursor-pointer items-center justify-center rounded-lg border-2 border-dashed border-slate-300 p-4 text-center text-sm hover:border-indigo-400 dark:border-slate-600">
          <span className="font-semibold text-indigo-700 dark:text-indigo-300">
            {file ? file.name : t("backup.chooseFile")}
          </span>
          <input
            type="file"
            accept=".json,application/json"
            className="sr-only"
            data-testid="backup-file"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void pick(f);
              e.target.value = "";
            }}
          />
        </label>
        <PasswordField
          label={t("backup.password")}
          autoComplete="off"
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={close}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" busy={busy}>
            {busy ? t("backup.opening") : t("backup.open")}
          </Button>
        </div>
      </form>
    );
  }

  return (
    <>
      <Button
        variant="secondary"
        onClick={() => {
          setOpen(true);
        }}
      >
        {t("backup.restoreOpen")}
      </Button>
      <Modal open={open} title={t("backup.restoreTitle")} onClose={close}>
        {body}
      </Modal>
    </>
  );
}
