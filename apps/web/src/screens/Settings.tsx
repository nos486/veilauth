import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useController } from "../app/context";
import {
  AUTO_LOCK_CHOICES,
  type DeviceSettings,
  loadSettings,
  saveSettings,
} from "../app/settings";
import { PasswordStrengthMeter, usePasswordStrength } from "../components/PasswordStrength";
import { Button, ErrorText, InfoText, Modal, Page, PasswordField, Section } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { MIN_LENGTH, MIN_SCORE } from "../lib/strength";
import { navigate, useApp } from "../store/app";
import { Backup } from "./Backup";

export function Settings({
  onSettingsChanged,
}: {
  onSettingsChanged: (s: DeviceSettings) => void;
}) {
  const controller = useController();
  const [settings, setSettings] = useState(loadSettings);

  const update = (patch: Partial<DeviceSettings>) => {
    const next = { ...settings, ...patch };
    setSettings(next);
    saveSettings(next);
    onSettingsChanged(next);
  };

  return (
    <Page
      title={t("settings.title")}
      onBack={() => {
        navigate({ name: "vault" });
      }}
    >
      <div className="flex flex-col gap-4">
        <Section title={t("settings.security")}>
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("settings.autoLock")}
            <select
              value={settings.autoLockSeconds}
              onChange={(e) => {
                update({ autoLockSeconds: Number(e.target.value) });
              }}
              className="min-h-11 rounded-lg border border-slate-300 bg-white px-3 text-base text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
            >
              {AUTO_LOCK_CHOICES.map((s) => (
                <option key={s} value={s}>
                  {s < 60 ? t("settings.seconds", { n: s }) : t("settings.minutes", { n: s / 60 })}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-800 dark:text-slate-200">
            <input
              type="checkbox"
              className="h-5 w-5"
              checked={settings.hideCodes}
              onChange={(e) => {
                update({ hideCodes: e.target.checked });
              }}
            />
            {t("settings.hideCodes")}
          </label>
          <p className="text-xs text-slate-600 dark:text-slate-400">{t("settings.lockHint")}</p>
        </Section>
        <Backup />
        <Devices />
        <ChangePassword />
        <Section title={t("settings.account")}>
          <Button
            variant="secondary"
            onClick={() => {
              void controller.logout();
            }}
          >
            {t("settings.logOut")}
          </Button>
          <DeleteAccount />
        </Section>
        <Button
          variant="ghost"
          onClick={() => {
            navigate({ name: "about" });
          }}
        >
          {t("about.title")}
        </Button>
      </div>
    </Page>
  );
}

function Devices() {
  const controller = useController();
  const queryClient = useQueryClient();
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: () => controller.api.devices(),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => controller.api.revokeDevice(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["devices"] }),
  });
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

  return (
    <Section title={t("settings.devices")}>
      {devices.isPending ? <p className="text-sm">{t("common.loading")}</p> : null}
      {devices.error ? <ErrorText>{errorMessage(devices.error)}</ErrorText> : null}
      {revoke.error ? <ErrorText>{errorMessage(revoke.error)}</ErrorText> : null}
      <ul className="flex flex-col gap-2">
        {devices.data?.devices.map((d) => (
          <li key={d.id} className="flex items-center gap-2 text-sm">
            <div className="min-w-0 flex-1">
              <p className="font-semibold text-slate-900 dark:text-slate-100">
                {t(`platform.${d.platform}`)} {d.current ? `(${t("settings.thisDevice")})` : ""}
              </p>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                {t("settings.lastSeen", { when: fmt.format(d.lastSeenAt) })}
              </p>
            </div>
            {!d.current ? (
              <Button
                variant="secondary"
                busy={revoke.isPending && revoke.variables === d.id}
                onClick={() => {
                  revoke.mutate(d.id);
                }}
              >
                {t("settings.revoke")}
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
    </Section>
  );
}

function ChangePassword() {
  const controller = useController();
  const email = useApp((s) => s.email);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const strength = usePasswordStrength(next, [email, "veilauth"]);
  const tooWeak = next.length < MIN_LENGTH || (strength?.score ?? 0) < MIN_SCORE;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (tooWeak) {
      setError(t("signup.tooWeak", { min: MIN_LENGTH }));
      return;
    }
    if (next !== confirm) {
      setError(t("signup.mismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      await controller.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title={t("password.title")}>
      <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)}>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t("password.explain")}</p>
        <input type="email" autoComplete="username" value={email} readOnly hidden />
        <PasswordField
          label={t("password.current")}
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => {
            setCurrent(e.target.value);
          }}
        />
        <PasswordField
          label={t("password.new")}
          autoComplete="new-password"
          required
          value={next}
          onChange={(e) => {
            setNext(e.target.value);
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
        {done ? <InfoText>{t("notice.passwordChanged")}</InfoText> : null}
        <Button type="submit" busy={busy}>
          {busy ? t("password.working") : t("password.submit")}
        </Button>
      </form>
    </Section>
  );
}

function DeleteAccount() {
  const controller = useController();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await controller.deleteAccount(password);
    } catch (err: unknown) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <>
      <Button
        variant="danger"
        onClick={() => {
          setOpen(true);
        }}
      >
        {t("delete.open")}
      </Button>
      <Modal
        open={open}
        title={t("delete.title")}
        onClose={() => {
          setOpen(false);
          setPassword("");
        }}
      >
        <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)}>
          <p className="text-sm">{t("delete.body")}</p>
          <PasswordField
            label={t("field.masterPassword")}
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
          <ErrorText>{error}</ErrorText>
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              onClick={() => {
                setOpen(false);
              }}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="danger" busy={busy}>
              {t("delete.confirm")}
            </Button>
          </div>
        </form>
      </Modal>
    </>
  );
}
