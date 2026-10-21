import { type FormEvent, useState } from "react";
import { useController } from "../app/context";
import { Button, Card, ErrorText, InfoText, PasswordField } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { useApp } from "../store/app";

export function Unlock() {
  const controller = useController();
  const email = useApp((s) => s.email);
  const notice = useApp((s) => s.notice);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await controller.unlock(password);
    } catch (err: unknown) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Card title={t("unlock.title")}>
      <form className="flex flex-col gap-4" onSubmit={(e) => void submit(e)}>
        {notice === "locked" ? <InfoText>{t("notice.locked")}</InfoText> : null}
        <p className="text-sm text-slate-700 dark:text-slate-300">
          {t("unlock.signedInAs", { email })}
        </p>
        {/* Hidden username field helps password managers pick the right entry. */}
        <input type="email" autoComplete="username" value={email} readOnly hidden />
        <PasswordField
          label={t("field.masterPassword")}
          autoComplete="current-password"
          required
          autoFocus
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        <ErrorText>{error}</ErrorText>
        <Button type="submit" busy={busy}>
          {busy ? t("unlock.working") : t("unlock.submit")}
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            void controller.logout();
          }}
        >
          {t("unlock.logOut")}
        </Button>
      </form>
    </Card>
  );
}
