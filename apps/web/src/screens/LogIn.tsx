import { type FormEvent, useState } from "react";
import { ApiError } from "../api/client";
import { useController } from "../app/context";
import { Turnstile } from "../components/Turnstile";
import { Button, Card, ErrorText, InfoText, PasswordField, TextField } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { useApp } from "../store/app";

export function LogIn() {
  const controller = useController();
  const initialEmail = useApp((s) => s.email);
  const notice = useApp((s) => s.notice);
  const siteKey = useApp((s) => s.turnstileSiteKey);
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsCheck, setNeedsCheck] = useState(false);
  const [checkToken, setCheckToken] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (needsCheck && siteKey !== null && checkToken === null) {
      setError(t("error.TURNSTILE_REQUIRED"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await controller.login(email, password, checkToken);
    } catch (err: unknown) {
      if (
        err instanceof ApiError &&
        (err.code === "TURNSTILE_REQUIRED" || err.code === "TURNSTILE_FAILED")
      ) {
        setNeedsCheck(true);
        setCheckToken(null);
      }
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Card title={t("login.title")}>
      <form className="flex flex-col gap-4" onSubmit={(e) => void submit(e)}>
        {notice === "sessionEnded" ? <InfoText>{t("notice.sessionEnded")}</InfoText> : null}
        <TextField
          label={t("field.email")}
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
          }}
        />
        <PasswordField
          label={t("field.masterPassword")}
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        {needsCheck && siteKey ? (
          <Turnstile siteKey={siteKey} action="login" onToken={setCheckToken} />
        ) : null}
        <ErrorText>{error}</ErrorText>
        <Button type="submit" busy={busy}>
          {busy ? t("login.working") : t("login.submit")}
        </Button>
        <Button
          variant="ghost"
          onClick={() => {
            useApp.setState({ phase: "welcome", notice: null });
          }}
        >
          {t("common.back")}
        </Button>
      </form>
    </Card>
  );
}
