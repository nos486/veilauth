import { Button, Card, InfoText } from "../components/ui";
import { t } from "../i18n";
import { useApp } from "../store/app";

export function Welcome() {
  const notice = useApp((s) => s.notice);
  return (
    <Card title={t("app.name")}>
      <div className="flex flex-col gap-4">
        <p className="text-slate-700 dark:text-slate-300">{t("welcome.tagline")}</p>
        {notice === "signedOut" ? <InfoText>{t("notice.signedOut")}</InfoText> : null}
        {notice === "accountDeleted" ? <InfoText>{t("notice.accountDeleted")}</InfoText> : null}
        <Button
          onClick={() => {
            useApp.setState({ phase: "signup", notice: null });
          }}
        >
          {t("welcome.signUp")}
        </Button>
        <Button
          variant="secondary"
          onClick={() => {
            useApp.setState({ phase: "login", notice: null });
          }}
        >
          {t("welcome.logIn")}
        </Button>
        <p className="text-xs text-slate-600 dark:text-slate-400">{t("welcome.zeroKnowledge")}</p>
      </div>
    </Card>
  );
}
