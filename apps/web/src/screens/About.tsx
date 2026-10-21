import { Page } from "../components/ui";
import { t } from "../i18n";
import { navigate } from "../store/app";

declare const __APP_VERSION__: string;
declare const __BUILD_COMMIT__: string;

export function About() {
  return (
    <Page
      title={t("about.title")}
      onBack={() => {
        navigate({ name: "settings" });
      }}
    >
      <div className="flex flex-col gap-3 text-sm text-slate-800 dark:text-slate-200">
        <p>{t("about.body")}</p>
        <dl className="grid grid-cols-2 gap-2">
          <dt className="text-slate-600 dark:text-slate-400">{t("about.version")}</dt>
          <dd>{__APP_VERSION__}</dd>
          <dt className="text-slate-600 dark:text-slate-400">{t("about.build")}</dt>
          <dd className="font-mono">{__BUILD_COMMIT__}</dd>
        </dl>
        <p>{t("about.verify")}</p>
      </div>
    </Page>
  );
}
