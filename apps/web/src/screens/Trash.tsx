import { useMemo, useState } from "react";
import { useController } from "../app/context";
import { Button, ErrorText, Page } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { TRASH_RETENTION_MS } from "../lib/tokens";
import { navigate, useApp } from "../store/app";

const DAY_MS = 24 * 60 * 60 * 1000;

export function Trash() {
  const controller = useController();
  const all = useApp((s) => s.tokens);
  const tokens = useMemo(() => all.filter((x) => x.value.trashedAt !== null), [all]);
  const [error, setError] = useState<string | null>(null);

  const run = (fn: () => Promise<void>) => {
    setError(null);
    fn().catch((e: unknown) => {
      setError(errorMessage(e));
    });
  };

  return (
    <Page
      title={t("trash.title")}
      onBack={() => {
        navigate({ name: "vault" });
      }}
    >
      <div className="flex flex-col gap-3">
        <p className="text-sm text-slate-700 dark:text-slate-300">{t("trash.explain")}</p>
        <ErrorText>{error}</ErrorText>
        {tokens.length === 0 ? (
          <p className="py-8 text-center text-slate-600 dark:text-slate-400">{t("trash.empty")}</p>
        ) : null}
        <ul className="flex flex-col gap-2">
          {tokens.map((tk) => {
            const daysLeft = Math.max(
              0,
              Math.ceil(((tk.value.trashedAt ?? 0) + TRASH_RETENTION_MS - Date.now()) / DAY_MS),
            );
            const name = tk.value.issuer || tk.value.account;
            return (
              <li
                key={tk.id}
                className="flex flex-wrap items-center gap-2 rounded-xl bg-white p-3 ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate font-semibold text-slate-900 dark:text-slate-100">
                    {name}
                  </p>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    {t("trash.daysLeft", { days: daysLeft })}
                  </p>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => {
                    run(() => controller.restoreToken(tk.id));
                  }}
                >
                  {t("trash.restore")}
                </Button>
                <Button
                  variant="danger"
                  onClick={() => {
                    run(() => controller.deleteToken(tk.id));
                  }}
                  aria-label={t("trash.deleteNamed", { name })}
                >
                  {t("trash.delete")}
                </Button>
              </li>
            );
          })}
        </ul>
      </div>
    </Page>
  );
}
