import { useCallback, useMemo, useState } from "react";
import { useController } from "../app/context";
import { loadSettings } from "../app/settings";
import { TokenRow } from "../components/TokenRow";
import { Button, Page } from "../components/ui";
import { useNow } from "../hooks";
import { t } from "../i18n";
import { copySensitive } from "../lib/clipboard";
import { errorMessage } from "../lib/errors";
import { matchesSearch, type VaultToken } from "../lib/tokens";
import { navigate, useApp } from "../store/app";

export function Vault() {
  const controller = useController();
  const tokens = useApp((s) => s.tokens);
  const unreadable = useApp((s) => s.unreadable);
  const sync = useApp((s) => s.sync);
  const updateReady = useApp((s) => s.updateReady);
  const conflicts = useApp((s) => s.conflictsResolved);
  const rollback = useApp((s) => s.rollbackDetected);
  const [query, setQuery] = useState("");
  const [toast, setToast] = useState<string | null>(null);
  const now = useNow();
  const hideCodes = useMemo(() => loadSettings().hideCodes, []);

  const visible = useMemo(
    () => tokens.filter((tk) => tk.value.trashedAt === null && matchesSearch(tk, query)),
    [tokens, query],
  );
  const trashed = tokens.filter((tk) => tk.value.trashedAt !== null).length;

  const onCopy = useCallback((code: string, token: VaultToken) => {
    copySensitive(code).then(
      () => {
        setToast(t("vault.copied", { name: token.value.issuer || token.value.account }));
      },
      (e: unknown) => {
        setToast(errorMessage(e));
      },
    );
    setTimeout(() => {
      setToast(null);
    }, 2500);
  }, []);
  const onEdit = useCallback((id: string) => {
    navigate({ name: "edit", id });
  }, []);
  const onNextHotp = useCallback(
    (id: string) => {
      controller.nextHotp(id).catch((e: unknown) => {
        setToast(errorMessage(e));
      });
    },
    [controller],
  );

  return (
    <Page
      title={t("vault.title")}
      actions={
        <>
          <Button
            variant="ghost"
            onClick={() => {
              void controller.syncNow();
            }}
            aria-label={t("vault.syncNow")}
            title={t(`sync.${sync}`)}
          >
            <span aria-hidden="true" className={sync === "syncing" ? "animate-spin" : ""}>
              ⟳
            </span>
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              navigate({ name: "settings" });
            }}
            aria-label={t("settings.title")}
          >
            ⚙
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              void controller.lock();
            }}
            aria-label={t("vault.lock")}
            title={t("vault.lockShortcut")}
          >
            🔒
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {updateReady ? (
          <div
            role="status"
            className="flex items-center gap-3 rounded-lg bg-indigo-50 p-3 text-sm text-indigo-900 dark:bg-indigo-950 dark:text-indigo-100"
          >
            <span className="flex-1">{t("update.ready")}</span>
            <Button
              variant="secondary"
              onClick={() => {
                void controller.lock();
              }}
            >
              {t("update.apply")}
            </Button>
          </div>
        ) : null}
        {sync === "offline" ? (
          <p role="status" className="text-sm text-slate-700 dark:text-slate-300">
            {t("sync.offline")}
          </p>
        ) : null}
        {sync === "error" ? (
          <p role="alert" className="text-sm text-red-700 dark:text-red-400">
            {t("sync.error")}
          </p>
        ) : null}
        {unreadable > 0 ? (
          <p
            role="alert"
            className="rounded-lg bg-amber-50 p-3 text-sm text-amber-950 dark:bg-amber-950 dark:text-amber-100"
          >
            {t("vault.unreadable", { count: unreadable })}
          </p>
        ) : null}
        {rollback ? (
          <p
            role="alert"
            className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
          >
            {t("vault.rollback")}
          </p>
        ) : null}
        {conflicts > 0 ? (
          <p
            role="status"
            className="rounded-lg bg-amber-50 p-3 text-sm text-amber-950 dark:bg-amber-950 dark:text-amber-100"
          >
            {t("vault.conflicts", { count: conflicts })}
          </p>
        ) : null}
        <div className="flex gap-2">
          <label className="sr-only" htmlFor="search">
            {t("vault.search")}
          </label>
          <input
            id="search"
            type="search"
            placeholder={t("vault.search")}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
            }}
            className="min-h-11 flex-1 rounded-lg border border-slate-300 bg-white px-3 text-base text-slate-900 placeholder:text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-400"
          />
          <Button
            onClick={() => {
              navigate({ name: "add" });
            }}
          >
            {t("vault.add")}
          </Button>
        </div>
        {visible.length === 0 ? (
          <p className="py-12 text-center text-slate-600 dark:text-slate-400">
            {tokens.length === 0 ? t("vault.empty") : t("vault.noMatches")}
          </p>
        ) : (
          <ul className="flex flex-col gap-2" aria-label={t("vault.listLabel")}>
            {visible.map((tk) => (
              <TokenRow
                key={tk.id}
                token={tk}
                now={now}
                hideCodes={hideCodes}
                onCopy={onCopy}
                onEdit={onEdit}
                onNextHotp={onNextHotp}
              />
            ))}
          </ul>
        )}
        {trashed > 0 ? (
          <Button
            variant="ghost"
            onClick={() => {
              navigate({ name: "trash" });
            }}
          >
            {t("vault.trashLink", { count: trashed })}
          </Button>
        ) : null}
      </div>
      <div
        aria-live="polite"
        className="pointer-events-none fixed inset-x-0 bottom-4 flex justify-center px-4"
      >
        {toast ? (
          <p className="rounded-full bg-slate-900 px-4 py-2 text-sm text-white shadow-lg dark:bg-slate-100 dark:text-slate-900">
            {toast}
          </p>
        ) : null}
      </div>
    </Page>
  );
}
