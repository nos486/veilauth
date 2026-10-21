import { type FormEvent, useState } from "react";
import { useController } from "../app/context";
import { Button, ErrorText, Modal, Page, TextField } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { navigate, useApp } from "../store/app";

export function EditToken({ id }: { id: string }) {
  const controller = useController();
  const token = useApp((s) => s.tokens.find((x) => x.id === id));
  const [issuer, setIssuer] = useState(token?.value.issuer ?? "");
  const [account, setAccount] = useState(token?.value.account ?? "");
  const [notes, setNotes] = useState(token?.value.notes ?? "");
  const [tags, setTags] = useState(token?.value.tags.join(", ") ?? "");
  const [favorite, setFavorite] = useState(token?.value.favorite ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmTrash, setConfirmTrash] = useState(false);

  const back = () => {
    navigate({ name: "vault" });
  };
  if (!token) {
    return (
      <Page title={t("edit.title")} onBack={back}>
        <p>{t("edit.missing")}</p>
      </Page>
    );
  }
  const v = token.value;

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await controller.saveToken(id, {
        ...v,
        issuer: issuer.trim().slice(0, 256),
        account: account.trim().slice(0, 256),
        notes: notes.slice(0, 2048),
        tags: [
          ...new Set(
            tags
              .split(",")
              .map((x) => x.trim())
              .filter((x) => x !== ""),
          ),
        ]
          .slice(0, 32)
          .map((x) => x.slice(0, 64)),
        favorite,
      });
      back();
    } catch (err: unknown) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  const trash = async () => {
    setBusy(true);
    try {
      await controller.trashToken(id);
      back();
    } catch (err: unknown) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Page title={t("edit.title")} onBack={back}>
      <form className="flex flex-col gap-4" onSubmit={(e) => void save(e)}>
        <TextField
          label={t("field.issuer")}
          value={issuer}
          maxLength={256}
          onChange={(e) => {
            setIssuer(e.target.value);
          }}
        />
        <TextField
          label={t("field.account")}
          value={account}
          maxLength={256}
          onChange={(e) => {
            setAccount(e.target.value);
          }}
        />
        <TextField
          label={t("field.tags")}
          hint={t("edit.tagsHint")}
          value={tags}
          onChange={(e) => {
            setTags(e.target.value);
          }}
        />
        <div className="flex flex-col gap-1">
          <label htmlFor="notes" className="text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("field.notes")}
          </label>
          <textarea
            id="notes"
            rows={3}
            maxLength={2048}
            value={notes}
            onChange={(e) => {
              setNotes(e.target.value);
            }}
            className="rounded-lg border border-slate-300 bg-white p-3 text-base text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-800 dark:text-slate-200">
          <input
            type="checkbox"
            className="h-5 w-5"
            checked={favorite}
            onChange={(e) => {
              setFavorite(e.target.checked);
            }}
          />
          {t("field.favorite")}
        </label>
        <dl className="grid grid-cols-2 gap-2 rounded-lg bg-slate-50 p-3 text-sm dark:bg-slate-900">
          <dt className="text-slate-600 dark:text-slate-400">{t("field.type")}</dt>
          <dd className="text-slate-900 dark:text-slate-100">{t(`type.${v.type}`)}</dd>
          {v.type !== "steam" ? (
            <>
              <dt className="text-slate-600 dark:text-slate-400">{t("field.algorithm")}</dt>
              <dd className="text-slate-900 dark:text-slate-100">{v.algorithm}</dd>
              <dt className="text-slate-600 dark:text-slate-400">{t("field.digits")}</dt>
              <dd className="text-slate-900 dark:text-slate-100">{v.digits}</dd>
            </>
          ) : null}
          {v.type === "totp" ? (
            <>
              <dt className="text-slate-600 dark:text-slate-400">{t("field.period")}</dt>
              <dd className="text-slate-900 dark:text-slate-100">{v.period}</dd>
            </>
          ) : null}
          {v.type === "hotp" ? (
            <>
              <dt className="text-slate-600 dark:text-slate-400">{t("field.counter")}</dt>
              <dd className="text-slate-900 dark:text-slate-100">{v.counter}</dd>
            </>
          ) : null}
        </dl>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" busy={busy}>
          {t("common.save")}
        </Button>
        <Button
          variant="danger"
          disabled={busy}
          onClick={() => {
            setConfirmTrash(true);
          }}
        >
          {t("edit.moveToTrash")}
        </Button>
      </form>
      <Modal
        open={confirmTrash}
        title={t("edit.trashTitle")}
        onClose={() => {
          setConfirmTrash(false);
        }}
      >
        <p className="text-sm">{t("edit.trashBody")}</p>
        <div className="flex justify-end gap-2">
          <Button
            variant="secondary"
            onClick={() => {
              setConfirmTrash(false);
            }}
          >
            {t("common.cancel")}
          </Button>
          <Button variant="danger" onClick={() => void trash()}>
            {t("edit.moveToTrash")}
          </Button>
        </div>
      </Modal>
    </Page>
  );
}
