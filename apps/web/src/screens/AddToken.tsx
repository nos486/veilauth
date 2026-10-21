import {
  generateCode,
  MigrationBatch,
  type OtpParams,
  OtpError,
  parseSecret,
  validatePeriod,
} from "@zk2fa/otp";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { useController } from "../app/context";
import { formatCode } from "../components/TokenRow";
import { QrScanner } from "../components/QrScanner";
import { Button, ErrorText, InfoText, Page, TextField } from "../components/ui";
import { useNow } from "../hooks";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { decodeQrImage } from "../lib/qr";
import { isDuplicate, newTokenItem, parseScannedText } from "../lib/tokens";
import { navigate, useApp } from "../store/app";

type Mode = "scan" | "image" | "link" | "manual";

export function AddToken() {
  const [mode, setMode] = useState<Mode>("image");
  const [found, setFound] = useState<OtpParams[] | null>(null);
  const [skipped, setSkipped] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const batch = useRef(new MigrationBatch());

  const handleText = (text: string) => {
    try {
      const r = parseScannedText(text, batch.current);
      if (r.kind === "batch-progress") {
        setProgress(t("add.batchProgress", { received: r.received, total: r.total }));
        setError(null);
        return;
      }
      batch.current = new MigrationBatch();
      setProgress(null);
      setError(null);
      setSkipped(r.skipped);
      setFound(r.tokens);
    } catch (e: unknown) {
      setError(errorMessage(e));
    }
  };

  const handleImage = async (blob: Blob) => {
    try {
      const text = await decodeQrImage(blob);
      if (text === null) setError(t("add.noQr"));
      else handleText(text);
    } catch (e: unknown) {
      if (e instanceof DOMException) setError(t("add.badImage"));
      else setError(errorMessage(e));
    }
  };

  // Paste a screenshot or an otpauth:// link anywhere on this screen.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const data = e.clipboardData;
      if (!data) return;
      const target = e.target;
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) return;
      const image = Array.from(data.items).find((i) => i.type.startsWith("image/"));
      const file = image?.getAsFile();
      if (file) {
        e.preventDefault();
        void handleImage(file);
        return;
      }
      const text = data.getData("text/plain");
      if (text.trim() !== "") {
        e.preventDefault();
        handleText(text);
      }
    };
    document.addEventListener("paste", onPaste);
    return () => {
      document.removeEventListener("paste", onPaste);
    };
  });

  if (found !== null)
    return (
      <Review
        tokens={found}
        skipped={skipped}
        onCancel={() => {
          setFound(null);
        }}
      />
    );

  const tabs: { id: Mode; label: string }[] = [
    { id: "scan", label: t("add.tabScan") },
    { id: "image", label: t("add.tabImage") },
    { id: "link", label: t("add.tabLink") },
    { id: "manual", label: t("add.tabManual") },
  ];

  return (
    <Page
      title={t("add.title")}
      onBack={() => {
        navigate({ name: "vault" });
      }}
    >
      <div className="flex flex-col gap-4">
        <div
          role="tablist"
          aria-label={t("add.methods")}
          className="grid grid-cols-4 gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800"
        >
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={mode === tab.id}
              onClick={() => {
                setMode(tab.id);
                setError(null);
              }}
              className={`min-h-11 rounded-md px-2 text-sm font-semibold ${mode === tab.id ? "bg-white text-indigo-800 shadow-sm dark:bg-slate-950 dark:text-indigo-200" : "text-slate-700 dark:text-slate-300"}`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        {progress ? <InfoText>{progress}</InfoText> : null}
        <ErrorText>{error}</ErrorText>
        <div role="tabpanel">
          {mode === "scan" ? <QrScanner onResult={handleText} /> : null}
          {mode === "image" ? <ImagePicker onImage={(b) => void handleImage(b)} /> : null}
          {mode === "link" ? <LinkForm onSubmit={handleText} /> : null}
          {mode === "manual" ? (
            <ManualForm
              onSubmit={(p) => {
                setSkipped(0);
                setFound([p]);
              }}
            />
          ) : null}
        </div>
      </div>
    </Page>
  );
}

function ImagePicker({ onImage }: { onImage: (b: Blob) => void }) {
  return (
    <div className="flex flex-col gap-2">
      <label className="flex min-h-32 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-slate-300 p-6 text-center text-sm text-slate-700 hover:border-indigo-400 dark:border-slate-600 dark:text-slate-300">
        <span className="font-semibold text-indigo-700 dark:text-indigo-300">
          {t("add.chooseImage")}
        </span>
        <span>{t("add.pasteHint")}</span>
        <input
          type="file"
          accept="image/*"
          className="sr-only"
          data-testid="qr-file"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) onImage(f);
            e.target.value = "";
          }}
        />
      </label>
    </div>
  );
}

function LinkForm({ onSubmit }: { onSubmit: (text: string) => void }) {
  const [text, setText] = useState("");
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(text);
      }}
    >
      <label htmlFor="otpauth" className="text-sm font-medium text-slate-800 dark:text-slate-200">
        {t("add.linkLabel")}
      </label>
      <textarea
        id="otpauth"
        rows={4}
        value={text}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        placeholder="otpauth://totp/Example:alice?secret=…"
        onChange={(e) => {
          setText(e.target.value);
        }}
        className="rounded-lg border border-slate-300 bg-white p-3 font-mono text-sm text-slate-900 placeholder:text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100"
      />
      <Button type="submit" disabled={text.trim() === ""}>
        {t("add.readLink")}
      </Button>
    </form>
  );
}

function ManualForm({ onSubmit }: { onSubmit: (p: OtpParams) => void }) {
  const [issuer, setIssuer] = useState("");
  const [account, setAccount] = useState("");
  const [secret, setSecret] = useState("");
  const [type, setType] = useState<OtpParams["type"]>("totp");
  const [algorithm, setAlgorithm] = useState<OtpParams["algorithm"]>("SHA1");
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState("30");
  const [counter, setCounter] = useState("0");
  const [error, setError] = useState<string | null>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    try {
      const s = parseSecret(secret);
      const isSteam = type === "steam";
      const counterN = Number(counter);
      if (type === "hotp" && (!Number.isSafeInteger(counterN) || counterN < 0))
        throw new OtpError("INVALID_COUNTER");
      onSubmit({
        type,
        issuer: issuer.trim(),
        account: account.trim(),
        secret: s,
        algorithm: isSteam ? "SHA1" : algorithm,
        digits: isSteam ? 5 : digits,
        period: isSteam ? 30 : validatePeriod(Number(period)),
        counter: type === "hotp" ? counterN : 0,
      });
    } catch (err: unknown) {
      setError(errorMessage(err));
    }
  };

  const select =
    "min-h-11 rounded-lg border border-slate-300 bg-white px-3 text-base text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100";

  return (
    <form className="flex flex-col gap-3" onSubmit={submit}>
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
        label={t("field.secret")}
        hint={t("add.secretHint")}
        required
        value={secret}
        spellCheck={false}
        autoCapitalize="characters"
        autoComplete="off"
        onChange={(e) => {
          setSecret(e.target.value);
        }}
      />
      <div className="grid grid-cols-2 gap-3">
        <label className="flex flex-col gap-1 text-sm font-medium text-slate-800 dark:text-slate-200">
          {t("field.type")}
          <select
            className={select}
            value={type}
            onChange={(e) => {
              setType(e.target.value as OtpParams["type"]);
            }}
          >
            <option value="totp">{t("type.totp")}</option>
            <option value="hotp">{t("type.hotp")}</option>
            <option value="steam">{t("type.steam")}</option>
          </select>
        </label>
        {type !== "steam" ? (
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("field.algorithm")}
            <select
              className={select}
              value={algorithm}
              onChange={(e) => {
                setAlgorithm(e.target.value as OtpParams["algorithm"]);
              }}
            >
              <option value="SHA1">SHA-1</option>
              <option value="SHA256">SHA-256</option>
              <option value="SHA512">SHA-512</option>
            </select>
          </label>
        ) : null}
        {type !== "steam" ? (
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("field.digits")}
            <select
              className={select}
              value={digits}
              onChange={(e) => {
                setDigits(Number(e.target.value));
              }}
            >
              <option value={6}>6</option>
              <option value={7}>7</option>
              <option value={8}>8</option>
            </select>
          </label>
        ) : null}
        {type === "totp" ? (
          <TextField
            label={t("field.period")}
            type="number"
            min={1}
            max={86400}
            value={period}
            onChange={(e) => {
              setPeriod(e.target.value);
            }}
          />
        ) : null}
        {type === "hotp" ? (
          <TextField
            label={t("field.counter")}
            type="number"
            min={0}
            value={counter}
            onChange={(e) => {
              setCounter(e.target.value);
            }}
          />
        ) : null}
      </div>
      <ErrorText>{error}</ErrorText>
      <Button type="submit">{t("add.review")}</Button>
    </form>
  );
}

function PreviewCode({ params }: { params: OtpParams }) {
  const now = useNow();
  const step = params.type === "hotp" ? 0 : Math.floor(now / 1000 / params.period);
  const [code, setCode] = useState("");
  useEffect(() => {
    let cancelled = false;
    void generateCode(params, step * params.period * 1000).then((c) => {
      if (!cancelled) setCode(c);
    });
    return () => {
      cancelled = true;
    };
  }, [params, step]);
  return (
    <span
      className="font-mono text-xl font-bold text-indigo-700 dark:text-indigo-300"
      data-testid="preview-code"
    >
      {code === "" ? "…" : formatCode(code)}
    </span>
  );
}

function Review({
  tokens,
  skipped,
  onCancel,
}: {
  tokens: OtpParams[];
  skipped: number;
  onCancel: () => void;
}) {
  const controller = useController();
  const existing = useApp((s) => s.tokens);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [include, setInclude] = useState<boolean[]>(() =>
    tokens.map((p) => !isDuplicate(p, existing)),
  );

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const now = Date.now();
      for (const [i, p] of tokens.entries()) {
        if (include[i]) await controller.saveToken(null, newTokenItem(p, now));
      }
      navigate({ name: "vault" });
    } catch (e: unknown) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };

  const count = include.filter(Boolean).length;
  return (
    <Page title={t("add.reviewTitle")} onBack={onCancel}>
      <div className="flex flex-col gap-3">
        {skipped > 0 ? <InfoText>{t("add.skipped", { count: skipped })}</InfoText> : null}
        <ul className="flex flex-col gap-2">
          {tokens.map((p, i) => {
            const dup = isDuplicate(p, existing);
            return (
              <li
                key={i}
                className="flex items-center gap-3 rounded-xl bg-white p-3 ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800"
              >
                <input
                  type="checkbox"
                  className="h-5 w-5"
                  aria-label={t("add.includeToken", { name: p.issuer || p.account })}
                  checked={include[i] ?? false}
                  onChange={(e) => {
                    const v = e.target.checked;
                    setInclude((prev) => prev.map((x, j) => (j === i ? v : x)));
                  }}
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-semibold text-slate-900 dark:text-slate-100">
                    {p.issuer || t("add.noIssuer")}
                  </p>
                  <p className="truncate text-sm text-slate-600 dark:text-slate-400">{p.account}</p>
                  {dup ? (
                    <p className="text-xs text-amber-800 dark:text-amber-300">
                      {t("add.duplicate")}
                    </p>
                  ) : null}
                </div>
                <PreviewCode params={p} />
              </li>
            );
          })}
        </ul>
        <ErrorText>{error}</ErrorText>
        <Button busy={busy} disabled={count === 0} onClick={() => void save()}>
          {t("add.save", { count })}
        </Button>
      </div>
    </Page>
  );
}
