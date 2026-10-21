import QRCode from "qrcode";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { useController } from "../app/context";
import { PasswordStrengthMeter, usePasswordStrength } from "../components/PasswordStrength";
import { Turnstile } from "../components/Turnstile";
import { Button, Card, ErrorText, PasswordField, TextField } from "../components/ui";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { MIN_LENGTH, MIN_SCORE } from "../lib/strength";
import { useApp } from "../store/app";

type Step = "form" | "words" | "confirm";

const CONFIRM_COUNT = 3;

function pickPositions(): number[] {
  const picked = new Set<number>();
  const rnd = new Uint32Array(16);
  while (picked.size < CONFIRM_COUNT) {
    crypto.getRandomValues(rnd);
    for (const r of rnd) {
      if (picked.size < CONFIRM_COUNT) picked.add(r % 24);
    }
  }
  return [...picked].sort((a, b) => a - b);
}

export function SignUp() {
  const controller = useController();
  const [step, setStep] = useState<Step>("form");
  const [words, setWords] = useState<string[]>([]);
  const [email, setEmail] = useState("");

  const back = () => {
    controller.cancelSignup();
    useApp.setState({ phase: "welcome" });
  };

  if (step === "form")
    return (
      <SignUpForm
        onBack={back}
        onDone={(mail, mnemonic) => {
          setEmail(mail);
          setWords(mnemonic.split(" "));
          setStep("words");
        }}
      />
    );
  if (step === "words")
    return (
      <RecoveryWords
        email={email}
        words={words}
        onContinue={() => {
          setStep("confirm");
        }}
      />
    );
  return (
    <ConfirmWords
      words={words}
      onBack={() => {
        setStep("words");
      }}
      onRestart={() => {
        controller.cancelSignup();
        setWords([]);
        setStep("form");
      }}
    />
  );
}

function SignUpForm({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: (email: string, mnemonic: string) => void;
}) {
  const controller = useController();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const strength = usePasswordStrength(
    password,
    useMemo(() => [email, "veilauth"], [email]),
  );

  const tooWeak = password.length < MIN_LENGTH || (strength?.score ?? 0) < MIN_SCORE;
  const mismatch = confirm !== "" && confirm !== password;

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
      onDone(email.trim(), await controller.beginSignup(email, password));
    } catch (err: unknown) {
      setError(errorMessage(err));
      setBusy(false);
    }
  };

  return (
    <Card title={t("signup.title")}>
      <form className="flex flex-col gap-4" onSubmit={(e) => void submit(e)}>
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
          autoComplete="new-password"
          required
          minLength={MIN_LENGTH}
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
          error={mismatch ? t("signup.mismatch") : null}
          onChange={(e) => {
            setConfirm(e.target.value);
          }}
        />
        <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-950 dark:bg-amber-950 dark:text-amber-100">
          <p className="font-semibold">{t("signup.warningTitle")}</p>
          <p>{t("signup.warningBody")}</p>
          <label className="mt-2 flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1 h-4 w-4"
              checked={understood}
              onChange={(e) => {
                setUnderstood(e.target.checked);
              }}
            />
            <span>{t("signup.understand")}</span>
          </label>
        </div>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" busy={busy} disabled={!understood || tooWeak || password !== confirm}>
          {busy ? t("signup.deriving") : t("signup.continue")}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          {t("common.back")}
        </Button>
      </form>
    </Card>
  );
}

function RecoveryWords({
  email,
  words,
  onContinue,
}: {
  email: string;
  words: string[];
  onContinue: () => void;
}) {
  const [saved, setSaved] = useState(false);
  const canvas = useRef<HTMLCanvasElement>(null);
  const mnemonic = words.join(" ");

  useEffect(() => {
    if (canvas.current) {
      void QRCode.toCanvas(canvas.current, mnemonic, {
        errorCorrectionLevel: "M",
        margin: 2,
        width: 192,
      });
    }
  }, [mnemonic]);

  const download = () => {
    const text = `${t("recovery.fileHeader", { email })}\n\n${words.map((w, i) => `${String(i + 1).padStart(2, " ")}. ${w}`).join("\n")}\n`;
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "veilauth-recovery-key.txt";
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  };

  return (
    <Card title={t("recovery.title")}>
      <div className="flex flex-col gap-4">
        <p className="text-sm text-slate-700 dark:text-slate-300">{t("recovery.explain")}</p>
        <section
          className="print-area rounded-lg border border-slate-300 p-3 dark:border-slate-700"
          aria-label={t("recovery.wordsLabel")}
        >
          <p className="hidden print:block">{t("recovery.fileHeader", { email })}</p>
          <ol
            className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-sm sm:grid-cols-3"
            data-testid="recovery-words"
          >
            {words.map((w, i) => (
              <li key={i} className="flex gap-2">
                <span className="w-6 text-right text-slate-500 dark:text-slate-400">{i + 1}.</span>
                <span className="text-slate-900 dark:text-slate-100">{w}</span>
              </li>
            ))}
          </ol>
          <canvas ref={canvas} className="mx-auto mt-3 hidden print:block" aria-hidden="true" />
        </section>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={download}>
            {t("recovery.download")}
          </Button>
          <Button
            variant="secondary"
            onClick={() => {
              window.print();
            }}
          >
            {t("recovery.print")}
          </Button>
        </div>
        <label className="flex items-start gap-2 text-sm text-slate-800 dark:text-slate-200">
          <input
            type="checkbox"
            className="mt-1 h-4 w-4"
            checked={saved}
            onChange={(e) => {
              setSaved(e.target.checked);
            }}
          />
          <span>{t("recovery.savedIt")}</span>
        </label>
        <Button disabled={!saved} onClick={onContinue}>
          {t("signup.continue")}
        </Button>
      </div>
    </Card>
  );
}

function ConfirmWords({
  words,
  onBack,
  onRestart,
}: {
  words: string[];
  onBack: () => void;
  onRestart: () => void;
}) {
  const controller = useController();
  const siteKey = useApp((s) => s.turnstileSiteKey);
  const positions = useMemo(pickPositions, []);
  const [answers, setAnswers] = useState<string[]>(() => positions.map(() => ""));
  const [checkToken, setCheckToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailTaken, setEmailTaken] = useState(false);

  const correct = positions.every((p, i) => (answers[i] ?? "").trim().toLowerCase() === words[p]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!correct) {
      setError(t("confirm.wrongWords"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await controller.completeSignup(checkToken);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.code === "EMAIL_TAKEN") setEmailTaken(true);
      setError(errorMessage(err));
      setCheckToken(null);
      setBusy(false);
    }
  };

  return (
    <Card title={t("confirm.title")}>
      <form className="flex flex-col gap-4" onSubmit={(e) => void submit(e)}>
        <p className="text-sm text-slate-700 dark:text-slate-300">{t("confirm.explain")}</p>
        {positions.map((p, i) => (
          <TextField
            key={p}
            label={t("confirm.word", { n: p + 1 })}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            required
            value={answers[i] ?? ""}
            onChange={(e) => {
              const v = e.target.value;
              setAnswers((prev) => prev.map((x, j) => (j === i ? v : x)));
            }}
          />
        ))}
        {siteKey ? <Turnstile siteKey={siteKey} action="register" onToken={setCheckToken} /> : null}
        <ErrorText>{error}</ErrorText>
        <Button type="submit" busy={busy} disabled={siteKey !== null && checkToken === null}>
          {busy ? t("confirm.creating") : t("confirm.create")}
        </Button>
        {emailTaken ? (
          <Button variant="secondary" onClick={onRestart}>
            {t("confirm.restart")}
          </Button>
        ) : (
          <Button variant="ghost" onClick={onBack}>
            {t("confirm.showWords")}
          </Button>
        )}
      </form>
    </Card>
  );
}
