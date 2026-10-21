import { generateCode, secondsRemaining, timeCounter } from "@zk2fa/otp";
import { memo, useEffect, useState } from "react";
import { t } from "../i18n";
import { otpParamsOf, type VaultToken } from "../lib/tokens";

export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 7 || code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

const NEXT_PREVIEW_SECONDS = 5;
const RING_R = 14;
const RING_C = 2 * Math.PI * RING_R;

export function CountdownRing({ remaining, period }: { remaining: number; period: number }) {
  const fraction = Math.max(0, Math.min(1, remaining / period));
  const urgent = remaining <= NEXT_PREVIEW_SECONDS;
  return (
    <svg viewBox="0 0 32 32" className="h-8 w-8 shrink-0 -rotate-90" aria-hidden="true">
      <circle
        cx="16"
        cy="16"
        r={RING_R}
        fill="none"
        strokeWidth="3"
        className="stroke-slate-200 dark:stroke-slate-700"
      />
      <circle
        cx="16"
        cy="16"
        r={RING_R}
        fill="none"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray={RING_C}
        strokeDashoffset={RING_C * (1 - fraction)}
        className={urgent ? "stroke-red-500" : "stroke-indigo-500"}
      />
    </svg>
  );
}

/** Computes the code for a time step; recomputes only when the step (or token) changes. */
function useCode(token: VaultToken, step: number): string | null {
  const [code, setCode] = useState<{ key: string; code: string } | null>(null);
  const v = token.value;
  const key = `${token.id}|${v.secret}|${v.type}|${v.algorithm}|${String(v.digits)}|${String(v.period)}|${String(v.counter)}|${String(step)}`;
  useEffect(() => {
    let cancelled = false;
    const params = otpParamsOf(v);
    const timeMs = step * v.period * 1000;
    generateCode(params, timeMs).then(
      (c) => {
        if (!cancelled) setCode({ key, code: c });
      },
      () => {
        if (!cancelled) setCode({ key, code: "" });
      },
    );
    return () => {
      cancelled = true;
    };
    // `key` captures every input of the computation.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return code?.key === key ? code.code : null;
}

export const TokenRow = memo(function TokenRow({
  token,
  now,
  hideCodes,
  onCopy,
  onEdit,
  onNextHotp,
}: {
  token: VaultToken;
  now: number;
  hideCodes: boolean;
  onCopy: (code: string, token: VaultToken) => void;
  onEdit: (id: string) => void;
  onNextHotp: (id: string) => void;
}) {
  const v = token.value;
  const isTimed = v.type !== "hotp";
  const step = isTimed ? timeCounter(now, v.period) : 0;
  const remaining = isTimed ? secondsRemaining(now, v.period) : 0;
  const code = useCode(token, step);
  const nextCode = useCode(token, step + 1);
  const [revealed, setRevealed] = useState(false);
  const showNext =
    isTimed && remaining <= NEXT_PREVIEW_SECONDS && nextCode !== null && nextCode !== "";
  const hidden = hideCodes && !revealed;
  const title = v.issuer !== "" ? v.issuer : v.account;
  const initial = (title.trim().charAt(0) || "?").toUpperCase();

  const copy = () => {
    if (hideCodes && !revealed) {
      setRevealed(true);
      return;
    }
    if (code) onCopy(code, token);
  };

  return (
    <li className="flex items-center gap-3 rounded-xl bg-white px-3 py-3 ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
      <span
        aria-hidden="true"
        className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-indigo-100 text-lg font-bold text-indigo-800 dark:bg-indigo-900 dark:text-indigo-100"
      >
        {initial}
      </span>
      <button
        type="button"
        onClick={copy}
        className="flex min-w-0 flex-1 flex-col items-start rounded-lg text-left focus-visible:outline-2 focus-visible:outline-indigo-500"
      >
        <span className="sr-only">{hidden ? t("vault.revealPrefix") : t("vault.copyPrefix")}</span>
        <span className="w-full truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
          {v.favorite ? (
            <>
              <span aria-hidden="true">★ </span>
              <span className="sr-only">{t("vault.favorite")} </span>
            </>
          ) : null}
          {title}
        </span>
        {v.issuer !== "" && v.account !== "" ? (
          <span className="w-full truncate text-xs text-slate-600 dark:text-slate-400">
            {v.account}
          </span>
        ) : null}
        <span
          className="mt-1 font-mono text-2xl font-bold tracking-wider text-indigo-700 tabular-nums dark:text-indigo-300"
          data-testid="code"
        >
          {hidden ? "••• •••" : code === null ? "…" : code === "" ? "—" : formatCode(code)}
        </span>
        {showNext && !hidden ? (
          <span className="text-xs text-slate-600 dark:text-slate-400" data-testid="next-code">
            {t("vault.next")} {formatCode(nextCode)}
          </span>
        ) : null}
      </button>
      {isTimed ? (
        <div className="flex flex-col items-center">
          <CountdownRing remaining={remaining} period={v.period} />
          <span
            className="text-xs tabular-nums text-slate-600 dark:text-slate-400"
            aria-hidden="true"
          >
            {remaining}
          </span>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => {
            onNextHotp(token.id);
          }}
          className="min-h-11 rounded-lg px-2 text-sm font-semibold text-indigo-700 hover:bg-slate-100 dark:text-indigo-300 dark:hover:bg-slate-800"
          aria-label={t("vault.nextHotp", { name: title })}
        >
          ↻
        </button>
      )}
      <button
        type="button"
        onClick={() => {
          onEdit(token.id);
        }}
        className="min-h-11 min-w-11 rounded-lg text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
        aria-label={t("vault.edit", { name: title })}
      >
        ⋯
      </button>
    </li>
  );
});
