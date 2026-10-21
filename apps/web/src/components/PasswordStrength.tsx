import { useEffect, useState } from "react";
import { t } from "../i18n";
import { loadStrengthChecker, type Strength } from "../lib/strength";

const LABELS = ["strength.0", "strength.1", "strength.2", "strength.3", "strength.4"] as const;
const COLORS = ["bg-red-600", "bg-red-600", "bg-amber-500", "bg-emerald-600", "bg-emerald-700"];

export function usePasswordStrength(password: string, inputs: string[]): Strength | null {
  const [result, setResult] = useState<Strength | null>(null);
  const joined = inputs.join("\u0000");
  useEffect(() => {
    let cancelled = false;
    if (password === "") {
      setResult(null);
      return;
    }
    void loadStrengthChecker().then((check) => {
      if (!cancelled) setResult(check(password, joined.split("\u0000")));
    });
    return () => {
      cancelled = true;
    };
  }, [password, joined]);
  return result;
}

export function PasswordStrengthMeter({ strength }: { strength: Strength | null }) {
  const score = strength?.score ?? 0;
  return (
    <div className="flex flex-col gap-1" aria-live="polite">
      <div className="flex gap-1" aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`h-1.5 flex-1 rounded ${strength && score > i ? (COLORS[score] ?? "") : "bg-slate-200 dark:bg-slate-700"}`}
          />
        ))}
      </div>
      <p className="text-xs text-slate-700 dark:text-slate-300">
        {strength ? t(LABELS[score]) : t("strength.empty")}
        {strength?.warning ? ` ${strength.warning}` : ""}
      </p>
    </div>
  );
}
