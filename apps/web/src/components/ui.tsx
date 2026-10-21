import {
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import { t } from "../i18n";

type Variant = "primary" | "secondary" | "danger" | "ghost";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-indigo-600 text-white hover:bg-indigo-700 disabled:bg-indigo-400 dark:disabled:bg-indigo-900",
  secondary:
    "bg-white text-slate-900 ring-1 ring-slate-300 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-600 dark:hover:bg-slate-700",
  danger: "bg-red-600 text-white hover:bg-red-700 disabled:bg-red-400",
  ghost:
    "text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800 disabled:text-slate-400",
};

export function Button({
  variant = "primary",
  busy = false,
  className = "",
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  return (
    <button
      type="button"
      {...rest}
      disabled={rest.disabled === true || busy}
      aria-busy={busy}
      className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
    >
      {busy ? <Spinner /> : null}
      {children}
    </button>
  );
}

export function Spinner() {
  return (
    <span
      aria-hidden="true"
      className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent"
    />
  );
}

export function TextField({
  label,
  hint,
  error,
  className = "",
  inputClassName = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & {
  inputClassName?: string;
  label: string;
  hint?: string;
  error?: string | null;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ");
  return (
    <div className={`flex flex-col gap-1 ${className}`}>
      <label htmlFor={id} className="text-sm font-medium text-slate-800 dark:text-slate-200">
        {label}
      </label>
      <input
        id={id}
        {...rest}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy === "" ? undefined : describedBy}
        className={`min-h-11 rounded-lg border border-slate-300 bg-white px-3 py-2 text-base text-slate-900 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-2 focus:outline-indigo-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-400 ${inputClassName}`}
      />
      {hint ? (
        <p id={hintId} className="text-xs text-slate-600 dark:text-slate-400">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} className="text-sm text-red-700 dark:text-red-400">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function PasswordField(
  props: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
    label: string;
    hint?: string;
    error?: string | null;
  },
) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <TextField
        {...props}
        type={visible ? "text" : "password"}
        spellCheck={false}
        autoCapitalize="off"
        inputClassName="pr-16"
      />
      <button
        type="button"
        onClick={() => {
          setVisible((v) => !v);
        }}
        aria-label={visible ? t("common.hidePassword") : t("common.showPassword")}
        aria-pressed={visible}
        className="absolute right-2 top-7 min-h-9 rounded px-2 text-xs font-semibold text-indigo-700 hover:bg-slate-100 dark:text-indigo-300 dark:hover:bg-slate-800"
      >
        {visible ? t("common.hide") : t("common.show")}
      </button>
    </div>
  );
}

export function ErrorText({ children }: { children: ReactNode }) {
  if (children === null || children === undefined || children === "") return null;
  return (
    <p
      role="alert"
      className="rounded-lg bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200"
    >
      {children}
    </p>
  );
}

export function InfoText({ children }: { children: ReactNode }) {
  return (
    <p
      role="status"
      className="rounded-lg bg-indigo-50 p-3 text-sm text-indigo-900 dark:bg-indigo-950 dark:text-indigo-100"
    >
      {children}
    </p>
  );
}

/** Centered single-column card used by the logged-out screens. */
export function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center px-4 py-8">
      <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
        <h1 className="mb-4 text-2xl font-bold text-slate-900 dark:text-white">{title}</h1>
        {children}
      </div>
    </main>
  );
}

/** Page frame for the unlocked screens: header with an optional back button. */
export function Page({
  title,
  onBack,
  actions,
  children,
}: {
  title: string;
  onBack?: () => void;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
  }, [title]);
  return (
    <div className="mx-auto flex min-h-dvh w-full max-w-2xl flex-col">
      <header className="sticky top-0 z-10 flex items-center gap-2 border-b border-slate-200 bg-white/95 px-2 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95">
        {onBack ? (
          <Button variant="ghost" onClick={onBack} aria-label={t("common.back")}>
            ←
          </Button>
        ) : null}
        <h1
          ref={headingRef}
          tabIndex={-1}
          className="flex-1 truncate px-2 text-lg font-bold text-slate-900 outline-none dark:text-white"
        >
          {title}
        </h1>
        {actions}
      </header>
      <main className="flex-1 px-4 py-4">{children}</main>
    </div>
  );
}

/** Accessible modal built on the native <dialog> element (no injected styles; CSP-safe). */
export function Modal({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      className="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-2xl bg-white p-0 text-slate-900 shadow-xl backdrop:bg-black/50 dark:bg-slate-900 dark:text-slate-100"
    >
      {open ? (
        <div className="flex flex-col gap-4 p-6">
          <h2 id={titleId} className="text-lg font-bold">
            {title}
          </h2>
          {children}
        </div>
      ) : null}
    </dialog>
  );
}
