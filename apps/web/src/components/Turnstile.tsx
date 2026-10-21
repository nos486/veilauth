import { useEffect, useRef } from "react";
import { t } from "../i18n";

/**
 * Cloudflare Turnstile in a same-origin frame (/turnstile, docs/DECISIONS.md D-036), so the app's
 * own CSP never needs a third-party script origin. The frame posts the token back to us.
 */
export function Turnstile({
  siteKey,
  action,
  onToken,
}: {
  siteKey: string;
  action: "register" | "login";
  onToken: (token: string | null) => void;
}) {
  const frame = useRef<HTMLIFrameElement>(null);
  const callback = useRef(onToken);
  callback.current = onToken;

  useEffect(() => {
    const listener = (event: MessageEvent<unknown>) => {
      if (event.origin !== location.origin || event.source !== frame.current?.contentWindow) return;
      const data = event.data as { type?: unknown; event?: unknown; token?: unknown } | null;
      if (data?.type !== "turnstile") return;
      if (data.event === "token" && typeof data.token === "string") callback.current(data.token);
      else callback.current(null);
    };
    window.addEventListener("message", listener);
    return () => {
      window.removeEventListener("message", listener);
    };
  }, []);

  const src = `/turnstile#${new URLSearchParams({ sitekey: siteKey, action }).toString()}`;
  return (
    <iframe
      ref={frame}
      src={src}
      title={t("turnstile.title")}
      className="h-[70px] w-[300px] max-w-full border-0"
    />
  );
}
