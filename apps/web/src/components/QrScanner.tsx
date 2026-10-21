import { useEffect, useRef, useState } from "react";
import { t } from "../i18n";
import { decodeQrPixels } from "../lib/qr";

const SCAN_INTERVAL_MS = 200;

/** Camera preview that scans for QR codes with getUserMedia + jsQR. Stops the camera on unmount. */
export function QrScanner({ onResult }: { onResult: (text: string) => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const [error, setError] = useState<string | null>(null);
  const callback = useRef(onResult);
  callback.current = onResult;

  useEffect(() => {
    let stream: MediaStream | null = null;
    let timer: ReturnType<typeof setInterval> | undefined;
    let stopped = false;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const start = async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment" },
          audio: false,
        });
      } catch (e: unknown) {
        if (e instanceof DOMException || e instanceof TypeError) {
          setError(t("scan.cameraUnavailable"));
          return;
        }
        throw e;
      }
      if (stopped) {
        stream.getTracks().forEach((tr) => {
          tr.stop();
        });
        return;
      }
      const v = video.current;
      if (!v || !ctx) return;
      v.srcObject = stream;
      await v.play();
      timer = setInterval(() => {
        if (v.readyState < v.HAVE_ENOUGH_DATA || v.videoWidth === 0) return;
        canvas.width = v.videoWidth;
        canvas.height = v.videoHeight;
        ctx.drawImage(v, 0, 0);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const text = decodeQrPixels(img.data, img.width, img.height);
        if (text !== null) {
          if ("vibrate" in navigator) navigator.vibrate(50);
          callback.current(text);
        }
      }, SCAN_INTERVAL_MS);
    };
    void start();
    return () => {
      stopped = true;
      clearInterval(timer);
      stream?.getTracks().forEach((tr) => {
        tr.stop();
      });
    };
  }, []);

  if (error)
    return (
      <p role="alert" className="text-sm text-red-700 dark:text-red-400">
        {error}
      </p>
    );
  return (
    <div className="relative overflow-hidden rounded-xl bg-black">
      <video
        ref={video}
        muted
        playsInline
        className="aspect-square w-full object-cover"
        aria-label={t("scan.preview")}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-[15%] rounded-2xl border-4 border-white/80"
      />
    </div>
  );
}
