import { useEffect, useState } from "react";
import { serverNow } from "./lib/time";

/** Server-corrected time, ticking once per second. */
export function useNow(): number {
  const [now, setNow] = useState(serverNow);
  useEffect(() => {
    const id = setInterval(() => {
      setNow(serverNow());
    }, 1000);
    return () => {
      clearInterval(id);
    };
  }, []);
  return now;
}
