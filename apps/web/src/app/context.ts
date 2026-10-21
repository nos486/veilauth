import { createContext, useContext } from "react";
import type { VaultController } from "./controller";

export const ControllerContext = createContext<VaultController | null>(null);

export function useController(): VaultController {
  const c = useContext(ControllerContext);
  if (!c) throw new Error("ControllerContext missing");
  return c;
}
