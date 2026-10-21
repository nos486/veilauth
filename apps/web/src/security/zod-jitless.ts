import { config } from "zod";

// Zod probes `new Function` to choose a faster parser. The CSP forbids eval, so turn the probe off
// before any schema module is evaluated (this module is imported first by main.tsx).
config({ jitless: true });
