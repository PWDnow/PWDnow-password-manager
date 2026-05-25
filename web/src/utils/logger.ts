// Unified logger utility
const DEV = import.meta.env.DEV;

export const logger = {
  debug: (...a: unknown[]) => { if (DEV) console.debug(...a); },
  log:   (...a: unknown[]) => { if (DEV) console.log(...a); },
  warn:  (...a: unknown[]) => { if (DEV) console.warn(...a); },
  error: (...a: unknown[]) => { console.error(...a); },
};
