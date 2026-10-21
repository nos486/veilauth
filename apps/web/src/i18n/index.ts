import en from "./en.json";

/** UI strings live in JSON resource files so more languages can be added without code changes. */
export type StringKey = keyof typeof en;

const strings: Record<StringKey, string> = en;

export function t(key: StringKey, vars?: Record<string, string | number>): string {
  const template = strings[key];
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match: string, name: string) => {
    const v = vars[name];
    return v === undefined ? match : String(v);
  });
}

export function hasString(key: string): key is StringKey {
  return Object.prototype.hasOwnProperty.call(strings, key);
}
