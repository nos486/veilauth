export interface Strength {
  /** 0 (weakest) to 4 */
  score: 0 | 1 | 2 | 3 | 4;
  /** a zxcvbn suggestion key, if any */
  warning: string;
}

/** Minimum zxcvbn score for a master password. */
export const MIN_SCORE = 3;
export const MIN_LENGTH = 10;

let loader: Promise<(pw: string, inputs: string[]) => Strength> | null = null;

/** Loads zxcvbn-ts (large dictionaries) only when the sign-up screen needs it. */
export function loadStrengthChecker(): Promise<(pw: string, inputs: string[]) => Strength> {
  loader ??= (async () => {
    const [{ ZxcvbnFactory }, common, en] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]);
    const zxcvbn = new ZxcvbnFactory({
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
      translations: en.translations,
    });
    return (pw: string, inputs: string[]) => {
      const r = zxcvbn.check(pw, inputs);
      return { score: r.score, warning: r.feedback.warning ?? "" };
    };
  })();
  return loader;
}
