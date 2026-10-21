// -----------------------------------------------------------------
// Argument parsing — a module of its own, with NO host imports
// -----------------------------------------------------------------
//
// This was carved out of `index.ts` because a unit test imported it and `index.ts` pulls in
// `tools.ts`, which pulls in the host SDK (`@earendil-works/pi-coding-agent`). That module is provided
// BY THE RUNNING HOST and is absent from an installed checkout's node_modules, so the test passed in
// the development tree and failed in the clone — a test that needs the host runtime is not a test of
// this code. Parsing `/loopsec` arguments needs nothing but string handling.

/**
 * Parse `"quoted text" key=value key="quoted value"` into a positional list
 * plus a flag map.
 *
 * Written by hand rather than with a dependency because the grammar has to
 * tolerate an ASSERTION as the positional argument — full of quotes, colons,
 * parentheses and arrows — and a generic CLI parser would mangle it.
 */
export function parseArgs(input: string): {
  positional: string[];
  flags: Record<string, string>;
  /**
   * Every token EXACTLY as written, in order.
   *
   * `positional` throws the exact text of a flag away (`focus=rce` becomes key + value), so a caller
   * that wants a free-text TAIL cannot rebuild it at all — the words are simply not there. `deep`
   * needs exactly that: its trailing sentence is the operator's own, and must survive a
   * `word=value` in the middle of it.
   */
  tokens: string[];
} {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  const tokens: string[] = [];
  let i = 0;
  const text = input ?? "";

  const readToken = (stopAtEquals: boolean): string => {
    let out = "";
    while (i < text.length) {
      const ch = text[i]!;
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i++;
        while (i < text.length && text[i] !== quote) {
          if (text[i] === "\\" && i + 1 < text.length) i++;
          out += text[i]!;
          i++;
        }
        i++; // closing quote
        continue;
      }
      if (stopAtEquals && ch === "=") break;
      if (!stopAtEquals && /\s/.test(ch)) break;
      if (stopAtEquals && /\s/.test(ch)) break;
      out += ch;
      i++;
    }
    return out;
  };

  while (i < text.length) {
    while (i < text.length && /\s/.test(text[i]!)) i++;
    if (i >= text.length) break;

    const tokenStart = i;
    // Look ahead for `key=` at the current token start.
    const keyMatch = /^([A-Za-z][A-Za-z0-9_-]*)=/.exec(text.slice(i));
    if (keyMatch) {
      const key = keyMatch[1]!;
      i += keyMatch[0].length;
      flags[key] = readToken(true);
      tokens.push(text.slice(tokenStart, i));
      continue;
    }
    const token = readToken(false);
    if (token) {
      positional.push(token);
      tokens.push(text.slice(tokenStart, i));
    }
  }
  return { positional, flags, tokens };
}

/**
 * The trailing free text of a command, exactly as the operator typed it.
 *
 * Skips up to and including the command word plus `skipAfter` further tokens (the finding id), then
 * returns the raw tokens. Built from `tokens`, not `positional`, so a `word=value` in the sentence is
 * not eaten as a flag and a quoted phrase keeps its words in order.
 */
export function tailAfterVerb(tokens: readonly string[], verb: string, skipAfter = 1): string[] {
  const bare = (s: string): string => s.replace(/^["']|["']$/g, "");
  let at = -1;
  for (let k = 0; k < tokens.length; k++) {
    if (bare(tokens[k]!).toLowerCase() === verb.toLowerCase()) {
      at = k;
      break;
    }
  }
  if (at < 0) return [];
  return tokens.slice(at + 1 + skipAfter);
}

/** Wrap a value in quotes for a round-trip through `parseArgs` (used in the
 * error messages that show the exact command to retype). */
function quote(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`;
}
