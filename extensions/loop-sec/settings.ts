/**
 * pi-audit-loopsec — extensions/loop-sec/settings.ts
 *
 * Project-level settings, at `<project>/.pi-hypothesis/settings.json`.
 *
 * -----------------------------------------------------------------------
 * Why there is a consent gate here at all
 * -----------------------------------------------------------------------
 *
 * Stage 3 adds a `command` probe: the executor can run a bounded shell command
 * and capture its output as evidence. That is what makes "run the test suite"
 * and "send the request" possible — and it is also the only probe that can
 * change the world.
 *
 * So it is OFF by default, and the switch lives in a file only the HUMAN can
 * write: the `/loopsec config` command writes it, and no agent tool exposes
 * it. An agent cannot authorize itself to run commands; the user grants that
 * once, deliberately. The read-only probes (reading a location, grepping) need
 * no gate because they cannot mutate anything.
 *
 * -----------------------------------------------------------------------
 * Write discipline
 * -----------------------------------------------------------------------
 *
 * A settings file is small, single-valued, and user-controlled, so it is
 * written in place with `writeFileSync` — NOT via temp-file + rename, which is
 * the exFAT hazard the store avoids (see store.ts). A crash mid-write leaves a
 * truncated JSON document, which the reader treats as "unreadable → defaults",
 * so the failure mode is a lost preference rather than a broken project.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { REPORT_LANGUAGES, type ReportLanguage, isReportLanguage } from "./reportText.js";

import { STATE_DIR_NAME, secBaseDir, secStateDir } from "./store.js";

export const SETTINGS_NAME = "settings.json";

export interface HypothesisSettings {
  /**
   * Consent gate for `command` probes. FALSE by default.
   *
   * Read-only probes are unaffected: they run whether or not this is set.
   */
  allowCommandProbes: boolean;
  /** Hard ceiling for one command probe, in milliseconds. */
  commandTimeoutMs: number;
  /** Hard cap on captured output per probe (characters, after truncation). */
  maxOutputChars: number;
  /** Hard cap on grep matches returned. */
  maxGrepMatches: number;
  /** Lines of context captured around a location probe. */
  locationContext: number;
  /** Hard cap on how many files a grep probe will open. */
  maxFilesScanned: number;
  /** Hard cap on the size of one file a probe will read (bytes). */
  maxFileBytes: number;
  /** Hard cap on the total lines a grep probe will examine. */
  maxLinesScanned: number;
  /**
   * Paragraphs per recon segment (stage 6).
   *
   * The design calls for 3–5 and the value is clamped to that range: below 3 a
   * segment is too thin to carry an attack surface, above 5 it spans several
   * unrelated parts of the project and the hypotheses it produces drift.
   */
  reconSegmentParagraphs: number;
  /**
   * Rounds spent PURSUING each high-or-worse confirmed finding for depth.
   *
   * 0 disables the pursue round entirely. The default is 2 because depth is the
   * expensive round: it is the one that does not advance the breadth-first sweep,
   * so it is budgeted per finding rather than run until the tree runs out.
   *
   * A pursue round that produces no new hypothesis closes the pursuit there, so
   * this is a ceiling, not a quota.
   */
  pursueRounds: number;
  /**
   * How many PURSUIT rounds one finding's blockers may cost.
   *
   * A finding that is REAL but GATED is the most valuable thing a run can hold — closing the gate
   * converts it into the objective — so the loop attacks its precondition BEFORE going back to the
   * work list. This is the budget that stops that from becoming a way to sit on one finding for the
   * rest of the run: past it the finding is left as a near miss, with the reason recorded, and the
   * loop returns to the plan.
   *
   * Distinct from `pursueRounds` (which is the DEPTH budget for one surface item): they bound two
   * different axes — a place versus a finding's precondition — and an operator may well want more
   * of one than the other.
   */
  pursuitRounds: number;
  /**
   * How many RECON rounds the run takes before it starts enumerating.
   *
   * One round was the original design and it was one model turn: on a 4,000-file project that
   * is a SAMPLE, and everything downstream is bounded by what the sample noticed — the
   * surface list, every analyze round, and the report's coverage section. Two rounds buys the
   * thing one round cannot: the first maps the project, the second reads the REQUEST LIFECYCLE
   * (entry → middleware/auth → handler → data layer) and the auth wiring, which is what
   * pre-auth findings actually turn on. Higher values spend more rounds on understanding
   * (3 = also build a sink catalogue for the objective's class).
   *
   * The notes are APPEND-ONLY, so more rounds can only WIDEN the run's ceiling — a later
   * section can add the part the first pass missed, and can never shrink what was already
   * recorded.
   */
  reconRounds: number;
  /**
   * The language of the REPORT's own scaffolding.
   *
   * Only the scaffolding: the headings, the labels, the method section. The
   * findings themselves are the model's words and are recorded verbatim in
   * whatever language it wrote them — see reportText.ts for why translating
   * those would launder the evidence. This setting ALSO drives the instruction
   * in the round brief that tells the model which language to write in, because
   * a Chinese report full of English assertions is not a Chinese report.
   */
  reportLanguage: ReportLanguage;
  /**
   * The language tag a code fence in the REPORT opens with. `"c"` by default.
   *
   * The audit targets this was built for are mostly C, and a fence with no tag gets no
   * highlighting in any viewer — so the default is the language the code is usually in
   * rather than nothing.
   *
   * It applies to the CONTENT fences: the artifact, the PoC and the call chain. An empty
   * string turns the tag off. It is one setting rather than one per fence because a
   * reader who wants highlighting wants it everywhere, and because a report whose
   * evidence block is tagged and whose PoC block is not looks like a bug.
   *
   * A tag is a HINT to the viewer, never a claim about the file: the evidence may be
   * Java, XML or a shell transcript, and tagging it `c` costs nothing but the wrong
   * colour on a few tokens.
   */
  fenceLanguage: string;
}

export const DEFAULT_SETTINGS: HypothesisSettings = {
  allowCommandProbes: false,
  commandTimeoutMs: 120_000,
  maxOutputChars: 8_000,
  maxGrepMatches: 50,
  locationContext: 6,
  maxFilesScanned: 4_000,
  maxFileBytes: 2_000_000,
  maxLinesScanned: 400_000,
  reconSegmentParagraphs: 4,
  pursueRounds: 2,
  // THREE, not two. The gate that was actually cracked on a real run needed three moves: re-check
  // the premise (the "sandbox" was not a sandbox), enumerate alternative entries, then find that the
  // guard and the handler read different parameter sources. Two rounds is enough to look, not enough
  // to break. The model can always close early with `pursuitClosed` once it concludes.
  pursuitRounds: 3,
  reconRounds: 2,
  // zh by default: this extension's operating instructions are Chinese-first,
  // and a report nobody on the team can read is not a deliverable.
  reportLanguage: "zh",
  // Most audit targets are C; a bare fence gets no highlighting at all.
  fenceLanguage: "c",
};

/**
 * Directory names a probe never descends into.
 *
 * `.pi-hypothesis` and `.pi-loopsec` are excluded because probing the audit's own
 * state would let a hypothesis "find" its own record and self-confirm — the tree
 * would become evidence for itself.
 */
export const PROBE_SKIP_DIRS: readonly string[] = [
  // VCS and this extension's own state
  ".git",
  ".pi-hypothesis",
  ".pi-loopsec",
  // JavaScript / TypeScript
  "node_modules",
  "bower_components",
  ".next",
  ".nuxt",
  "dist",
  "build",
  "out",
  "coverage",
  ".cache",
  // PHP (Composer) and Go
  "vendor",
  // JVM
  "target",
  ".gradle",
  ".mvn",
  // Python
  ".venv",
  "venv",
  "env",
  "__pycache__",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  // Apple / Rust / .NET / Terraform
  "Pods",
  ".cargo",
  "obj",
  ".terraform",
  ".stack-work",
];

/**
 * Why `vendor` and friends are in the list, in one line:
 *
 * Field report (2026-09-21, Centreon Web): the project has 7062 files under
 * `vendor/` and 6516 of its own, while the default file budget is 4000. An
 * unscoped grep therefore spent its ENTIRE budget inside dependencies and never
 * reached `src/` — so every probe looking for something in the project's own
 * code reported "absent", which reads as "the check is missing" and can confirm
 * a hypothesis that the code contradicts.
 *
 * The budget is not the bug; walking dependencies with it is. A dependency tree
 * is not the audited surface.
 */
export const PROBE_SKIP_DIRS_NOTE =
  "dependency, build and cache directories are skipped: they are not the audited surface, and walking them spends the file budget before the project's own code is reached";

export function settingsPath(projectRoot: string): string {
  // The WRITE target belongs to the ACTIVE run: a deep run's `config` must not rewrite the parent's
  // file. On the main run the old precedence still holds — an EXISTING .pi-loopsec/settings.json wins,
  // then an existing .pi-hypothesis/settings.json (a project that ran the old modes keeps its settings
  // readable), otherwise the sec path, because this extension's only writes belong beside its own
  // state and a settings save must not create a .pi-hypothesis/ in a project that never had one.
  const activeDir = secStateDir(projectRoot);
  const baseDir = secBaseDir(projectRoot);
  if (path.resolve(activeDir) !== path.resolve(baseDir)) return path.join(activeDir, SETTINGS_NAME);
  const secFile = path.join(baseDir, SETTINGS_NAME);
  try {
    if (fs.existsSync(secFile)) return secFile;
    const hypFile = path.join(projectRoot, STATE_DIR_NAME, SETTINGS_NAME);
    if (fs.existsSync(hypFile)) return hypFile;
  } catch {
    /* fall through to the sec path */
  }
  return secFile;
}

/**
 * The settings files to read, LOWEST priority first.
 *
 * A DEEP RUN OVERRIDES ITS PARENT, IT DOES NOT REPLACE IT. `deep/F-0008/settings.json` may set
 * `reconRounds: 1` and must still inherit `allowCommandProbes`, the probe timeout, the output bound and
 * the language from `.pi-loopsec/settings.json`. Reading only the first file that exists would silently
 * forbid `sec_verify` inside every deep run — a setting nobody changed and nobody could see.
 */
function settingsLayers(projectRoot: string): string[] {
  const baseDir = secBaseDir(projectRoot);
  const activeDir = secStateDir(projectRoot);
  const layers: string[] = [];
  const secBase = path.join(baseDir, SETTINGS_NAME);
  const legacy = path.join(projectRoot, STATE_DIR_NAME, SETTINGS_NAME);
  try {
    // `.pi-loopsec` wins over `.pi-hypothesis`; they are alternatives for the SAME layer, never stacked.
    if (fs.existsSync(secBase)) layers.push(secBase);
    else if (fs.existsSync(legacy)) layers.push(legacy);
  } catch {
    /* nothing readable — the defaults stand */
  }
  if (path.resolve(activeDir) !== path.resolve(baseDir)) {
    const own = path.join(activeDir, SETTINGS_NAME);
    try {
      if (fs.existsSync(own)) layers.push(own);
    } catch {
      /* the parent layer still applies */
    }
  }
  return layers;
}

export interface LoadedSettings {
  settings: HypothesisSettings;
  /** Where the values came from — so a UI can say "these are defaults". */
  source: "file" | "defaults" | "partial";
  /** Present when the file exists but could not be used. */
  error?: string;
}

/**
 * Load settings, falling back to defaults on anything unusable.
 *
 * Never throws: an unreadable or corrupt settings file must not stop an audit,
 * and silently ignoring a CORRUPT file would hide the user's intent — hence
 * `error` and `source` are reported rather than swallowed.
 */
/**
 * The report language, read from the project's settings.
 *
 * Read per call rather than cached: the operator can change it mid-run with
 * `/loopsec config reportLanguage=en`, and a report that keeps coming out in the
 * old language after that is a setting that looks broken.
 *
 * Lives here rather than in loop.ts because BOTH report writers need it —
 * `writeReport` and `writeSecReport` — and loop.ts imports sec.ts, so sec.ts cannot
 * import loop.ts back.
 */
/** The fence tag, read per call for the same reason `reportLanguageOf` is. */
export function fenceLanguageOf(projectRoot: string): string {
  try {
    return loadSettings(projectRoot).settings.fenceLanguage;
  } catch {
    return "c";
  }
}

export function reportLanguageOf(projectRoot: string): ReportLanguage {
  try {
    return loadSettings(projectRoot).settings.reportLanguage;
  } catch {
    return "zh";
  }
}

/**
 * Whether `sec_verify` is enabled — read per call, like the language.
 *
 * The report needs it because it names the same depth reasons the loop ranks with, and `unproven`
 * only exists when a probe is possible. Falls back to `false` on a settings error: under-reporting a
 * depth reason is survivable, inventing one is not.
 */
export function allowCommandProbesOf(projectRoot: string): boolean {
  try {
    return loadSettings(projectRoot).settings.allowCommandProbes === true;
  } catch {
    return false;
  }
}

/** The per-finding depth budget, so the report can print `已花 N/M 轮`. */
export function pursuitRoundsOf(projectRoot: string): number {
  try {
    return loadSettings(projectRoot).settings.pursuitRounds;
  } catch {
    return DEFAULT_SETTINGS.pursuitRounds;
  }
}

export function loadSettings(projectRoot: string): LoadedSettings {
  const files = settingsLayers(projectRoot);
  const settings = { ...DEFAULT_SETTINGS };
  let partial = false;
  let error: string | undefined;
  let applied = 0;
  for (const file of files) {
    let text: string;
    try {
      text = fs.readFileSync(file, "utf-8");
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      continue;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      error = `${file} is not valid JSON (${e instanceof Error ? e.message : String(e)})`;
      continue;
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      error = `${file} must be a JSON object`;
      continue;
    }
    applied++;
    if (applySettingsObject(raw as Record<string, unknown>, settings)) partial = true;
  }
  // A broken layer is REPORTED and the ones below it still apply: a corrupt deep-run file must not
  // take the parent's `allowCommandProbes` down with it.
  const withError = error ? { error } : {};
  if (applied === 0) return { settings: { ...DEFAULT_SETTINGS }, source: "defaults", ...withError };
  return { settings, source: partial ? "partial" : "file", ...withError };
}

/** Apply ONE settings file on top of what is already loaded. Returns true when a field was present
 *  but unusable, so the caller can report "partial" instead of pretending it was clean. */
function applySettingsObject(o: Record<string, unknown>, settings: HypothesisSettings): boolean {
  let partial = false;

  const bool = (key: keyof HypothesisSettings): void => {
    if (key in o) {
      if (typeof o[key] === "boolean") settings[key] = o[key] as never;
      else partial = true;
    }
  };
  const num = (key: keyof HypothesisSettings, min: number, max: number): void => {
    if (key in o) {
      const value = o[key];
      if (typeof value === "number" && Number.isFinite(value)) {
        settings[key] = Math.min(max, Math.max(min, Math.floor(value))) as never;
      } else {
        partial = true;
      }
    }
  };

  bool("allowCommandProbes");
  const str = (key: keyof HypothesisSettings, valid: (v: unknown) => boolean): void => {
    if (key in o) {
      if (valid(o[key])) settings[key] = o[key] as never;
      else partial = true;
    }
  };
  str("reportLanguage", isReportLanguage);
  // A language tag is a token, not free text: letters, digits, `+`, `-`, `#` and `.`
  // cover every tag a viewer understands (c, cpp, objective-c, c#, f#, sh).
  str("fenceLanguage", (v) => typeof v === "string" && /^[A-Za-z0-9+#.-]*$/.test(v));
  num("commandTimeoutMs", 1_000, 3_600_000);
  num("maxOutputChars", 200, 500_000);
  num("maxGrepMatches", 1, 5_000);
  num("locationContext", 0, 200);
  num("maxFilesScanned", 1, 200_000);
  num("maxFileBytes", 1_024, 200_000_000);
  num("maxLinesScanned", 100, 20_000_000);
  // Clamped to the design's 3–5 range rather than to an arbitrary bound.
  num("reconSegmentParagraphs", 3, 5);
  num("pursueRounds", 0, 5);
  // 0 disables the pursuit of a finding's blockers entirely (the finding is filed as a near miss).
  num("pursuitRounds", 0, 5);
  // Capped at 5: past that the rounds are re-reading, not understanding, and the plateau
  // no longer protects the run because a re-read can still add a sentence.
  num("reconRounds", 1, 5);

  return partial;
}

/**
 * Merge a patch into the settings file.
 *
 * Only the keys present in `patch` are written; the rest keep whatever the file
 * already had (or the defaults, when the file did not exist). Writing the whole
 * resolved object would silently persist defaults for keys the user never set,
 * which then look like deliberate choices.
 */
export function saveSettings(
  projectRoot: string,
  patch: Partial<HypothesisSettings>,
): { ok: boolean; errors: string[]; settings?: HypothesisSettings } {
  const errors: string[] = [];
  const validated: Partial<HypothesisSettings> = {};

  for (const [key, value] of Object.entries(patch) as [keyof HypothesisSettings, unknown][]) {
    if (!(key in DEFAULT_SETTINGS)) {
      errors.push(`unknown setting "${key}" (known: ${Object.keys(DEFAULT_SETTINGS).join(", ")})`);
      continue;
    }
    if (typeof DEFAULT_SETTINGS[key] === "boolean") {
      if (typeof value !== "boolean") errors.push(`${key} must be true or false`);
      else validated[key] = value as never;
      continue;
    }
    if (typeof DEFAULT_SETTINGS[key] === "string") {
      // Validated against the setting's OWN domain, not just "is a string": a
      // typo like "cn" would otherwise be written and then silently fall back to
      // the default on every read, which looks like the setting is being ignored.
      if (key === "reportLanguage" && !isReportLanguage(value)) {
        errors.push(`reportLanguage must be one of: ${REPORT_LANGUAGES.join(", ")}`);
      } else {
        validated[key] = value as never;
      }
      continue;
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
      errors.push(`${key} must be a number`);
      continue;
    }
    validated[key] = value as never;
  }
  if (errors.length > 0) return { ok: false, errors };

  // Re-read so unknown/extra keys already in the file are preserved verbatim.
  let existing: Record<string, unknown> = {};
  const file = settingsPath(projectRoot);
  try {
    if (fs.existsSync(file)) {
      const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf-8"));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) existing = parsed as Record<string, unknown>;
    }
  } catch {
    // A corrupt file is replaced by the patch alone; the load path already
    // reported the corruption, and refusing to write would strand the user.
  }

  const next = { ...existing, ...validated };
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // In place, no rename: the exFAT-safe choice for a small single-valued file.
    fs.writeFileSync(file, JSON.stringify(next, null, 2) + "\n", "utf-8");
  } catch (error) {
    return { ok: false, errors: [`could not write ${file}: ${error instanceof Error ? error.message : String(error)}`] };
  }

  return { ok: true, errors: [], settings: loadSettings(projectRoot).settings };
}
