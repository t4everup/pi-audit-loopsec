/**
 * pi-audit-loopsec — extensions/loop-sec/sec.ts
 *
 * `/loopsec` — give an objective, dig, get a report.
 *
 * -----------------------------------------------------------------------
 * What this mode is, and what it deliberately is not
 * -----------------------------------------------------------------------
 *
 * The hypothesis tree exists to make an audit's output TRUSTWORTHY. Every node is
 * an assertion that can be proven wrong, a verdict requires a quotable artifact, a
 * derived tier says how strong that artifact is, a challenge round attacks the
 * finding afterwards, and a refuted finding leaves the report. All of that is load
 * on every round, and it is load the operator may not want for a first pass over a
 * large codebase.
 *
 * So this mode drops it. There is no assertion gate, no verdict, no tier, no
 * falsification attempt and no challenge round — none of those can exist without
 * an assertion to attack, and a report that claimed them here would be claiming
 * discipline it does not have.
 *
 * ONE REQUIREMENT SURVIVES: a finding must carry an artifact — a `location`, an
 * `evidence` excerpt, or both. The bar is cheap (the model is reading the code, so
 * it has a `file:line`), and it is the entire difference between a triage report
 * and a list of things a model said. `validateFinding` refuses a finding with
 * neither, and `store.ts` drops one on read as well, so a hand-edited log cannot
 * put a bare claim back.
 *
 * The report therefore LEADS with what it is not. A reader who skims a list of
 * findings grouped by severity will assume the severities were checked; the report
 * says, before the first finding, that they were not.
 *
 * -----------------------------------------------------------------------
 * Where the breadth comes from, without hypotheses
 * -----------------------------------------------------------------------
 *
 * The hypothesis mode gets its breadth from recon segments: the note is chunked and
 * every chunk becomes a generation round. A dig round does not generate from a
 * segment, so this mode needs another mechanism — and it uses the one that was
 * already there and measured: **what has not been read yet**.
 *
 * `coverage.ts` computes the untouched subtrees from the files a run has cited.
 * Here the citations come from the findings instead of from hypothesis nodes, and
 * the dig brief hands the model the gap. That is the same adaptive gap the coverage
 * round uses, and it is why a `/loopsec` run gets wider as it goes rather than
 * re-reading whatever it found first.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

import { SEC_STATE_DIR_NAME, appendSecEvent, loadSec, nowIso, secStateDir } from "./store.js";
import { type Result } from "./types.js";
import { coverageGaps, coverageHeadline, type CoverageReport } from "./coverage.js";
import { allowCommandProbesOf, fenceLanguageOf, loadSettings, pursuitRoundsOf, reportLanguageOf } from "./settings.js";
import { ladderFor } from "./ladders.js";
import {
  type ReportLanguage,
  type SecStrings,
  secStrings,
  severityLabel,
} from "./reportText.js";
import {
  type AuditLoopState,
  type SecFinding,
  type SecFindingPatch,
  type SecFindingStep,
  type SecSurface,
  type SecSurfaceKind,
  type SecSurfacePatch,
  type SecVerification,
  type SecVerifyInput,
  type Severity,
  type TreeSnapshot,
  SEC_SURFACE_KINDS,
  SEVERITIES,
  formatDuration,
  loopTiming,
  severityRank,
} from "./types.js";

/**
 * Depth rounds one item may be given, on top of the round that examined it.
 *
 * Two, matching the hypothesis mode's `pursueRounds` default and for the same reason:
 * depth is the expensive round, so it is BUDGETED rather than run until the model runs out
 * of ideas. Without it, `digging` is a way to sit on one item for the rest of the run —
 * which is the failure it exists to prevent.
 */
export const SEC_DIG_BUDGET = 2;

/**
 * Soft ceiling on the work list, and SOFT is the whole design.
 *
 * A list of 200 items is 200 rounds, and every one of them is "productive" because it
 * examines something — so the plateau never fires and the run goes quiet for hours with no
 * warning. Measured: the share of rounds spent enumerating is 1/(k+1) for a sweep of k items,
 * so the cost is not the cap, it is the COMMITMENT the cap bounds.
 *
 * It does not REFUSE, because refusing the item the model just found loses information —
 * and an item it cannot record is an item the run will never come back to. It warns, says
 * what to do instead, and keeps the item.
 */
export const SEC_SURFACE_SOFT_CAP = 60;

/**
 * How many rounds one item may be handed before it drops to the back of the queue.
 *
 * Measured failure this closes: a round that reads an item and records NOTHING — no finding,
 * no clearance, no dig — leaves the item `open` with no priority, so the very next round was
 * handed the SAME item again. Repeating that burned the whole plateau window (8 unproductive
 * rounds by default) on one item while the other nineteen waited — the run stopped with
 * exactly one place examined.
 *
 * It is not a refusal: an item past the budget is DEPRIORITISED (rank -1, so it runs last),
 * stays in the report, and can still be reached by promoting it (`sec_update <id> priority=1`)
 * or by digging on it (`sec_dig`) when the model believes it is close. Throwing it away would
 * lose the very place the model was working on.
 */
export const MAX_ITEM_ATTEMPTS = 3;

/** The sec report's file name. Distinct from REPORT.md so the two modes coexist. */
export const SEC_REPORT_FILE = "SEC-REPORT.md";
/** The running journal, one section per round. */
export const SEC_LEDGER_FILE = "SEC-FINDINGS.md";

export function secReportPath(projectRoot: string): string {
  return path.join(secStateDir(projectRoot), SEC_REPORT_FILE);
}

export function secLedgerPath(projectRoot: string): string {
  return path.join(secStateDir(projectRoot), SEC_LEDGER_FILE);
}

// -----------------------------------------------------------------
// Recording
// -----------------------------------------------------------------

export interface FindingInput {
  title: string;
  category: string;
  severity?: Severity;
  preAuth?: boolean;
  file?: string;
  line?: number;
  evidence?: string;
  reasoning?: string;
  poc?: string;
  round?: number;
  /** The surface item this came out of. */
  surfaceId?: string;
  /** The call chain, one step per hop. */
  path?: SecFindingStep[];
  /** The findings this one combines. Two or more, all of which must already exist. */
  chainOf?: string[];
  /**
   * What must hold for this to be exploitable as recorded. See `SecFinding.blockers`.
   *
   * Recording a gated finding is the point: the loop then attacks the gate instead of moving to
   * the next surface item.
   */
  blockers?: string[];
  /**
   * There is MORE HERE — the loop should deepen this finding. See `SecFinding.deepen`.
   *
   * The general form of "a breakthrough happened": a gate is one reason to keep going, and this is
   * how the model says so for every other reason it can see and the plugin cannot.
   */
  deepen?: boolean;
}

/**
 * The one gate this mode keeps, and why it is not negotiable.
 *
 * Everything else about `/loopsec` is free-form, but a finding with no artifact is
 * not a finding — it is a sentence. The cost of the requirement is a `file:line`
 * the model already has in hand, and the benefit is that every line of the report
 * can be opened and checked by the reader. A mode that dropped this too would
 * produce a document that looks like a security assessment and cannot be verified
 * at all.
 */
export function validateFinding(input: FindingInput): Result<FindingInput> {
  const errors: string[] = [];
  if (typeof input.title !== "string" || input.title.trim() === "") {
    errors.push("title is required — say what the finding is");
  }
  const hasLocation = typeof input.file === "string" && input.file.trim() !== "";
  const hasEvidence = typeof input.evidence === "string" && input.evidence.trim() !== "";
  const chain = input.chainOf ?? [];
  if (chain.length === 1) {
    errors.push(
      "`chainOf` needs TWO OR MORE findings — a chain of one is just that finding. Say which other " +
        "finding this one combines with, and what the two reach together that neither reaches alone.",
    );
  }
  if (chain.length > 0 && new Set(chain).size !== chain.length) {
    errors.push("`chainOf` repeats an id — a chain is a set of distinct findings");
  }
  // A CHAIN IS ITS OWN ARTIFACT. Its parts each carry one, and demanding a third for
  // the combination would push the model to attach something unrelated just to get past
  // the check — which is worse than the check is worth.
  if (!hasLocation && !hasEvidence && chain.length < 2) {
    errors.push(
      "a finding needs an artifact: a `file` (with `line`) or an `evidence` excerpt. " +
        "This mode has no assertion gate and no verification tier, so the artifact is the ONLY thing " +
        "a reader can check — without it the report is a list of sentences. " +
        "(A finding with `chainOf` naming two or more existing findings is exempt: its artifact IS its parts.)",
    );
  }
  if (hasLocation && (typeof input.line !== "number" || !Number.isFinite(input.line) || input.line < 1)) {
    errors.push("`line` must be a 1-based line number when `file` is given");
  }
  if (typeof input.category !== "string" || input.category.trim() === "") {
    errors.push("category is required (free-form here, but it is how the report groups findings)");
  }
  // BLOCKERS ARE STATES OF THE WORLD, and a blank one is not a state. Capped at 6 because a finding
  // gated by more than six independent things is not one finding — it is a description of the
  // deployment, and the loop would spend its whole pursuit budget reading it.
  const blockers = input.blockers ?? [];
  if (blockers.some((b) => typeof b !== "string" || b.trim() === "")) {
    errors.push("every `blockers` entry must be a non-empty state of the world (e.g. \"需要一个有效的管理员会话\")");
  }
  if (blockers.length > 6) {
    errors.push(`\`blockers\` has ${blockers.length} entries — a finding gated by more than six independent things is not one finding. Name the one that matters most.`);
  }
  return errors.length === 0 ? { ok: true, value: input, warnings: [] } : { ok: false, errors };
}

/** Next free `F-####` id. */
function nextFindingId(snapshot: TreeSnapshot): string {
  let max = 0;
  for (const f of snapshot.findings) {
    const m = /^F-(\d+)$/.exec(f.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `F-${String(max + 1).padStart(4, "0")}`;
}

export function recordFinding(projectRoot: string, input: FindingInput, at = nowIso()): Result<SecFinding> {
  const check = validateFinding(input);
  if (!check.ok) return { ok: false, errors: check.errors };
  const snapshot = loadSec(projectRoot).snapshot;
  // SINK DEDUPLICATION. Two findings at the same file:line are almost always the same
  // bug found twice under different titles — and a report that counts it twice inflates
  // the severity distribution exactly where it matters. A different CATEGORY at the same
  // location is a real second finding (a traversal into an exec is two bugs); same
  // category is a duplicate, returned with a pointer to sec_update instead.
  if (input.file && typeof input.line === "number") {
    const loc = { file: input.file, line: Math.max(1, Math.floor(input.line)) };
    const dupe = snapshot.findings.find(
      (f) => f.location && f.location.file === loc.file && f.location.line === loc.line && f.category === input.category.trim(),
    );
    if (dupe) {
      // THE DEDUP MUST NOT UNDO THE SURFACE ITEM. This call may have come from a DIFFERENT
      // surface item reaching the same sink (two routes into one exec) — recording the finding
      // again is a duplicate, but the item the model just analysed still needs to be marked
      // examined, or the next round hands the same sink back and the model analyses it again.
      // (Measured: S-0002 stayed `open` after its round produced a duplicate, and was
      // re-assigned immediately.)
      if (input.surfaceId && snapshot.surfaces.some((x) => x.id === input.surfaceId)) {
        updateSurface(projectRoot, input.surfaceId, { status: "examined", findingId: dupe.id }, at);
      }
      return {
        ok: true,
        value: dupe,
        warnings: [
          `already recorded as ${dupe.id} — same sink (${loc.file}:${loc.line}) and category (${input.category}).`,
          `To retitle, re-grade or add a PoC, use sec_update ${dupe.id} — do not record it again.`,
        ],
      };
    }
  }
  // Every id in `chainOf` must be a finding this run already has — the same bar the
  // hypothesis mode sets by refusing a `spawnedFrom` that names anything unconfirmed.
  // Without it a chain could cite ids that do not exist and the report would print a
  // combination of nothing.
  const chain = input.chainOf ?? [];
  const known = new Set(snapshot.findings.map((f) => f.id));
  const unknown = chain.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    const available = snapshot.findings.map((f) => `${f.id} (${clip(f.title, 50)})`).join("; ") || "(none yet)";
    return {
      ok: false,
      errors: [
        `chainOf names ${unknown.join(", ")}, which this run has not recorded. A chain must be built from ` +
          `findings that exist — record them first.\n  Known findings: ${available}`,
      ],
    };
  }
  const finding: SecFinding = {
    id: nextFindingId(snapshot),
    at,
    round: typeof input.round === "number" && input.round > 0 ? input.round : snapshot.rounds,
    title: input.title.trim(),
    category: input.category.trim(),
    ...(input.severity ? { severity: input.severity } : {}),
    ...(typeof input.preAuth === "boolean" ? { preAuth: input.preAuth } : {}),
    ...(typeof input.file === "string" && input.file
      ? { location: { file: input.file, line: typeof input.line === "number" ? Math.max(1, Math.floor(input.line)) : 1 } }
      : {}),
    ...(typeof input.evidence === "string" && input.evidence ? { evidence: input.evidence } : {}),
    ...(typeof input.reasoning === "string" && input.reasoning ? { reasoning: input.reasoning } : {}),
    ...(typeof input.poc === "string" && input.poc ? { poc: input.poc } : {}),
    ...(input.surfaceId ? { surfaceId: input.surfaceId } : {}),
    ...(input.path && input.path.length > 0 ? { path: input.path } : {}),
    ...(chain.length >= 2 ? { chainOf: [...chain] } : {}),
    ...((input.blockers ?? []).length > 0 ? { blockers: input.blockers!.map((b) => b.trim()) } : {}),
    ...(input.deepen === true ? { deepen: true } : {}),
  };
  if (!appendSecEvent(projectRoot, { type: "finding_recorded", at, finding })) {
    return { ok: false, errors: ["the finding could not be written to the log"] };
  }
  // A finding recorded against a surface item EXAMINES that item. Without this the
  // item stayed `open`, so the next round was handed the same one and the model was
  // asked to analyse a thing it had just found a bug in.
  if (input.surfaceId && snapshot.surfaces.some((x) => x.id === input.surfaceId)) {
    updateSurface(projectRoot, input.surfaceId, { status: "examined", findingId: finding.id }, at);
  }
  return { ok: true, value: finding, warnings: [] };
}

export function updateFinding(projectRoot: string, id: string, patch: SecFindingPatch, at = nowIso()): Result<SecFinding> {
  const snapshot = loadSec(projectRoot).snapshot;
  const existing = snapshot.findings.find((f) => f.id === id);
  if (!existing) return { ok: false, errors: [`${id} is not a finding in this run`] };
  // The artifact requirement holds on UPDATE too, or a patch could erase the only thing a
  // reader can check. A CHAIN is the one exception, and it is the same exception everywhere
  // else in this mode: a finding with two or more chainOf ids has no artifact OF ITS OWN —
  // its artifact is its parts, each of which carries one. This check used to ignore that,
  // which made a chain finding impossible to VERIFY: the run happened, the refusal fired,
  // and the evidence of the run was thrown away.
  const location = patch.location ?? existing.location;
  const evidence = patch.evidence ?? existing.evidence;
  const chainArtifact = (existing.chainOf?.length ?? 0) >= 2 || (patch.chainOf?.length ?? 0) >= 2;
  if (!location && !evidence && !chainArtifact) {
    return { ok: false, errors: [`${id} would be left with no artifact — a finding needs a location, an evidence excerpt, or a chain of two or more recorded findings`] };
  }
  if (!appendSecEvent(projectRoot, { type: "finding_updated", at, id, patch })) {
    return { ok: false, errors: ["the update could not be written to the log"] };
  }
  const after = loadSec(projectRoot).snapshot.findings.find((f) => f.id === id)!;
  return { ok: true, value: after, warnings: [] };
}

/**
 * Run something and record what it produced against a finding.
 *
 * THIS IS THE ONLY THING IN THIS MODE THAT TOUCHES ANYTHING OUTSIDE THE SOURCE TREE, so it is
 * the only thing that needs a gate. Three rules, and each exists for a failure this project
 * has already seen:
 *
 *   1. CONSENT FIRST. `allowCommandProbes` defaults to false, and the refusal names the exact
 *      setting that turns it on. A mode that could send requests to a live target without the
 *      operator saying so is not a triage tool, it is a scanner nobody asked for.
 *
 *   2. THE EXPECTATION IS STATED BEFORE THE RUN. `expect` is required, and `confirmed` is
 *      COMPUTED from the exit code and the output substring — never taken from the caller's
 *      opinion of what the output means. A run that comes back 0 when the author predicted a
 *      refusal is recorded as a DISCONFIRMATION, and the report says so.
 *
 *   3. BOUNDED. Timeout and output cap come from settings; a hung request is killed rather
 *      than allowed to hold the round.
 *
 * What it buys: the report can distinguish a sink somebody READ from a request that CAME
 * BACK. That distinction is the difference between a triage list and a weapon.
 */
export function verifyFinding(
  projectRoot: string,
  id: string,
  input: SecVerifyInput,
  at = nowIso(),
): Result<SecVerification> {
  const snapshot = loadSec(projectRoot).snapshot;
  const finding = snapshot.findings.find((f) => f.id === id);
  if (!finding) {
    const known = snapshot.findings.map((f) => f.id).join(", ") || "(none yet)";
    return { ok: false, errors: [`${id} is not a finding in this run. Known findings: ${known}`] };
  }
  const command = (input.command ?? "").trim();
  if (!command) {
    return { ok: false, errors: ["`command` is required — say exactly what to run, so the reader can re-run it"] };
  }
  const expect = (input.expect ?? "").trim();
  if (!expect) {
    return {
      ok: false,
      errors: [
        "`expect` is required and must be stated BEFORE the run — 'what do you predict this shows?'.",
        "Without it there is nothing for the result to be confirmed AGAINST, and the record is just a transcript.",
      ],
    };
  }
  const settings = loadSettings(projectRoot).settings;
  if (!settings.allowCommandProbes) {
    return {
      ok: false,
      errors: [
        "running commands is OFF for this project, so nothing was executed.",
        "Turn it on first:  /loopsec config allowCommandProbes=true",
        "(It is `allowCommandProbes` in the project's settings.json under .pi-loopsec/ — or .pi-hypothesis/ for a pre-migration run.)",
      ],
    };
  }

  let output = "";
  let exitCode: number | null = null;
  let timedOut = false;
  try {
    const run = spawnSync(command, {
      shell: true,
      cwd: projectRoot,
      timeout: settings.commandTimeoutMs,
      maxBuffer: Math.max(64_000, settings.maxOutputChars * 8),
      encoding: "utf-8",
    });
    output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    exitCode = typeof run.status === "number" ? run.status : null;
    timedOut = (run.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
  } catch (error) {
    return { ok: false, errors: [`the command could not be run: ${(error as Error).message}`] };
  }

  const clipped = output.length > settings.maxOutputChars ? `${output.slice(0, settings.maxOutputChars)}\n… [clipped at ${settings.maxOutputChars} chars]` : output;
  const expectExit = input.expectExit === "nonzero" ? "nonzero" : "zero";
  const expectOutput = input.expectOutput && input.expectOutput.trim() ? input.expectOutput : null;
  const exitOk = exitCode !== null && (expectExit === "zero" ? exitCode === 0 : exitCode !== 0);
  const outputOk = expectOutput === null ? true : clipped.includes(expectOutput);
  const verification: SecVerification = {
    at,
    command,
    output: clipped,
    exitCode,
    timedOut,
    expect,
    expectExit,
    ...(expectOutput !== null ? { expectOutput } : {}),
    confirmed: !timedOut && exitOk && outputOk,
  };

  const written = updateFinding(projectRoot, id, { verification }, at);
  if (!written.ok) return { ok: false, errors: [`the run happened but could not be recorded: ${written.errors.join("; ")}`] };

  return {
    ok: true,
    value: verification,
    warnings: verification.confirmed
      ? []
      : [
          timedOut
            ? `the command did not finish within ${settings.commandTimeoutMs}ms and was KILLED — recorded as NOT confirmed.`
            : `the run did NOT match the stated expectation (exit ${exitCode ?? "killed"}${expectOutput ? ", output substring missing" : ""}) — recorded as NOT confirmed.`,
          "A disconfirmed run is a result: either the finding is wrong, or the expectation was. Fix whichever is wrong rather than re-running until it agrees.",
        ],
  };
}

export function reconNotePath(projectRoot: string): string {
  return path.join(secStateDir(projectRoot), "recon.md");
}

/**
 * Append one RECON section to the run's note.
 *
 * APPEND-ONLY, and that is the whole design of multi-round recon. The note is the run's
 * CEILING — what it can see at all — and the original version refused any second submit for
 * exactly that reason: a model that re-submitted after round 15 would replace the audit's whole
 * scope with whatever it found convenient, while the surface list it had already enumerated
 * stayed. Appending keeps the reason and drops the limitation: a later section can only ADD,
 * so the ceiling can widen (the miss the first pass made gets recorded) and can never shrink
 * (nothing already written is lost).
 *
 * The floor applies to the NEW section, not to the total: "the note is 900 chars" is not a
 * reason to accept `\"also check /admin\"` as a recon round.
 */
/**
 * Write a deep run's SEED note.
 *
 * A separate function from `submitSecRecon`, not a flag on it, because the heading is the difference:
 * `submitSecRecon` numbers its sections (`## RECON ROUND 1`) and `reconSections` counts those markers.
 * A deep run performs NO recon pass — its note was assembled mechanically from the parent finding — and
 * labelling it "RECON ROUND 1" would put a claim in the record that no round produced, and would make
 * the report say the run spent a round mapping a project it was handed a target from.
 */
export function submitDeepSeed(projectRoot: string, note: string, at = nowIso()): Result<string> {
  const text = (note ?? "").trim();
  if (text.length < 200) {
    return { ok: false, errors: [`a deep seed must be at least 200 characters (got ${text.length})`] };
  }
  // Append-only, like every other note: a second seed adds to the record rather than replacing the
  // context the earlier rounds already worked from.
  const existing = loadSec(projectRoot).snapshot.secNote;
  const combined = existing === null ? text : `${existing}\n\n${text}`;
  if (!appendSecEvent(projectRoot, { type: "sec_recon_submitted", at, note: combined })) {
    return { ok: false, errors: ["the deep seed could not be written to the log"] };
  }
  try {
    fs.mkdirSync(secStateDir(projectRoot), { recursive: true });
    fs.writeFileSync(reconNotePath(projectRoot), `${combined}\n`, "utf-8");
  } catch {
    // The mirror is a convenience; the event is the record.
  }
  return { ok: true, value: combined, warnings: [] };
}

export function submitSecRecon(projectRoot: string, note: string, at = nowIso()): Result<string> {
  const text = (note ?? "").trim();
  if (text.length < 200) {
    return {
      ok: false,
      errors: [
        `a recon section must be at least 200 characters (got ${text.length}). It is the only pass ` +
          "over the project, and every later round works from it plus the attack surface it enumerates.",
      ],
    };
  }
  const snapshot = loadSec(projectRoot).snapshot;
  // THE SECTION NUMBER, not the log's round number. A fresh project has recorded no rounds yet
  // (`rounds` is 0), so numbering by that marked EVERY section "RECON ROUND 1" — and the marker
  // is what `reconSections` counts, so the phase would never advance.
  const sectionNumber = reconSections(snapshot) + 1;
  const heading = `## RECON ROUND ${sectionNumber}`;
  // A section for this round already exists: keep BOTH rather than refusing. A model that
  // wants to add detail in the round it is already in is doing the right thing, and refusing
  // would send it to a dead end (the same failure as the refusal that named a command which
  // did not exist). Append-only means the cost of a duplicate section is a longer note.
  const section = `${heading}\n\n${text}`;
  const combined = snapshot.secNote === null ? section : `${snapshot.secNote}\n\n${section}`;
  if (!appendSecEvent(projectRoot, { type: "sec_recon_submitted", at, note: combined })) {
    return { ok: false, errors: ["the recon note could not be written to the log"] };
  }
  // A readable mirror, so a later round can RE-READ the ceiling instead of working from
  // memory of it. The durable record is the event above; this file is for the model and the
  // operator, and it is rewritten rather than appended (it is a mirror, not the log).
  try {
    fs.mkdirSync(secStateDir(projectRoot), { recursive: true });
    fs.writeFileSync(reconNotePath(projectRoot), `${combined}\n`, "utf-8");
  } catch {
    // The mirror is a convenience; the event is the record.
  }
  return { ok: true, value: combined, warnings: [] };
}

// -----------------------------------------------------------------
// The attack surface — the work list
// -----------------------------------------------------------------
//
// This is what turns "go and look" into an ANALYSIS.
//
// Without a list the loop can only hand over a note and a set of unread directories;
// there is no record of what has been looked at, no way to tell progress from
// idleness, and no way to give the model a specific target. With it:
//
//   - the loop ASSIGNS the next open item, so the analysis is systematic rather than
//     whatever the model felt like reading;
//   - `cleared` is a first-class result, so "I read this and it is guarded" counts as
//     progress and stops the next round re-reading it;
//   - the report can say examined N of M, which is the honest answer to "how much of
//     this project did the run actually analyse".
//
// The items are COORDINATES, not claims — that is what keeps this mode distinct from
// the hypothesis tree. `POST /diag/ping` is a place; "the ping handler reaches
// system() without a check" is an assertion about it. Enumerating places must not
// require asserting anything first, or the mode is back to the gate it exists to
// avoid.

export interface SurfaceInput {
  title: string;
  kind?: SecSurfaceKind;
  file?: string;
  line?: number;
  categories?: string[];
  round?: number;
  /** Raise to jump the queue. See `SecSurface.priority`. */
  priority?: number;
}

/**
 * The surface item's own gate, and it is deliberately weak.
 *
 * A title and a kind, nothing more. A `file` is not required: the whole point of an
 * entrypoint is that it is reachable from OUTSIDE the code, so demanding a line
 * number would exclude exactly the items that matter most.
 */
export function validateSurface(input: SurfaceInput): Result<SurfaceInput> {
  const errors: string[] = [];
  if (typeof input.title !== "string" || input.title.trim() === "") {
    errors.push("title is required — say what the item is (a route, a function, a boundary)");
  }
  if (input.kind !== undefined && !(SEC_SURFACE_KINDS as readonly string[]).includes(input.kind)) {
    errors.push(`kind must be one of ${SEC_SURFACE_KINDS.join("|")}`);
  }
  if (typeof input.file === "string" && input.file.trim() !== "" && typeof input.line !== "number") {
    errors.push("`line` is required when `file` is given");
  }
  return errors.length === 0 ? { ok: true, value: input, warnings: [] } : { ok: false, errors };
}

function nextSurfaceId(snapshot: TreeSnapshot): string {
  let max = 0;
  for (const s of snapshot.surfaces) {
    const m = /^S-(\d+)$/.exec(s.id);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `S-${String(max + 1).padStart(4, "0")}`;
}

export function recordSurface(projectRoot: string, input: SurfaceInput, at = nowIso()): Result<SecSurface> {
  const check = validateSurface(input);
  if (!check.ok) return { ok: false, errors: check.errors };
  const snapshot = loadSec(projectRoot).snapshot;
  const title = input.title.trim();
  // A duplicate is not an error — enumerating the same route twice is a waste, not a
  // fault, and refusing it would make the model handle a rejection it cannot act on.
  const existing = snapshot.surfaces.find((s) => s.title.trim() === title);
  if (existing) return { ok: true, value: existing, warnings: [`already enumerated as ${existing.id}`] };
  const surface: SecSurface = {
    id: nextSurfaceId(snapshot),
    at,
    round: typeof input.round === "number" && input.round > 0 ? input.round : snapshot.rounds,
    kind: input.kind ?? "other",
    title,
    ...(typeof input.file === "string" && input.file
      ? { location: { file: input.file, line: typeof input.line === "number" ? Math.max(1, Math.floor(input.line)) : 1 } }
      : {}),
    ...(input.categories && input.categories.length > 0 ? { categories: [...input.categories] } : {}),
    ...(typeof input.priority === "number" && Number.isFinite(input.priority) && input.priority !== 0
      ? { priority: Math.floor(input.priority) }
      : {}),
    status: "open",
  };
  if (!appendSecEvent(projectRoot, { type: "surface_recorded", at, surface })) {
    return { ok: false, errors: ["the surface item could not be written to the log"] };
  }
  const total = snapshot.surfaces.length + 1;
  const open = snapshot.surfaces.filter((x) => x.status === "open" || x.status === "digging").length + 1;
  return {
    ok: true,
    value: surface,
    warnings:
      total >= SEC_SURFACE_SOFT_CAP
        ? [
            `SURFACE AT ${total} ITEMS (soft ceiling ${SEC_SURFACE_SOFT_CAP}). It was recorded — refusing it would lose it — but the run is now committed to at least ${open} more round(s).`,
            "Analyse before enumerating further: `sec_surface` again only for a place that matters MORE than what is already waiting.",
          ]
        : [],
  };
}

/**
 * Mark an item examined and CLEARED.
 *
 * The reason is required and that is the whole value of the operation. "Nothing
 * found" is not a reason — it is the absence of one. A clearance that cannot name
 * the guard it found is a clearance nobody can check, and it would let a whole area
 * be marked done on the strength of a shrug.
 */
export function clearSurface(
  projectRoot: string,
  id: string,
  reason: string,
  guardLocation?: { file: string; line: number },
  at = nowIso(),
): Result<SecSurface> {
  const text = (reason ?? "").trim();
  if (text.length < 20) {
    return {
      ok: false,
      errors: [
        `${id} cannot be cleared with "${text}" — say WHICH guard you found and where. ` +
          'A clearance that cannot name one is a clearance nobody can check, and "nothing found" is ' +
          "the absence of a reason rather than one.",
      ],
    };
  }
  // A CLEARANCE IS AN ARTIFACT TOO, and this is the same bar the findings carry.
  //
  // Measured on a real run: the clearances read well ("the role check is enforced in the decorator")
  // and NOT ONE could be checked, because none named a line. A clearance is what bounds the attack
  // surface — "this part was looked at and found guarded" — so on a 0day hunt it carries as much
  // weight as a finding does, and a reason a reader cannot open is a shrug with good grammar.
  //
  // The guard is not always in the handler: a framework default lives in the config, a middleware in
  // the pipeline registration, a base class in the base class. Those are lines too, and they are the
  // right ones to cite.
  if (!guardLocation || !guardLocation.file || !(guardLocation.line > 0)) {
    return {
      ok: false,
      errors: [
        `${id} cannot be cleared without the guard's LOCATION — a clearance nobody can open is not a clearance.`,
        "Pass the line that enforces it:  sec_clear id=<id> reason=\"<which guard>\" file=<path> line=<n>",
        "A framework default or middleware is fine to cite: point at where it is configured or registered.",
      ],
    };
  }
  return updateSurface(
    projectRoot,
    id,
    { status: "cleared", clearedReason: text, guardLocation: { file: guardLocation.file, line: Math.max(1, Math.floor(guardLocation.line)) } },
    at,
  );
}

/**
 * `sec_dig` — "I am not finished with this item; give me another round."
 *
 * A NAMED ACTION rather than a status the model sets, for the same reason `sec_clear` is:
 * an action can carry its own rule, and the rule here is a budget.
 *
 * Why it exists at all: before this, an item got ONE round. A round spent genuinely
 * tracing something that needed a second pass recorded nothing, moved no status, and so
 * counted as unproductive — the model paid a plateau slot for being thorough, and the
 * cheap way out was to close the item hastily.
 */
export function digSurface(
  projectRoot: string,
  id: string,
  digBudget = SEC_DIG_BUDGET,
  at = nowIso(),
): Result<SecSurface> {
  const item = loadSec(projectRoot).snapshot.surfaces.find((s) => s.id === id);
  if (!item) return { ok: false, errors: [`${id} is not on this run's attack surface`] };
  if (item.status === "cleared") {
    return {
      ok: false,
      errors: [
        `${id} is CLEARED — a clearance names a guard, and asking for depth does not undo it.`,
        `If the guard turned out not to hold, reopen it with sec_reopen ${id} \"<why the guard fails>\"`,
        "(Before this said `sec_update … status=open`, which does not exist — sec_update takes a FINDING id and has no status field, so the model was sent to a dead end and the item could not be reopened at all.)",
      ],
    };
  }
  const spent = item.digRounds ?? 0;
  if (spent >= digBudget) {
    return {
      ok: false,
      errors: [
        `${id} has had ${spent} depth round(s), which is the budget (${digBudget}).`,
        "Finish it: `sec_finding` if you found something, `sec_clear` with the guard if you did not.",
        "A depth round that never ends is the same as never deciding.",
      ],
    };
  }
  return updateSurface(projectRoot, id, { status: "digging" }, at);
}

/**
 * `sec_reopen` — the named opposite of `sec_clear`.
 *
 * It had to exist. `digSurface` refused a cleared item and told the model to reopen it, and there
 * was NO WAY TO DO THAT: `sec_update` takes a finding id and has no status field, so the model got
 * "S-0001 is not a finding in this run" and the item stayed cleared forever. A refusal that names a
 * command which does not exist is worse than a refusal that names nothing — it sends the model to a
 * dead end and looks like a tool bug from the inside.
 *
 * The reason is required for the same reason `sec_clear` requires one: a clearance asserts a guard
 * holds, and withdrawing that assertion is a claim too.
 */
export function reopenSurface(projectRoot: string, id: string, reason: string, at = nowIso()): Result<SecSurface> {
  const text = (reason ?? "").trim();
  if (text.length < 20) {
    return {
      ok: false,
      errors: [
        `${id} cannot be reopened with "${text}" — say why the guard does not hold.`,
        "A clearance asserts that something protects this code; withdrawing that is a claim too, and an" ,
        "empty one tells the next round nothing about what changed.",
      ],
    };
  }
  const item = loadSec(projectRoot).snapshot.surfaces.find((s) => s.id === id);
  if (!item) return { ok: false, errors: [`${id} is not on this run's attack surface`] };
  if (item.status !== "cleared") {
    return { ok: false, errors: [`${id} is ${item.status}, not cleared — there is nothing to reopen.`] };
  }
  // Status only. `clearedReason` stays in the log as history and is simply not printed once the
  // status is no longer `cleared` — the report filters on status, so a stale reason cannot leak.
  return updateSurface(projectRoot, id, { status: "open" }, at);
}

export function updateSurface(
  projectRoot: string,
  id: string,
  patch: SecSurfacePatch,
  at = nowIso(),
): Result<SecSurface> {
  const snapshot = loadSec(projectRoot).snapshot;
  const existing = snapshot.surfaces.find((s) => s.id === id);
  if (!existing) return { ok: false, errors: [`${id} is not on this run's attack surface`] };
  const after = applySurfacePatchForCheck(existing, patch);
  if (after.status === "cleared" && (!after.clearedReason || !after.guardLocation)) {
    return { ok: false, errors: [`${id} cannot be cleared without a reason AND the guard's location — see clearSurface`] };
  }
  // The timestamp is STAMPED here rather than taken from the caller, and it is part
  // of the patch because that is the only way it reaches the log. An earlier version
  // built a `stamped` object, never used it, and asserted the field onto the patch
  // through `unknown` — which type-checked and did nothing at all.
  const full: SecSurfacePatch = {
    ...patch,
    ...(patch.status !== undefined && patch.status !== "open" && !existing.examinedAt ? { examinedAt: at } : {}),
  };
  if (!appendSecEvent(projectRoot, { type: "surface_updated", at, id, patch: full })) {
    return { ok: false, errors: ["the update could not be written to the log"] };
  }
  const written = loadSec(projectRoot).snapshot.surfaces.find((s) => s.id === id)!;
  return { ok: true, value: written, warnings: [] };
}

/** Local mirror of the store's patch application, for the pre-write check only. */
function applySurfacePatchForCheck(surface: SecSurface, patch: SecSurfacePatch): SecSurface {
  return {
    ...surface,
    ...(patch.status !== undefined ? { status: patch.status } : {}),
    ...(patch.clearedReason !== undefined ? { clearedReason: patch.clearedReason } : {}),
    ...(patch.guardLocation !== undefined ? { guardLocation: patch.guardLocation } : {}),
    ...(patch.findingId !== undefined ? { findingId: patch.findingId } : {}),
  };
}

/**
 * The next item to analyse: the highest PRIORITY, then ENUMERATION order.
 *
 * The plan still governs everything nobody promoted — ties keep insertion order, because
 * `sort` is stable and the comparator returns 0 for equal priorities.
 *
 * What changed, and why: the first design froze the order at "the enumerator's order IS the
 * plan, and nothing re-sorts it". The hole in that was WHEN the plan was written — round 2,
 * with almost nothing read. A model that has spent fifteen rounds tracing data flows knows
 * things it did not know then, and making it walk a stale list is not respecting its
 * judgement; it is overruling its newer judgement with its older one.
 *
 * The hypothesis mode already re-ranks every round. A frozen order was the inconsistent one.
 *
 * What it does NOT do is let the model chase whatever it just thought of: promotion is an
 * explicit act on an item, the item still gets examined one per round, and the brief reports
 * how many items are queued ahead of the plan so over-promoting is visible rather than free.
 */
export function nextOpenSurface(snapshot: TreeSnapshot, digBudget = SEC_DIG_BUDGET): SecSurface | null {
  // `digging` is in the pool: an item you deliberately asked to go deeper on is not
  // finished, and it must not wait behind the whole plan to be continued.
  const open = snapshot.surfaces.filter((s) => s.status === "open" || s.status === "digging");
  if (open.length === 0) return null;
  /**
   * 2 = mid-dig with budget left, 1 = promoted, 0 = the plan, -1 = EXHAUSTED.
   *
   * A digging item outranks even a promoted one: finishing a trace you started is worth
   * more than starting a more promising-looking one, because an abandoned trace is wasted
   * work while an unstarted item is still just an item. Past the budget it drops back to 0
   * — which is what stops a `digging` item that the model has stopped caring about from
   * holding the queue forever.
   *
   * An item that has been handed `MAX_ITEM_ATTEMPTS` rounds without a conclusion goes to
   * -1: still in the queue, still in the report, but only reached when nothing else is left.
   * That is what stops one item from eating the plateau while the rest of the work list
   * waits (see `MAX_ITEM_ATTEMPTS`).
   */
  const rank = (s: SecSurface): number => {
    if (s.status === "digging" && (s.digRounds ?? 0) < digBudget) return 2;
    // PROMOTION OUTRANKS EXHAUSTION. The exhausted rule exists to stop an item from eating
    // the plateau unattended, not to forbid it — a model that believes it is close says so
    // with `sec_update <id> priority=1`, and that has to work or the deprioritisation becomes
    // a silent ban on the very item the run was working on.
    if ((s.priority ?? 0) > 0) return 1;
    // EXHAUSTED, two ways, and BOTH count: the attempt cap (measured on an item the model
    // read five times and recorded nothing), and a dig budget that was SPENT without a
    // conclusion. The second one used to escape — the exhausted rule required
    // `status === "open"`, so a mid-dig item with a spent budget kept rank 0 and was handed
    // every round while digRounds grew past the budget without limit.
    const attemptsSpent = (s.attempts ?? 0) >= MAX_ITEM_ATTEMPTS;
    const digSpent = s.status === "digging" && (s.digRounds ?? 0) >= digBudget;
    return attemptsSpent || digSpent ? -1 : 0;
  };
  // `focus` REORDERS, it does not merely decorate. It used to be rendered as a banner at the top
  // of every brief and touch nothing else — a setting that says "this run is for rce" while the
  // assignment ignores it is worse than no setting, because the operator stops checking. It sits
  // below `priority` (an explicit act on ONE item) and above plan order: the operator's scope
  // outranks enumeration order, and the model's specific judgement outranks both.
  const focus = snapshot.loop?.focus ?? [];
  const focusHit = (s: SecSurface): number =>
    focus.length > 0 && (s.categories ?? []).some((c) => focus.includes(c)) ? 1 : 0;
  // Ties keep insertion order — `sort` is stable and every term returns 0 — so the plan
  // still governs everything nobody promoted and nothing in scope.
  return (
    [...open].sort(
      (a, b) => rank(b) - rank(a) || focusHit(b) - focusHit(a) || (b.priority ?? 0) - (a.priority ?? 0),
    )[0] ?? null
  );
}

export interface SurfaceProgress {
  total: number;
  open: number;
  examined: number;
  cleared: number;
  /** Items that produced a finding. */
  productive: number;
  /** Items mid-dig: examined, deliberately not settled. */
  digging: number;
  /**
   * Items this run has HANDED AT LEAST ONE ROUND TO.
   *
   * Deliberately separate from `examined`, which counts a STATUS CHANGE and is what the plateau
   * reads. Widening `examined` to include this would make an unproductive round look productive,
   * because the loop increments `attempts` on prepare — the day a round is prepared it would
   * already have produced something. So this is reported and `examined` is left alone.
   */
  attempted: number;
  /**
   * Open items the model has promoted above the plan.
   *
   * Reported so that over-promoting is VISIBLE. The mechanism has no cap — a model can send
   * every item to the front — and the honest defence is not a limit but a number the model
   * can see: "12 items queued ahead of a plan of 30" is a fact it can act on, where a silent
   * reorder is not.
   */
  aheadOfPlan: number;
}

export function surfaceProgress(snapshot: TreeSnapshot): SurfaceProgress {
  const total = snapshot.surfaces.length;
  const cleared = snapshot.surfaces.filter((s) => s.status === "cleared").length;
  const withFinding = snapshot.surfaces.filter((s) => s.findingId).length;
  const open = snapshot.surfaces.filter((s) => s.status === "open" || s.status === "digging");
  return {
    total,
    open: open.length,
    // "examined" counts everything that was looked at, cleared or not — it is the
    // honest denominator for "how much did this run analyse".
    examined: snapshot.surfaces.filter((s) => s.status !== "open").length,
    cleared,
    productive: withFinding,
    aheadOfPlan: open.filter((s) => (s.priority ?? 0) > 0).length,
    digging: snapshot.surfaces.filter((s) => s.status === "digging").length,
    attempted: snapshot.surfaces.filter((s) => (s.attempts ?? 0) > 0).length,
  };
}

// -----------------------------------------------------------------
// Coverage, from findings instead of from nodes
// -----------------------------------------------------------------

/**
 * Every project-relative file a FINDING cites.
 *
 * The hypothesis version walks `attackVector.path` and `evidence`. This walks the
 * finding's location and — because a finding may carry an evidence excerpt with no
 * location — any `file:line` looking token inside that excerpt, so a paste of a
 * code slice still counts as having read the file it came from.
 */
export function secCitedFiles(snapshot: Pick<TreeSnapshot, "findings">): Set<string> {
  const cited = new Set<string>();
  const add = (file: string | undefined): void => {
    if (!file) return;
    cited.add(path.posix.normalize(file.split("\\").join("/")).replace(/^\.\//, ""));
  };
  for (const finding of snapshot.findings) {
    add(finding.location?.file);
    const text = finding.evidence ?? "";
    // `src/a.py:41` and `src/a.py:41-49` — the two shapes a pasted artifact uses.
    for (const m of text.matchAll(/([A-Za-z0-9_./-]+\.[A-Za-z0-9]+):\d+/g)) add(m[1]);
  }
  return cited;
}

export function secCoverage(snapshot: TreeSnapshot, projectRoot: string): CoverageReport {
  return coverageGaps(snapshot, projectRoot, secCitedFiles(snapshot));
}

// -----------------------------------------------------------------
// The briefs
// -----------------------------------------------------------------

/**
 * How many RECON sections have been recorded.
 *
 * The recon phase is counted in SECTIONS, not in rounds, and that is the difference between a
 * phase that tracks work and one that tracks a counter. Counted in rounds, a model that recorded
 * nothing in round 1 still "spent" that round and the phase moved on with an empty note — the
 * run then enumerates from a note that does not exist. Counted in sections, the phase ends when
 * the work is DONE: nothing recorded keeps the run in recon (and the plateau stops it after its
 * window of empty rounds), and a model that records two sections in one round has finished early.
 */
export function reconSections(snapshot: TreeSnapshot): number {
  if (snapshot.secNote === null) return 0;
  return (snapshot.secNote.match(/^## RECON ROUND \d+$/gm) ?? []).length;
}

/**
 * Is the recon phase over?
 *
 * ONE source of truth, used by both the brief generator and the loop's round-kind decision — they
 * must never disagree, or a round gets a recon brief and an `analyze` label (or the reverse), and
 * the plateau counts the two kinds differently.
 */
export function reconPhaseOver(snapshot: TreeSnapshot, reconRounds: number): boolean {
  // A DEEP RUN HAS NO RECON PHASE. It was opened FROM a finding, so the project is already mapped
  // enough to name a target — spending its first two rounds re-mapping the project would be the
  // sweep it exists to avoid. Its first round enumerates SUB-QUESTIONS instead.
  if (snapshot.loop?.deep) return true;
  return reconSections(snapshot) >= reconRounds;
}

/**
 * The RECON phase, one brief per round.
 *
 * Multi-round because one round is one model turn, and on a real codebase that is a SAMPLE:
 * everything downstream is bounded by what the sample noticed. The rounds are not the same
 * question asked twice — round 1 maps the project, round 2 reads the REQUEST LIFECYCLE and the
 * auth wiring (what pre-auth findings actually turn on), and round 3+ builds the sink catalogue
 * for the objective's class. Each round is told what the previous ones already recorded, so the
 * note grows instead of repeating.
 */
export function renderSecReconBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  sectionNumber: number,
  reconRounds = 1,
): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — RECON ${sectionNumber}/${reconRounds}]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("THIS PHASE SETS THE CEILING.");
  lines.push("");
  lines.push("Every later round works from these notes plus what has not been read yet. **A part of the");
  lines.push("project absent from the notes is a part nothing will look at.**");
  lines.push("");
  if (snapshot.secNote !== null) {
    lines.push("--- WHAT YOU HAVE RECORDED SO FAR (do NOT repeat it) ---");
    lines.push(clip(snapshot.secNote, 9_000));
    lines.push("--- END ---");
    lines.push("");
  }
  if (sectionNumber <= 1) {
    lines.push("**ROUND 1 — MAP THE PROJECT.** Read enough to know its shape. Use `ls`, `find`, `grep`,");
    lines.push("`read` — whatever the shape of the repository demands. Cover, in prose:");
    lines.push("  - what the project IS (language, framework, what it does, how it is deployed)");
    lines.push("  - its ENTRYPOINTS: HTTP routes, RPC/GraphQL, websockets, CLI verbs, scheduled jobs,");
    lines.push("    queue consumers, file uploads, deserializers, template/plugin loaders");
    lines.push("  - the TRUST BOUNDARIES: where input crosses from unauthenticated to authenticated,");
    lines.push("    and what the authentication actually checks");
    lines.push("  - where the class of bug the objective names would LIVE in this codebase");
    lines.push("  - anything you could NOT work out (this is required, not optional)");
  } else if (sectionNumber === 2) {
    lines.push("**ROUND 2 — READ THE REQUEST LIFECYCLE AND THE AUTH WIRING.** Round 1 gave the map; this");
    lines.push("round is where pre-auth findings are actually decided, because it answers *what runs* and");
    lines.push("*in what order*. Follow ONE request end to end — entry → router → middleware/decorators →");
    lines.push("auth → handler → data layer — and write down:");
    lines.push("  - the exact FILES that make up that path, in order, with their line numbers");
    lines.push("  - **how authentication is enforced**: framework middleware, a decorator, a base class,");
    lines.push("    a route table, a reverse proxy, or nothing. Name the file that decides it.");
    lines.push("  - **the public/unauthenticated surface**: which routes/handlers bypass that enforcement,");
    lines.push("    and HOW they are marked (an allowlist, a decorator, a path prefix, a separate app)");
    lines.push("  - the AUTHORIZATION layer separately from authentication: who checks *this user may do");
    lines.push("    this to this object*, and where");
    lines.push("  - what DEPLOYMENT configuration changes at runtime (env vars, feature flags, settings");
    lines.push("    files, profiles) — a finding that depends on a default nobody deploys is not a finding");
    lines.push("  - **what you still could not work out**, named specifically");
  } else {
    lines.push("**ROUND " + sectionNumber + " — BUILD THE SINK CATALOGUE FOR THE OBJECTIVE'S CLASS.** Stop mapping");
    lines.push("and start locating the places that DO the dangerous thing, because that is what the");
    lines.push("surface list is built from. For `${objective}`:");
    lines.push("  - enumerate the SINKS: every call that executes code, builds a query, writes or reads a");
    lines.push("    file by path, deserializes, renders a template, resolves a URL, or spawns a process");
    lines.push("  - for each: the `file:line`, what it does, and **whether it is reachable before");
    lines.push("    authentication** (this is the field that decides whether it is worth a round)");
    lines.push("  - name the CHECK that guards each one, if any — read the check itself, not its name");
    lines.push("  - list the places where the same sink is reachable from two different entries");
    lines.push("  - and again: what you could not determine, and WHICH FILE would settle it");
  }
  lines.push("");
  lines.push("Write PARAGRAPHS, not one giant block. Name the files and directories you looked at.");
  lines.push("");
  if (sectionNumber < reconRounds) {
    lines.push(
      `Then record it with \`sec_recon\`. ${reconRounds - sectionNumber} more recon round(s) follow, each widening the`,
    );
    lines.push("note; the notes are append-only, so nothing you recorded is lost.");
  } else {
    lines.push(
      `Then record it with \`sec_recon\` — this was the LAST recon round (${sectionNumber}/${reconRounds}), and the next`,
    );
    lines.push("round starts enumerating the attack surface from everything recorded here.");
  }
  return lines.join("\n");
}

/**


/**
 * How many findings the brief lists before it switches to a count.
 *
 * See `renderFoundSoFar`: the list is a de-duplication aid, and thirty worst-first entries is
 * enough to recognise anything the model is about to re-report. Everything past that is a
 * number, because the brief is not a pager.
 */
const FINDINGS_SHOWN = 30;

/**
 * The severity floor for pursuing a finding's blockers.
 *
 * Same floor the hypothesis mode used for `pursue`, and for the same reason: a pursuit round is
 * the expensive kind — it does not advance the sweep — so spending it on a `medium` finding's
 * precondition costs a round that a `high` finding's whole class could have used. An UNRATED
 * finding is not pursued either: "we have not decided whether this matters" is not a reason to
 * spend two rounds on it, and the brief tells the model to rate what it wants pursued.
 */
export const PURSUIT_MIN_SEVERITY: Severity = "high";

/**
 * The finding whose blockers the next round should attack, or null.
 *
 * THE FIX FOR "WE FOUND THE RCE AND WALKED AWAY". A finding that is real but gated — a post-auth
 * RCE on a pre-auth objective, an RCE that needs one more controllable field — is one step from
 * the objective, and closing its gate converts it. Before this existed the loop marked the
 * finding's surface item examined and moved to the next S-xxx: the best result the run could
 * produce was filed and abandoned in the same round.
 *
 * Three conditions, each of which bounds it:
 *   1. it has blockers (the model declared a gate),
 *   2. its pursuit is not already closed, and its budget is not spent,
 *   3. it is at or above `PURSUIT_MIN_SEVERITY`.
 *
 * Worst-first, so the heaviest near miss is attacked before the lighter ones.
 */
/**
 * The blocking gates on a finding, explicit or implicit.
 *
 * EXPLICIT: the model recorded `blockers`. IMPLICIT: the finding is marked POST-AUTH.
 *
 * The implicit case is what closes the measured failure. On a real run a CRITICAL RCE was recorded
 * with `preAuth: false` and NO blocker list — the field did not exist yet — so the loop marked its
 * surface item examined and went on enumerating. The operator then asked "can this be pre-auth?"
 * in chat, that one question produced a CRITICAL pre-auth RCE two exchanges later, and the loop had
 * had nothing to do with it. A post-auth finding on a pre-auth objective IS a near miss, and it must
 * not depend on the model remembering to say so.
 *
 * `preAuth` is the one signal the model already records reliably (the brief asks for it every round),
 * so it is the right thing to derive the gate from. `undefined` stays UNGATED: "nobody determined
 * it" is not "needs a session", and treating it as gated would spend depth rounds on findings whose
 * reachability was never even asserted.
 */
// -----------------------------------------------------------------
// DEEP RUNS — one finding, worked until it gives or the budget ends
// -----------------------------------------------------------------
//
// A sweep and a deep run answer different questions. The sweep asks "what is on this project", and
// its work list is the ATTACK SURFACE. A deep run asks "can THIS be made exploitable", and its work
// list is a set of SUB-QUESTIONS: what has to be true for the finding to land, and which of those is
// still unknown. Each answered sub-question narrows the next one, which is the whole difference
// between ten rounds of progress and ten rounds of the same playbook.
//
// The number that made this necessary: `pursuitRounds` is 3, so a sweep gives a finding three rounds
// over its lifetime and then `nextPursuit` never returns it again. The measured case — a critical
// post-auth RCE that became a critical PRE-auth RCE only after the operator asked one question in
// chat — took more than three rounds of real work (enumerate the unauthenticated entrypoints, query
// the live DB for a usable record, question the premise, find the parameter-source confusion).

/** What a deep run is FOR, in one line. Shown as the run's objective. */
export function deepObjectiveOf(f: SecFinding): string {
  const gates = gatesOfFinding(f);
  const aim = gates.length > 0 ? "打开它的前提" : "推到可复现";
  // The title is carried because the objective is what the report prints as the run's purpose, and
  // "deepen F-0001" alone tells a later reader nothing about what was being deepened.
  return `深挖 ${f.id} · ${aim} · ${clip(f.title, 60)}`;
}

/**
 * The seed note a deep run starts from: what the PARENT run already established, and what is left.
 *
 * Written mechanically from the parent finding's own fields, so it cannot contain anything the parent
 * did not record — a seed that embellished would be the deep run inheriting an assertion nobody made.
 * Empty sections say so instead of being omitted: "the parent recorded no PoC" is information, and a
 * missing section reads as "nobody looked".
 */
export function renderDeepSeedNote(f: SecFinding, parentDir: string, directive?: string): string {
  const out: string[] = [];
  out.push(`# 深挖目标：${f.id} · ${f.severity ?? "未定级"} · ${f.category}`);
  out.push("");
  out.push(
    `本次运行不是扫描。它只做一件事：把 ${f.id}（在 ${parentDir === "." ? "主运行" : parentDir} 记录的）推到结论。`,
  );
  out.push("");
  // THE OPERATOR'S STEER GOES FIRST, before even the established facts.
  //
  // It is the reason this run was opened NOW rather than left to the sweep, so a round that read the
  // facts and never reached it would be answering a different question. But it is stated as a
  // DIRECTION TO TEST, not a conclusion to confirm: the operator is looking at a report, not at the
  // code, and a run that manufactured agreement with the steer would be the worst kind of useless —
  // confident, on-target in its own words, and wrong.
  if (directive && directive.trim()) {
    out.push("## 操作者这一次的要求（优先于下面的默认形状）");
    out.push("");
    out.push(directive.trim());
    out.push("");
    out.push("把子问题往这个方向拆。但**它是方向，不是结论**：操作者只看过报告，没看过代码。");
    out.push(
      "如果沿着这个方向读完发现真正的缺口在别处，就在那一轮把子问题改成实际方向，并在发现里写清楚：" +
        "「按 X 方向查了，不成立，因为 ……；真正的缺口在 Y」。**不要为了让报告贴合要求而把结论写成要求的样子。**",
    );
    out.push("");
  }
  out.push("## 已知事实（来自父运行，不要重新求证）");
  out.push("");
  out.push(`- 标题：${f.title}`);
  if (f.location) out.push(`- 位置：${f.location.file}:${f.location.line}`);
  out.push(
    `- 认证：${
      f.preAuth === true ? "认证前可达" : f.preAuth === false ? "需要已认证会话" : "未判断（父运行没有下这个结论）"
    }`,
  );
  out.push(`- 严重度：${f.severity ?? "未定级"}（这是模型自己的判断，没有任何机制校验）`);
  out.push(`- 类别：${f.category}`);
  if (f.surfaceId) out.push(`- 来自攻击面项：${f.surfaceId}`);
  if (f.round) out.push(`- 父运行的第 ${f.round} 轮记录`);
  out.push("");

  if (f.reasoning && f.reasoning.trim()) {
    out.push("## 父运行的推理（它的结论，不是你的任务）");
    out.push("");
    out.push(f.reasoning.trim());
    out.push("");
  }

  if (f.path && f.path.length > 0) {
    out.push("## 父运行的调用链");
    out.push("");
    f.path.forEach((step, i) => {
      out.push(`${i + 1}. ${step.file ? `${step.file}${step.line ? `:${step.line}` : ""} — ` : ""}${step.detail}`);
    });
    out.push("");
    out.push("**每一步都要重新对一眼源码。** 一份父运行写的调用链是结论，不是证据。");
    out.push("");
  }

  const gates = gatesOfFinding(f);
  if (gates.length > 0) {
    out.push("## 前提（要利用它还需要什么成立）");
    out.push("");
    for (const g of gates) out.push(`- ${g}`);
    out.push("");
    out.push("这就是本次运行要打开的东西。先把每一条拆成能回答的子问题。");
    out.push("");
  }

  out.push("## 已有的 PoC 与验证");
  out.push("");
  if (f.poc && f.poc.trim()) {
    out.push("父运行记录的 PoC：");
    out.push("");
    out.push("```");
    for (const l of f.poc.split("\n")) out.push(l);
    out.push("```");
  } else {
    out.push("_父运行没有记录 PoC。_");
  }
  out.push("");
  if (f.verification) {
    const v = f.verification;
    out.push(`验证：${v.confirmed ? "已复现" : "跑了，但不符合预期"} —— \`${v.command}\`（退出码 ${v.exitCode ?? "超时"}）`);
  } else {
    out.push("_没有跑过任何验证命令。**静态结论。**_");
  }
  out.push("");
  if ((f.pursuitSpent ?? 0) > 0 || f.pursuitClosed) {
    out.push("## 父运行追索过的角度（不要原地重跑）");
    out.push("");
    out.push(`已花 ${f.pursuitSpent ?? 0} 轮。${f.pursuitClosed ? `已结束：${f.pursuitClosed}` : "仍在追索中。"}`);
    out.push("");
  }

  out.push("## 这一轮要做的（不是侦察）");
  out.push("");
  out.push("把「要把它变成可利用的」拆成**能回答的子问题**，每条用 `sec_surface` 记录：");
  out.push("");
  out.push("- 一个子问题是一个**疑问**，不是一句结论。写「守卫读的是哪个参数，处理器读的是哪个？」不是写「守卫有缺陷」。");
  out.push("- 子问题要能**用一个动作回答**：读一个文件、跑一条查询、发一个请求。回答不了的不是子问题，是猜测。");
  out.push("- 最便宜、最能定性的先列。**一个否掉了整条链的前提，第一轮就该问。**");
  out.push("- 已经由父运行确认过的事实不要再列（上面「已知事实」那节），那里重复一次就浪费一轮。");
  out.push("");
  out.push("参考形状（不是模板，要看这个发现实际缺什么）：");
  out.push("");
  out.push("```");
  out.push("门是什么，检查真的在读它吗          → 读那个守卫和那个处理器，两个参数名对得上吗");
  out.push("有没有入口跳过了这个检查              → 列出所有到同一 sink 的路由，哪条没走守卫");
  out.push("要利用它的那条数据，项目里存在吗      → 查种子数据/迁移/默认配置");
  out.push("sink 的输入真的流到这里吗              → 从 source 到 sink 逐跳读");
  out.push("```");
  return out.join("\n");
}

export function gatesOfFinding(f: SecFinding): string[] {
  const explicit = f.blockers ?? [];
  if (explicit.length > 0) return explicit;
  if (f.preAuth === false) return [SEC_IMPLICIT_AUTH_GATE];
  return [];
}

/**
 * The blocker text invented for a POST-AUTH finding that declared none.
 *
 * Exported so the report renders it the same way and a test can pin the wording: this string is the
 * difference between "the run never asked" and "the run asked and could not open it".
 */
export const SEC_IMPLICIT_AUTH_GATE = "需要一个已认证会话（该发现记录为认证后，没有声明更具体的前提）";

/**
 * The DEPTH SIGNAL for a finding: is there something here worth turning over?
 *
 * This is the generalisation of what used to be a gate-only test. The trigger for going deeper is
 * not "it is post-auth" and not "it is blocked" — it is **a breakthrough**: a round produced
 * something real, and there is more to establish about it. Three ways that shows up, in the order a
 * reader would trust them:
 *
 *   "gate"    something real that does not work yet (explicit blockers, or marked post-auth).
 *             Deepening it means opening the precondition, and closing it converts the finding.
 *   "deepen"  the model's own judgement that there is more here — a proven primitive that was never
 *             exercised, a root cause that probably holds elsewhere, a piece that only becomes
 *             dangerous combined with another finding. The plugin cannot read that from prose, so it
 *             asks (see `SecFinding.deepen`).
 *   "unproven" a HIGH-or-worse finding nobody ever ran. It is a claim with an artifact and no test,
 *             and on a 0day hunt the difference between "read it" and "ran it" is the whole product.
 *             Only counts when the project allows probes — otherwise there is literally nothing the
 *             model could do about it, and scheduling it would burn rounds on an impossible round.
 *
 * Returns the REASONS, not a boolean, so the brief can say which one it is and give the matching
 * playbook instead of one generic "go deeper".
 */
export type DepthReason = "gate" | "deepen" | "unproven";

export function depthReasons(f: SecFinding, probesAllowed: boolean): DepthReason[] {
  const reasons: DepthReason[] = [];
  if (gatesOfFinding(f).length > 0) reasons.push("gate");
  if (f.deepen === true) reasons.push("deepen");
  if (probesAllowed && !!f.severity && severityRank(f.severity) <= severityRank(PURSUIT_MIN_SEVERITY) && !f.verification) {
    reasons.push("unproven");
  }
  return reasons;
}

/**
 * The finding whose open threads the next round should deepen, or null.
 *
 * THE FIX FOR "WE FOUND SOMETHING AND WALKED AWAY", generalised. Two measured failures drove it: a
 * critical RCE recorded `preAuth: false` was filed and the run went on enumerating (the operator had
 * to ask "can this be pre-auth?" in chat, and that question produced a critical pre-auth RCE); and the
 * same run's most useful primitive sat unexercised because nothing told the loop that a proven sink
 * is worth a round of its own.
 *
 * So the question is not "is it gated" but "is there a breakthrough here to finish". Conditions:
 *   1. it has a depth reason (see `depthReasons`),
 *   2. its depth is not already closed, and its budget is not spent,
 *   3. it is at or above `PURSUIT_MIN_SEVERITY` — a depth round is the expensive kind.
 *
 * Worst-first, then NEWEST first: among equals the round that just produced something wins, because
 * the model still has the context that made it a breakthrough.
 */
export function nextPursuit(
  snapshot: TreeSnapshot,
  pursuitBudget: number,
  probesAllowed = false,
): SecFinding | null {
  if (pursuitBudget <= 0) return null;
  const candidates = snapshot.findings.filter(
    (f) =>
      depthReasons(f, probesAllowed).length > 0 &&
      !f.pursuitClosed &&
      (f.pursuitSpent ?? 0) < pursuitBudget &&
      !!f.severity &&
      severityRank(f.severity) <= severityRank(PURSUIT_MIN_SEVERITY),
  );
  if (candidates.length === 0) return null;
  return [...candidates].sort(
    (a, b) => severityRank(a.severity!) - severityRank(b.severity!) || b.round - a.round || a.id.localeCompare(b.id),
  )[0]!;
}

/**
 * What has been found so far, one line each.
 *
 * Carried in EVERY sec brief, not only the analyze one: a round that re-reports a
 * finding the run already has wastes the turn, and the model cannot know what is
 * already recorded unless it is told.
 */
export interface SecBriefOptions {
  /** Depth rounds one item may be given. See `SEC_DIG_BUDGET`. */
  digBudget?: number;
  /**
   * Does the project allow command probes?
   *
   * Passed IN because it decides whether the "unproven" depth reason is reachable at all: telling a
   * model to run the PoC on a project that forbids running commands spends a round on an impossible
   * task, and the plugin has the setting in hand already.
   */
  probesAllowed?: boolean;
  /**
   * May this round be a depth round? See `depthAllowed` in loop.ts.
   *
   * Passed IN and not recomputed here, because the loop's round-kind decision and the brief MUST
   * agree: a round labelled `analyze` carrying a pursuit brief (or the reverse) is the bug this
   * parameter exists to make impossible — and the plateau counts the two kinds differently.
   */
  pursuitAllowed?: boolean;
  /**
   * How many PURSUIT rounds one finding's blockers may cost. See `HypothesisSettings.pursuitRounds`.
   *
   * Passed IN for the same reason `reconRounds` is: the phase boundary and the scheduling decision
   * must read the same number, and the brief should not read the settings file per round.
   */
  pursuitBudget?: number;
  /**
   * How many RECON rounds the run takes. See `HypothesisSettings.reconRounds`.
   *
   * Passed IN so the brief does not have to read the settings file on every round, and so the
   * phase boundary has ONE source (the loop passes the same number the round-kind decision used).
   */
  reconRounds?: number;
  /**
   * The previous round's outcome, already formatted as one line.
   *
   * Built by loop.ts, which owns `RoundOutcome` — sec.ts cannot import it without a cycle.
   * The hypothesis briefs have carried a line like this all along (`Last round (N): …`);
   * this mode carried NOTHING, so the model could not tell a round that found something
   * from a round that found nothing, and had no way to notice it was repeating itself.
   */
  lastRound?: string | null;
  /**
   * The LIVE loop state.
   *
   * Passed separately because `tickLoop` evaluates the round it was handed and only then
   * prepares the next one — so `snapshot.loop.stallRounds` is the count from BEFORE that
   * evaluation. Reading the snapshot gave the brief a stall counter that was always one
   * round stale, which is exactly the number the line exists to communicate.
   */
  loop?: AuditLoopState | null;
}

/**
 * A line the model can act on before the run is stopped by something it cannot see.
 *
 * The stall counter was absent from every sec brief. With it, "I am one unproductive round
 * from being stopped" is a fact the model can respond to — by changing class, or by
 * promoting the item it actually suspects. Without it the run ends for a reason the model
 * never learned.
 */
function renderStall(loop: AuditLoopState | null | undefined): string {
  if (!loop || loop.plateauWindow <= 0) return "";
  const left = Math.max(0, loop.plateauWindow - loop.stallRounds);
  if (loop.stallRounds === 0) return `UNPRODUCTIVE ROUNDS: 0/${loop.plateauWindow} — the run stops if this reaches ${loop.plateauWindow}.`;
  return (
    `UNPRODUCTIVE ROUNDS: ${loop.stallRounds}/${loop.plateauWindow} — **${left} more and this run STOPS.** ` +
    "An examined item is what resets it; if you are about to try the same angle again, try a different one."
  );
}

/** The items the model deliberately asked to keep digging, with their budget use. */
function renderDigging(snapshot: TreeSnapshot, digBudget: number): string {
  const digging = snapshot.surfaces.filter((s) => s.status === "digging");
  if (digging.length === 0) return "";
  const lines = [`MID-DIG (${digging.length}) — these are not finished:`];
  for (const s of digging) {
    lines.push(`  ${s.id}  depth round ${s.digRounds ?? 0}/${digBudget}  ${clip(s.title, 70)}`);
  }
  return lines.join("\n");
}

function renderFoundSoFar(snapshot: TreeSnapshot): string {
  const findings = snapshot.findings;
  if (findings.length === 0) {
    return "FOUND SO FAR: nothing yet.";
  }
  // BOUNDED, because this line rides EVERY brief and a long run is exactly when it matters.
  // Unbounded, it grows by one line per finding: a run with 60 findings — nothing unusual on a
  // real codebase — re-sent all 60 every round, and the list crowded out the item the round was
  // actually about. The worst ones are kept because that is what a re-report would duplicate;
  // the rest are a COUNT, and the count is honest about how many are hidden.
  const sorted = [...findings].sort(compareFinding);
  const shown = sorted.slice(0, FINDINGS_SHOWN);
  const lines: string[] = [`FOUND SO FAR (${findings.length}) — do NOT re-report these:`];
  for (const f of shown) {
    const where = f.location ? ` ${f.location.file}:${f.location.line}` : "";
    const chain = f.chainOf && f.chainOf.length > 0 ? `  ⛓ combines ${f.chainOf.join(" + ")}` : "";
    const ran = f.verification?.confirmed ? " ✓ran" : "";
    // A GATED finding is marked, so the model can see at a glance which of its results is one
    // step from the objective — and whether that gate is still open (being pursued) or was
    // already attacked and closed.
    const gated = (f.blockers?.length ?? 0) > 0 ? `  ⊘ gated(${f.blockers!.length})` : f.pursuitClosed ? "  ⊘ gate closed" : "";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category} — ${clip(f.title, 110)}${where}${chain}${ran}${gated}`);
  }
  if (findings.length > shown.length) {
    lines.push(`  … +${findings.length - shown.length} more, worst-first — the full list is in SEC-REPORT.md and tree.jsonl.`);
  }
  const chains = findings.filter((f) => f.chainOf && f.chainOf.length > 0);
  if (chains.length > 0) {
    lines.push("");
    lines.push(`CHAINS ALREADY RECORDED (${chains.length}) — these are findings in their own right:`);
    for (const c of chains.slice(0, FINDINGS_SHOWN)) lines.push(`  ${c.id} [${c.severity ?? "unrated"}] ${clip(c.title, 100)}`);
  }
  return lines.join("\n");
}

/**
 * The findings that HIT THE OBJECTIVE: reachable before authentication, at HIGH or worse.
 *
 * The thing a pre-auth hunt is actually for. Exported because the round summary leads with it — the
 * operator watching a run should learn the moment it lands, not when they next open the report.
 *
 * Tri-state `preAuth` is respected: `undefined` is NOT counted. "Nobody determined whether it needs a
 * session" is not "reachable without one", and counting it here would announce a pre-auth hit the run
 * never established — the exact inflation this mode's report refuses to make.
 *
 * Worst-first, then newest-first, so the headline is the most serious and most recent.
 */
export function objectiveHits(snapshot: TreeSnapshot): SecFinding[] {
  return snapshot.findings
    .filter((f) => f.preAuth === true && !!f.severity && severityRank(f.severity) <= severityRank("high"))
    .sort((a, b) => severityRank(a.severity!) - severityRank(b.severity!) || b.round - a.round || a.id.localeCompare(b.id));
}

/**
 * The depth moves for a finding that has NO gate — the other half of "keep going on this".
 *
 * A gate is the loudest reason to deepen something, but it is not the only one. When the model says
 * "there is more here" (`deepen`) or when a HIGH finding has never been RUN, the round is not about
 * opening a precondition — it is about FINISHING the finding: prove it, complete the path, find where
 * else the root cause holds, and see what it combines with. Those are the four depth axes of a
 * FINDING, the same way the class ladders are the depth axes of a bug class.
 */
function renderNonGateDepth(lines: string[], finding: SecFinding): void {
  const id = finding.id;
  lines.push("--- HOW TO DEEPEN THIS FINDING: four axes ---");
  lines.push("");
  lines.push("**1. PROVE IT.** The finding is a claim plus an artifact. Run the thing: a response that comes");
  lines.push("back carrying your own string, or a 500 with your input in the message, settles more than any");
  lines.push("reading. `sec_verify` records the command, its exit code and its output, and the report then");
  lines.push("marks the finding REPRODUCED instead of static — the difference between a lead and a result.");
  lines.push("");
  lines.push("**2. COMPLETE THE PATH.** Walk entry → check → sink and write each hop as a `path` step with a");
  lines.push("`file:line`. A finding whose reachability rests on \"this looks callable\" is one a reader cannot");
  lines.push("check, and the hop that is missing is usually where the guard is.");
  lines.push("");
  lines.push("**3. FOLLOW THE ROOT CAUSE.** The bug is rarely one endpoint. Ask: what shared helper, base");
  lines.push("class, decorator, framework default or middleware produced this? Then enumerate every other");
  lines.push("caller of it — each one is a new place, and each is cheaper to check than the original was.");
  lines.push("Record the ones that hold as findings; `sec_surface` the ones that need analysis of their own.");
  lines.push("");
  lines.push("**4. ASK WHAT IT COMBINES WITH.** Two medium findings that meet can be one critical. Does this");
  lines.push("primitive give you a value, a write, a position or a token that another recorded finding needs?");
  lines.push("If so, record the COMBINATION as its own finding with `chainOf=[...]` — its artifact is its");
  lines.push("parts, and the report can only state the chain if you record it.");
  lines.push("");
  lines.push("--- WHAT THIS ROUND CAN END WITH ---");
  lines.push(`**You learned something** → land it: \`sec_verify\` when you ran it, \`sec_update ${id} path=[...]\``);
  lines.push("when you completed the chain, `sec_finding` for each new place the root cause reaches, and");
  lines.push("`sec_finding` with `chainOf` when it combines with something already recorded.");
  lines.push("**There is genuinely nothing more here** → say so, so the loop returns to the work list:");
  lines.push(`  \`sec_update ${id} pursuitClosed="<理由：四个轴分别试到了哪里，为什么没有更深的东西>"\``);
  lines.push("**There is more, and it needs its own rounds** → keep `deepen=true` and name which axis is open.");
  lines.push("");
}


/**
 * The depth axes for a class, in THIS mode's terms.
 *
 * `renderLadder` in ladders.ts is hypothesis-flavoured: it ends by telling the model
 * to file each unsettled axis as a `requires` gate. That is exactly the machinery
 * this mode does not have. The AXES are the valuable part and they are class
 * knowledge rather than tree machinery, so they are reused here with the instruction
 * that fits — settle each one, and an axis you cannot settle is where to keep
 * digging rather than a question mark to move past.
 */
function renderSecLadder(category: string): string {
  const ladder = ladderFor(category);
  const lines: string[] = [];
  lines.push(`### The depth axes for ${category}`);
  lines.push("");
  lines.push('Settle EACH one by reading code — "no" is as useful an answer as "yes".');
  lines.push("**An axis you cannot settle is where this round should keep digging**, not a question mark to move past.");
  lines.push("");
  lines.push("**The one that matters most — if you check only one, check this:**");
  lines.push(`  ${ladder.keyAxis}`);
  lines.push("");
  lines.push("All of them:");
  for (const axis of ladder.axes) lines.push(`  - ${axis}`);
  return lines.join("\n");
}

/**
 * Round 2: enumerate the attack surface into a WORK LIST.
 *
 * This is the round that turns the mode from "go and look" into an analysis. The
 * list is what the loop then works through one item at a time, so the ORDER the model
 * writes it in IS the plan — which is why the brief says so, and why the loop does not
 * re-sort it afterwards.
 */
/**
 * The SURFACE round of a DEEP run: enumerate SUB-QUESTIONS, not an attack surface.
 *
 * This is the round that makes depth compound instead of repeat. A sweep's surface is a list of places
 * ("look here, then here"); a deep run already has its place — it has one finding — so the round after
 * the seed has to produce the next question, and the round after that the question after that.
 *
 * The instruction that matters most is the third bullet: a sub-question must be answerable by ONE
 * action. Without it the model writes "the guard may be bypassable" — which is not a question, cannot
 * be closed, and produces rounds that end with nothing recorded.
 */
export function renderSecDeepQuestionBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  const lines: string[] = [];
  const deep = snapshot.loop?.deep;
  lines.push(`[SEC ROUND ${round} — SUB-QUESTIONS]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("--- WHAT THE SWEEP ALREADY ESTABLISHED ---");
  lines.push(snapshot.secNote ?? "(the seed note is missing — record the sub-questions from the finding itself)");
  lines.push("--- END ---");
  lines.push("");
  lines.push("This run has ONE target and no attack surface to sweep. What it needs from you now is");
  lines.push("the next questions, not a list of places.");
  lines.push("");
  lines.push("**A sub-question is a QUESTION THAT ONE ACTION CAN ANSWER.** Not a suspicion, not a");
  lines.push("hypothesis about what might be wrong — a thing you can go and find out this round:");
  lines.push("");
  lines.push("  - \"which parameter does the guard read, and which does the handler read?\"  → read both");
  lines.push("  - \"do any of the routes to this sink skip the check?\"  → list the routes, read the wiring");
  lines.push("  - \"does the shipped seed data contain a record that reaches it?\"  → read the migrations");
  lines.push("  - \"does the value survive the cast at line 88?\"  → read the cast");
  lines.push("");
  lines.push("  NOT \"the guard may be bypassable\" — nothing can close that, so the round ends with");
  lines.push("  nothing recorded and the next round starts from the same place.");
  lines.push("");
  lines.push("Record each with `sec_surface`, one per question, and **order them by what they would");
  lines.push("settle**: a question whose answer kills the whole path goes first, because finding out");
  lines.push("it does not hold four rounds in is the most expensive way to learn it.");
  lines.push("");
  lines.push("Pass `categories` when the class is obvious. Do NOT re-list what the seed note already");
  lines.push("records as established — every line you repeat costs a round on a question somebody");
  lines.push("already answered.");
  lines.push("");
  lines.push("Aim for 4-12 questions. Fewer, sharper, answerable ones are worth more here than a");
  lines.push("complete-sounding list nobody can finish.");
  return lines.join("\n");
}

export function renderSecSurfaceBrief(snapshot: TreeSnapshot, objective: string, round: number): string {
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — SURFACE]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  lines.push("--- YOUR NOTE FROM THE RECON PASS ---");
  lines.push(snapshot.secNote ?? "(no recon note was recorded)");
  lines.push("--- END OF NOTE ---");
  lines.push("");
  lines.push("Now enumerate the ATTACK SURFACE: the places in this project that an attacker can");
  lines.push("reach, and the places where something dangerous happens.");
  lines.push("");
  lines.push("  - **entrypoint** — a route, an RPC method, a CLI verb, a queue consumer, a");
  lines.push("    scheduled job, a file that gets parsed. Anything reachable from outside.");
  lines.push("  - **sink** — where something dangerous actually happens: an exec, a query, a");
  lines.push("    file write, a deserialize, a template render, a path built from input.");
  lines.push("  - **boundary** — where input crosses from unauthenticated to authenticated, and");
  lines.push("    what the check actually inspects.");
  lines.push("  - **file** — a source file worth reading closely even if you cannot yet say why.");
  lines.push("");
  const listed = snapshot.surfaces.length;
  if (listed >= SEC_SURFACE_SOFT_CAP) {
    lines.push(`**THE LIST IS ALREADY AT ${listed} ITEMS** (soft ceiling ${SEC_SURFACE_SOFT_CAP}), and every one of them costs a round.`);
    lines.push("Do NOT sweep again for its own sake. `sec_surface` only for a place that matters more than what is already waiting —");
    lines.push("the analysis is what produces findings, and a list nobody finishes produces none.");
  } else {
    lines.push(`Record each with \`sec_surface\`. Aim for 10-30 items — enough to cover the project,`);
    lines.push(`few enough that each one can get a full round of its own. (Soft ceiling: ${SEC_SURFACE_SOFT_CAP}.)`);
  }
  lines.push("");
  lines.push("**LIST THEM IN THE ORDER THEY SHOULD BE EXAMINED.** The loop takes the highest-priority");
  lines.push("open item each round, and everything you do NOT promote keeps THIS order — put the ones most");
  lines.push("likely to hold the objective first.");
  lines.push("");
  lines.push("**The order is NOT frozen.** When a later round reveals something more promising than what is");
  lines.push("left, send it to the front — `sec_surface ... priority=1` for a new place, or");
  lines.push("`sec_update <id> priority=1` for one you already listed. You know more in round 15 than you do");
  lines.push("now, and a plan written before you had read anything should not override that. Promote sparingly:");
  lines.push("the next brief tells you how many items are queued ahead of the plan.");
  lines.push("");
  lines.push("**These are COORDINATES, not claims.** `POST /diag/ping` is a place. You do NOT have");
  lines.push("to say what is wrong with it yet — that is what the analyze rounds are for. Listing a");
  lines.push("place you end up clearing is not a wasted item; it is a part of the project somebody");
  lines.push("looked at and found sound.");
  lines.push("");
  lines.push("If a category is already obvious (`rce`, `sqli`, `path-traversal`, …), pass it as");
  lines.push("`categories` — the analyze round then hands you that class's depth axes.");
  return lines.join("\n");
}
/**
 * A PURSUIT round: attack the gate of a finding that is one step from the objective.
 *
 * This brief exists because of a measured failure, and it is worth stating precisely because the
 * fix is aimed at exactly what happened. A critical RCE was recorded with `preAuth: false`; the loop
 * marked its surface item examined and went on enumerating. The operator then asked, in chat, "can
 * this be pre-auth?" — and that ONE question, in two exchanges, produced a critical pre-auth RCE:
 * they enumerated the unauthenticated entrypoints against the expression sink, queried the live
 * database for a usable share record, questioned that premise, and found the real flaw — the guard
 * read `request.getParameter("id")` (query string) while the handler read `@RequestBody.id`. The
 * loop contributed nothing to any of it.
 *
 * So this brief is NOT "go and think about the gate". It is a PLAYBOOK: the moves that actually
 * break a gate, ordered cheapest-and-most-decisive first, printed in full every round because the
 * failure mode was never "the model repeated an angle" — it was "the model never considered the
 * angles". The previous round's outcome is at the top, so a second round continues rather than
 * repeats.
 */
export function renderSecPursuitBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  finding: SecFinding,
  opts: SecBriefOptions = {},
): string {
  const budget = opts.pursuitBudget ?? 2;
  const spent = finding.pursuitSpent ?? 0;
  const gates = gatesOfFinding(finding);
  const reasons = depthReasons(finding, opts.probesAllowed === true);
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — PURSUE ${finding.id}]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  if (opts.lastRound) lines.push(opts.lastRound);
  const stall = renderStall(opts.loop ?? snapshot.loop);
  if (stall) lines.push(stall);
  if (opts.lastRound || stall) lines.push("");
  lines.push("--- THIS ROUND IS THIS FINDING, NOT THE WORK LIST ---");
  lines.push(`  ${finding.id}  [${finding.severity ?? "unrated"}] ${finding.category}`);
  lines.push(`  ${finding.title}`);
  if (finding.location) lines.push(`  at ${finding.location.file}:${finding.location.line}`);
  if (finding.preAuth === false) lines.push("  recorded as POST-AUTH — a session is required first");
  if (finding.preAuth === true) lines.push("  recorded as PRE-AUTH (the gate below is something else)");
  lines.push(`  PURSUIT ${spent}/${budget} — ${budget - spent} round(s) left on this finding`);
  lines.push("--- END ---");
  lines.push("");
  lines.push("**You found something real and it is ONE STEP from the objective. Do NOT go to the next**");
  lines.push("**surface item this round.** Everything else on the list can wait; this cannot, because");
  lines.push("closing the gate below is what turns this into the objective.");
  lines.push("");
  // WHY THIS FINDING — the depth reasons, so the round knows which playbook applies. A gate and
  // "there is more here" are different problems and deserve different rounds.
  lines.push("--- WHY THIS FINDING IS BEING DEEPENED ---");
  if (reasons.includes("gate")) lines.push("  - it is REAL but does not work yet — a gate is blocking it");
  if (reasons.includes("deepen")) lines.push("  - you recorded that there is MORE HERE (deepen=true) — this round finishes turning it over");
  if (reasons.includes("unproven")) lines.push("  - it has never been RUN — a claim with an artifact and no test");
  lines.push("--- END ---");
  lines.push("");
  if (gates.length > 0) {
    lines.push("--- THE GATE ---");
    for (const g of gates) lines.push(`  - ${g}`);
    lines.push("--- END ---");
    lines.push("");
  }

  // THE FIRST INSTRUCTION CAN BE AN EXIT. A post-auth finding is now a pursuit candidate
  // automatically, which means a run whose objective is NOT about pre-auth lands here on its first
  // high post-auth finding. One sentence closes it; without this line the mechanism would tax every
  // ordinary audit.
  if (finding.preAuth === false && (finding.blockers?.length ?? 0) === 0) {
    lines.push(`**FIRST: does this objective even care about pre-auth?** If \`${clip(objective, 100)}\``);
    lines.push("does not require reaching the sink without authentication, then this gate is not worth a");
    lines.push("round — close it and go back to the plan:");
    lines.push(`  \`sec_update ${finding.id} pursuitClosed="目标不要求认证前，该发现的认证后属性不构成缺口"\``);
    lines.push("Only continue if pre-auth reachability is what this run is FOR.");
    lines.push("");
  }

  if (gates.length > 0) {
  lines.push("--- HOW TO BREAK A GATE: four moves, in this order ---");
  lines.push("");
  lines.push("**MOVE 0 — VERIFY THE GATE ITSELF. Maybe it is not real.**");
  lines.push("The premise you recorded may be wrong, and this is the cheapest move because it needs no new");
  lines.push("entry: re-read the guard's ACTUAL body, not its name, and check what it really disables or");
  lines.push("enforces. Measured example from a real run: a template sandbox was recorded as complete because");
  lines.push("one line read `disableFeature(Feature.NewInstance)` — the library's default feature set is");
  lines.push("*fully* enabled, so `Use`, `StaticMethods` and `StaticFields` were wide open and code execution");
  lines.push("was reachable through `use java.lang.System; System.load(...)` with no `new` at all. That finding");
  lines.push("was re-graded from high to CRITICAL without ever attacking an entrypoint.");
  lines.push("Ask: which specific check makes this impossible, at which line, and does it check what its");
  lines.push("name claims? A `sanitize()` that concatenates is not a sanitizer; an `isValid()` that returns");
  lines.push("true on a missing field is not a check.");
  lines.push("");
  lines.push("**MOVE 1 — FIND AN ENTRY THAT SKIPS THE GATE ENTIRELY.**");
  lines.push("Do not hunt for a bypass of the check; hunt for a second door into the same SINK. Enumerate");
  lines.push("**every unauthenticated entrypoint you know of, crossed with this sink**, and ask of each pair:");
  lines.push("does attacker-controlled input from that entry reach the same dangerous call?");
  lines.push("  - the anonymous/public routes your recon found, and every `@NoAuth`-style annotation;");
  lines.push("  - a share/token/preview/explicitly-public route, and its whitelist in the config;");
  lines.push("  - an export/render/download variant of the same handler (`show`, `exportPdf`, `exportExcel`");
  lines.push("    usually share the whole data path — one guard, four entries);");
  lines.push("  - an internal/RPC/websocket/GraphQL entry that calls the same service method.");
  lines.push("This is where a run usually wins, because the sink is already proven and only the door is new.");
  lines.push("");
  lines.push("**MOVE 2 — PARAMETER SOURCE CONFUSION. The guard and the handler may read DIFFERENT inputs.**");
  lines.push("The single highest-yield auth-bypass pattern, and it is worth checking literally: for the SAME");
  lines.push("request, **where does the guard get the value it validates, and where does the handler get the");
  lines.push("value it acts on?** If they differ, put a legitimate value where the guard looks and the");
  lines.push("attacker's value where the handler looks.");
  lines.push("  - guard reads `request.getParameter(\"id\")` (query string) while the handler reads");
  lines.push("    `@RequestBody.id` (JSON body) → `?id=<a value the guard accepts>` with a different body id.");
  lines.push("    Measured: this exact mismatch turned a post-auth expression-injection into a CRITICAL");
  lines.push("    pre-auth RCE on a real target, and JSON bodies never enter `parameterMap`, so the two values");
  lines.push("    genuinely cannot agree by accident.");
  lines.push("  - guard checks the path prefix while the handler routes on a suffix; guard checks a header");
  lines.push("    the client controls, or a cookie whose signature is not verified; guard validates one id");
  lines.push("    and the handler resolves a second one from the same body.");
  lines.push("  - guard runs on `/api/**` while an identical handler exists under `/internal/**` or `/v2/**`.");
  lines.push("Read the guard's read side and the handler's read side as two separate code paths and diff them.");
  lines.push("");
  lines.push("**MOVE 3 — FIND THE DATA OR CONFIG THAT UNLOCKS IT.**");
  lines.push("Many gates are not code but STATE: a record, a token, a flag, a default. Go and look at the");
  lines.push("state instead of the code:");
  lines.push("  - **seed/fixture SQL and migration scripts in the repo** — plaintext tokens, default passwords");
  lines.push("    and demo share records are routinely checked in. A leaked token whose row is enabled is a");
  lines.push("    working bypass, and the repo is where it lives.");
  lines.push("  - the **shipped default** of the setting that gates you, and whether the default deployment");
  lines.push("    uses it (config files, env defaults, docker-compose, the example app's profile).");
  lines.push("  - whether the guard's own condition is satisfied by a record that ALREADY exists — a share");
  lines.push("    row, a public flag, a disabled feature. Query the state if the target is reachable.");
  lines.push("  - a **token that unlocks a different object than the one being protected**: check whether the");
  lines.push("    guard validates the OBJECT it was given, or only that A valid token exists somewhere.");
  lines.push("");
  lines.push("**MOVE 4 — TEST IT. A gate you only READ is a gate you may have misread.**");
  lines.push("You have tools. If a live instance is reachable, send the request — do not stop at \"the code");
  lines.push("says this is blocked\". A 500 carrying your own string, or a response body whose length changes");
  lines.push("with your input, is proof that beats any reading. `sec_verify` records the run so the finding");
  lines.push("becomes REPRODUCED instead of static; plain `bash` (curl, docker, mysql) works too, as long as");
  lines.push("what you learn ends up recorded here.");
  lines.push("");
  } else {
    renderNonGateDepth(lines, finding);
  }
  lines.push("--- THE DEPTH AXES FOR THIS KIND OF PROBLEM ---");
  lines.push(renderSecLadder("auth-bypass"));
  lines.push("");
  lines.push("--- HOW THIS ROUND CAN END ---");
  lines.push("**The gate opened** → record the ENABLING thing as its own finding (`sec_finding`, with its own");
  lines.push("artifact — an auth bypass IS a finding, not a footnote), then update this one:");
  lines.push(`  \`sec_update ${finding.id} blockers=[]\``);
  lines.push(`  \`sec_update ${finding.id} preAuth=true\``, "   (if it is now reachable pre-auth)");
  lines.push("  or link them so the report can state the chain:");
  lines.push(`  \`sec_update ${finding.id} chainOf=[<new finding id>, ${finding.id}]\``);
  lines.push("**The gate is still closed, and you know more now** → refine it. Replace the blocker text with");
  lines.push("what you actually established. A refined blocker is progress; the same text is not.");
  lines.push("**The gate cannot be opened** → close the pursuit with the reason, so the report says the");
  lines.push("finding was ATTACKED rather than forgotten:");
  lines.push(`  \`sec_update ${finding.id} pursuitClosed="试过 <哪几条路>：<为什么每条都不成立>"\``);
  lines.push("**A new place the pursuit revealed** → `sec_surface` it (it joins the plan, and the loop");
  lines.push("returns to the plan when this gate is settled).");
  lines.push("");
  lines.push(`**A note on the budget:** this finding gets ${budget} pursuit round(s) in total. Past that it is`);
  lines.push("left as a recorded near miss and the loop goes back to the list — a pursuit that never ends");
  lines.push("is the same as never deciding.");
  lines.push("");
  lines.push(renderFoundSoFar(snapshot));
  lines.push("");
  lines.push(`(wider context lives in \`${SEC_STATE_DIR_NAME}/recon.md\` — this run's ceiling.)`);
  return lines.join("\n");
}

/**
/**
 * Round 3..N: work ONE item on the list, all the way down.
 *
 * The loop ASSIGNS the item, and that is the point: the analysis is systematic rather
 * than whatever the model felt like reading, and a round cannot drift onto something
 * else because it found the assigned item uninteresting.
 */
export function renderSecAnalyzeBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  item: SecSurface,
  opts: SecBriefOptions = {},
): string {
  const digBudget = opts.digBudget ?? SEC_DIG_BUDGET;
  const lines: string[] = [];
  lines.push(`[SEC ROUND ${round} — ANALYZE ${item.id}]`);
  lines.push("");
  lines.push(`Objective: ${objective}`);
  lines.push("");
  // The two lines that were missing entirely: what just happened, and how close the run is
  // to being stopped because of it.
  if (opts.lastRound) lines.push(opts.lastRound);
  const stall = renderStall(opts.loop ?? snapshot.loop);
  if (stall) lines.push(stall);
  if (opts.lastRound || stall) lines.push("");
  lines.push("--- THIS ROUND IS THIS ITEM ---");
  lines.push(`  ${item.id}  [${item.kind}]  ${item.title}`);
  if (item.location) lines.push(`  at ${item.location.file}:${item.location.line}`);
  if (item.categories && item.categories.length > 0) lines.push(`  classes to check: ${item.categories.join(", ")}`);
  if (item.status === "digging") {
    lines.push(`  CONTINUING — depth round ${item.digRounds ?? 0}/${digBudget} on this item`);
  }
  lines.push("--- END ---");
  lines.push("");
  // POINT AT THE CEILING. The recon note is the run's whole scope statement and this round is
  // narrow by design — but an item sometimes needs the wider context (how auth is wired, what
  // was never read). The note is mirrored to a file so the model can re-read it instead of
  // working from a memory of it that has been through twenty rounds of context compaction.
  lines.push(`(wider context lives in \`${SEC_STATE_DIR_NAME}/recon.md\` — this run's ceiling. Read it if this`);
  lines.push("item turns on something the note covered, and check what the note says was never read.)");
  lines.push("");
  // THE ATTEMPT COUNT IS A FACT THE MODEL CAN ACT ON. Without it the brief looked identical
  // on the first and the fifth round on one item, and a model that kept reading and recording
  // nothing never learned that the item was about to fall to the back of the queue.
  //
  // EXHAUSTED has two forms and both get the warning: the attempt cap on an open item, and a
  // dig budget that was SPENT without a conclusion (a mid-dig item past its budget used to
  // escape the warning and keep being handed rounds with digRounds growing past the budget).
  const attemptsGone = (item.attempts ?? 0) >= MAX_ITEM_ATTEMPTS;
  const digGone = item.status === "digging" && (item.digRounds ?? 0) >= digBudget;
  if (attemptsGone || digGone) {
    const rounds = attemptsGone ? `${item.attempts} ROUNDS` : `${item.digRounds} DIG ROUNDS + THIS ONE`;
    lines.push(`**THIS ITEM HAS HAD ${rounds} AND NO CONCLUSION RECORDED.** It has been dropped to the`);
    lines.push("back of the queue — other items are being analysed first now. This round MUST end in one of:");
    lines.push("  - `sec_finding` — you found something; record it with its artifact;");
    lines.push("  - `sec_clear` — you traced it and found the guard; NAME the guard and where it is;");
    if (!digGone) lines.push("  - `sec_dig` — you are close and need one more round on it;");
    lines.push("  - `sec_update <id> priority=1` — it deserves to come back to the front.");
    lines.push("Recording nothing again keeps it at the back and burns a round in the plateau window.");
    lines.push("");
  } else if ((item.attempts ?? 0) > 0) {
    lines.push(`  (round ${(item.attempts ?? 0) + 1} on this item — a conclusion is expected this time.)`);
    lines.push("");
  }
  lines.push(
    "**Analyse THIS item all the way down.** Do not switch to another — every item on the list gets a round",
  );
  lines.push("of its own, and one abandoned half way never gets looked at like this again.");
  lines.push("");
  lines.push("--- HOW TO ANALYSE ---");
  lines.push("Trace the **complete data flow**, one step at a time:");
  lines.push("  1. **ENTRY** — how does control reach this item? Which route, function or event hands it over?");
  lines.push("  2. **CONTROLLED INPUT** — which parts are attacker-controlled? What constrains format, length, encoding?");
  lines.push("  3. **THE CHECK** — is there validation, escaping, an auth check, a cast? **Read the check itself**,");
  lines.push("     not its name. A function called `sanitize` that concatenates is not a sanitizer.");
  lines.push("  4. **SINK** — which exact call does the dangerous thing, and is its argument built by concatenation");
  lines.push("     or passed through untouched?");
  lines.push("");
  lines.push("**Trace it ALL before concluding.** Stopping half way is guessing, and a guess written into the");
  lines.push("report is one a reader cannot tell apart from a checked conclusion.");
  lines.push("");
  for (const category of item.categories ?? []) {
    lines.push(renderSecLadder(category));
    lines.push("");
  }
  lines.push("--- ALREADY CLEARED ---");
  const cleared = snapshot.surfaces.filter((s) => s.status === "cleared");
  if (cleared.length === 0) {
    lines.push("(nothing yet)");
  } else {
    lines.push("These items have been examined and found guarded — do not re-examine them:");
    // WAS `slice(-12)`. Past twelve clearances the oldest reasons fell out of the brief, so
    // the model could not tell WHY an area had been ruled out — and a model that cannot see
    // its own exclusions will re-litigate them, or contradict them. The count is stated
    // rather than silently implied by the list length.
    const CLEARED_SHOWN = 40;
    for (const s of cleared.slice(-CLEARED_SHOWN)) {
      lines.push(`  ${s.id}  ${clip(s.title, 80)} — ${clip(s.clearedReason ?? "", 90)}`);
    }
    if (cleared.length > CLEARED_SHOWN) {
      lines.push(`  … +${cleared.length - CLEARED_SHOWN} earlier clearance(s), not shown — they are in the report.`);
    }
  }
  lines.push("");
  const diggingText = renderDigging(snapshot, digBudget);
  if (diggingText) {
    lines.push(diggingText);
    lines.push("");
  }
  lines.push(renderFoundSoFar(snapshot));
  lines.push("");
  // The promoted count, so over-promoting is a FACT the model can act on rather than a
  // silent reorder it cannot see. No cap: the honest defence is visibility.
  if (snapshot.surfaces.filter((s) => (s.priority ?? 0) > 0 && s.status === "open").length > 0) {
    const ahead = snapshot.surfaces.filter((s) => (s.priority ?? 0) > 0 && s.status === "open");
    lines.push(`QUEUED AHEAD OF THE PLAN (${ahead.length}):`);
    for (const s of ahead.slice(0, 8)) lines.push(`  ${s.id} [p${s.priority}] ${clip(s.title, 70)}`);
    lines.push("These are analysed before the plan order. If that list is growing faster than you clear it,");
    lines.push("you are not re-prioritising — you are thrashing.");
    lines.push("");
  }
  // THE COMBINATION QUESTION, and it is asked on EVERY analyze round.
  //
  // Without it nothing in this mode ever suggests that two findings might be one bug,
  // and `renderFoundSoFar` hands over a flat list with no hint that F-0001 and F-0007
  // could be a chain. That is how the highest-severity findings work: an arbitrary file
  // write alone is medium, and the same file write plus "the config it lands in is
  // exec'd" is root code execution. A report that lists those as two separate medium
  // findings and never says the word has missed the finding.
  //
  // Combination is ORTHOGONAL to the assertion gate — the gate is what this mode drops,
  // and chaining was never about assertions.
  if (snapshot.findings.length > 0) {
    lines.push("--- DOES THIS COMBINE? ---");
    lines.push("**Does what you are looking at now, together with something ALREADY RECORDED, reach");
    lines.push("somewhere neither reaches alone?** If so, record the chain as its own finding:");
    lines.push("  `sec_finding title=\"...\" category=\"...\" chainOf=[\"F-0001\", \"F-0007\"]`");
    lines.push("A chain needs NO artifact of its own — its artifact IS its parts, each of which already carries");
    lines.push("one. Say what the two reach together, and what an attacker gains from it.");
    lines.push("");
  }
  lines.push("--- HOW THIS ROUND CAN END ---");
  lines.push("**Found something** → `sec_finding`, with `surfaceId` pointing back at this item, and an artifact");
  lines.push("(`file`+`line` or an `evidence` excerpt).");
  lines.push("**Found something REAL but GATED** → `sec_finding` it anyway, and pass `blockers` — what");
  lines.push("must hold for it to be exploitable as recorded (\"需要一个有效的管理员会话\", \"需要 attacker");
  lines.push("控制 X-Forwarded-Host\"). A gated HIGH finding is the most valuable thing you can record:");
  lines.push("the loop then spends its next rounds attacking that gate INSTEAD of the next item on the list,");
  lines.push("because closing it converts the finding into the objective. Do not file it as a near miss and");
  lines.push("move on — that is what this field exists to prevent.");
  lines.push("**Found something HIGH but POST-AUTH?** Then you have recorded a GATE, whether or not you pass");
  lines.push("`blockers` — the loop treats `preAuth=false` at HIGH-or-worse as a gate in its own right and will");
  lines.push("spend its next rounds trying to open it. So record what you already know about why it needs a");
  lines.push("session: which check enforces it, at which line, and whether that check reads the same input the");
  lines.push("handler acts on. That note is what the depth round starts from.");
  // THE GENERAL DEPTH REFLEX, and the reason it is an explicit flag: the plugin cannot tell "a proven
  // primitive nobody exercised" from ordinary prose, so it asks the model — at the moment it knows.
  lines.push("**Anything else that opened something up?** Set `deepen=true` on the finding and the loop will");
  lines.push("spend its next rounds deepening THAT instead of moving to the next item on the list. Use it when");
  lines.push("the round produced something worth turning over: a primitive you proved but never exercised, a");
  lines.push("root cause that probably holds in five more handlers, a piece that only becomes dangerous when");
  lines.push("combined with another finding. Do NOT set it on every finding — a depth round is the expensive");
  lines.push("kind, and the loop is asking you to spend them where you believe there is more.");
  lines.push("**The call chain goes in `path`**, one step per hop with a `file:line` on each — not buried in");
  lines.push("`reasoning`; a reader scans a numbered list and cannot scan prose for a path. Keep `reasoning` for");
  lines.push("why it matters, what it costs, and what you could not settle.");
  lines.push("**Guarded** → `sec_clear`, saying WHICH guard you found and where. \"Nothing found\" is not a");
  lines.push("reason — it is the absence of one, and a clearance nobody can check protects nothing.");
  lines.push("**Not finished** → `sec_dig`, and this item comes back to you NEXT round. Budgeted at " +
  digBudget + " round(s); a trace that never ends is the same as never deciding.");
  lines.push("**A new place revealed by the analysis** → `sec_surface` it now, and `priority=1` if it beats what");
  lines.push("is left; **an item you already listed now more promising** → `sec_update <id> priority=1`. The plan");
  lines.push("is not frozen: it was written before you had read anything.");
  if (snapshot.surfaces.length >= SEC_SURFACE_SOFT_CAP) {
    lines.push(`The list is at ${snapshot.surfaces.length} items (soft ceiling ${SEC_SURFACE_SOFT_CAP}) — there is more listed than can be finished.`);
    lines.push("Add only what matters more than what is already waiting.");
  }
  lines.push("**Clearing an item is a RESULT** — it is what stops the next round re-reading the same file.");
  return lines.join("\n");
}

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

function clip(text: string, max: number): string {
  const t = (text ?? "").replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function compareFinding(a: SecFinding, b: SecFinding): number {
  const ra = a.severity ? severityRank(a.severity) : 99;
  const rb = b.severity ? severityRank(b.severity) : 99;
  if (ra !== rb) return ra - rb;
  return a.id.localeCompare(b.id);
}

export interface SecReportOptions {
  /** ISO timestamp to stamp the report with. */
  at?: string;
  coverageReport?: CoverageReport;
  /** The reader's language. Defaults to Chinese — see settings.reportLanguage. */
  language?: ReportLanguage;
  /** The language tag the content fences open with. See settings.fenceLanguage. */
  fenceLanguage?: string;
  /**
   * Whether `sec_verify` is enabled, so the report can name the SAME depth reasons the loop used.
   *
   * Passed in rather than re-derived, because a report that recomputed them could disagree with the
   * rounds it is describing — the depth reflex is judged with this flag, and the report must print
   * the judgement that actually happened. Omitted means `false`, which under-reports `unproven`
   * rather than inventing it.
   */
  probesAllowed?: boolean;
  /** The depth budget per finding, so `已花 N/M 轮` can print the M. See settings.pursuitRounds. */
  pursuitBudget?: number;
}

/** Findings grouped by severity, worst first, with the unrated last. */
export function secFindingsBySeverity(snapshot: TreeSnapshot): { rated: SecFinding[]; unrated: SecFinding[] } {
  const sorted = [...snapshot.findings].sort(compareFinding);
  return { rated: sorted.filter((f) => f.severity), unrated: sorted.filter((f) => !f.severity) };
}

export function renderSecReport(
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): string {
  const at = opts.at ?? nowIso();
  const coverage = opts.coverageReport ?? null;
  const lang: ReportLanguage = opts.language ?? "zh";
  const fenceLanguage = opts.fenceLanguage ?? "c";
  const t = secStrings(lang);
  // One object rather than two more positional parameters — `renderSecFinding` already takes five, and
  // the next thing the report needs to name will be a third.
  const depthCtx: DepthCtx = {
    probesAllowed: opts.probesAllowed ?? false,
    pursuitBudget: opts.pursuitBudget ?? 0,
  };
  const lines: string[] = [];
  const findings = snapshot.findings;
  const { rated, unrated } = secFindingsBySeverity(snapshot);
  const preAuth = findings.filter((f) => f.preAuth === true).length;

  lines.push(t.title);
  lines.push("");
  lines.push(t.generatedFrom);
  lines.push("");
  // A DEEP REPORT AND A SWEEP REPORT ARE OTHERWISE ALMOST IDENTICAL — same sections, same finding
  // format — and the difference is the first thing a reader needs: this run worked ONE finding for
  // many rounds, so "20 rounds, 1 finding" is not a thin result, it is the shape of the run.
  const deep = loop?.deep ?? snapshot.loop?.deep;
  if (deep) {
    lines.push(t.deepBanner(deep.findingId, deep.title, deep.parentDir));
    // The steer is printed because a reader of a deep report has to know whether the run chose its
    // direction or was pointed at one — otherwise a thin result along the operator's axis reads as the
    // run's own judgement.
    if (deep.directive) {
      lines.push(">");
      lines.push(t.deepDirective(deep.directive));
    }
    lines.push("");
  }
  lines.push(`- **${t.objective}**: \`${snapshot.objective || loop?.objective || "(none)"}\``);
  lines.push(`- **${t.generatedAt}**: ${at}`);
  if (loop) {
    lines.push(`- **${t.run}**: sec · ${loop.status} · round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""}`);
    const timing = loopTiming(loop, Date.parse(at) || Date.now());
    if (timing) lines.push(`- **${t.duration}**: ${formatDuration(timing.activeMs)}`);
    lines.push(`- **${t.stoppedBecause}**: ${loop.stopReason ?? loop.pausedReason ?? t.stillRunning}`);
  }
  lines.push("");

  // ---- THE CAVEAT, BEFORE THE FINDINGS ------------------------------------
  //
  // Placed here rather than at the foot, and that is deliberate. Everywhere else in
  // this extension the non-claims go last; here the reader is about to scroll a list
  // of findings GROUPED BY SEVERITY, and severity is exactly the field this mode
  // does not check. A reader who meets the caveat afterwards has already formed the
  // wrong impression.
  lines.push(t.caveatTitle);
  lines.push("");
  lines.push(t.caveatIntro);
  lines.push("");
  lines.push(`| ${t.caveatColMissing} | ${t.caveatColMeans} |`);
  lines.push("|---|---|");
  lines.push(`| ${t.caveatNoTier} | ${t.caveatNoTierWhy} |`);
  lines.push(`| ${t.caveatNoFalsification} | ${t.caveatNoFalsificationWhy} |`);
  lines.push(`| ${t.caveatNoChallenge} | ${t.caveatNoChallengeWhy} |`);
  lines.push(`| ${t.caveatNoSeverity} | ${t.caveatNoSeverityWhy} |`);
  lines.push(`| ${t.caveatNoGate} | ${t.caveatNoGateWhy} |`);
  lines.push("");
  lines.push(t.caveatEnforced);
  lines.push("");
  lines.push(t.caveatRerun);
  lines.push("");

  // ---- summary ------------------------------------------------------------
  lines.push(t.summaryTitle);
  lines.push("");
  lines.push("| | |");
  lines.push("|---|---|");
  lines.push(`| ${t.rowFindings} | ${findings.length} |`);
  for (const sev of SEVERITIES) {
    const n = rated.filter((f) => f.severity === sev).length;
    if (n > 0) lines.push(`| ${severityLabel(sev, lang)} | ${n} |`);
  }
  if (unrated.length > 0) lines.push(`| ${t.rowUnrated} | **${unrated.length}** |`);
  // Chains first among the counts, because they are the findings that say something no
  // single finding can.
  const chains = findings.filter((f) => f.chainOf && f.chainOf.length >= 2);
  if (chains.length > 0) lines.push(`| ${t.rowChains} | **${chains.length}** |`);
  // THE NEAR MISSES, counted separately, because they are what the run is DOING rather than what it
  // HAS. A high finding whose gate is still open is one pursuit away from the objective, and a
  // reader watching a run should be able to see that at a glance instead of inferring it from the
  // per-finding blocks.
  // `gatesOfFinding`, not `f.blockers`: a POST-AUTH finding has an IMPLICIT gate, and counting only
  // explicit blockers made exactly the near miss this report exists to surface invisible in the
  // summary — the finding that is one step from the objective did not appear in the count.
  const gated = findings.filter((f) => gatesOfFinding(f).length > 0 && !f.pursuitClosed);
  if (gated.length > 0) {
    lines.push(`| ${t.rowGated(gated.length, findings.length)} | **${gated.length}/${findings.length}** |`);
  }
  lines.push(`| ${t.rowPreAuth} | ${preAuth} |`);
  lines.push(`| ${t.rowPostAuth} | ${findings.filter((f) => f.preAuth === false).length} |`);
  lines.push(`| ${t.rowUnassessed} | ${findings.filter((f) => typeof f.preAuth !== "boolean").length} |`);
  lines.push(`| ${t.rowNote} | ${snapshot.secNote ? t.yes : t.no} |`);
  // How much reconnaissance the run actually did, because it bounds every finding below it:
  // "1 section" means the surface list was built from a single pass over a codebase that did
  // not fit in one turn. The note itself is not printed here (it is long) — it is at
  // `.pi-loopsec/recon.md`, and a reader who wants to judge the coverage should read it.
  const sections = reconSections(snapshot);
  if (snapshot.loop?.deep) {
    // A DEEP RUN HAS NO RECON PHASE, and printing "0 rounds" would read as a gap where there is a
    // different design: it was opened FROM a finding, so the context is the seed, not a pass over the
    // project. The count would be misleading in either direction, so the row says what happened.
    lines.push(`| ${t.rowDeepSeed} | ${snapshot.secNote ? t.yes : t.no} |`);
  } else if (sections > 0) {
    lines.push(`| ${t.rowReconRounds} | ${sections}（\`${SEC_STATE_DIR_NAME}/recon.md\`） |`);
  }
  lines.push("");
  // THE VERIFICATION SPLIT, stated in the summary rather than left for the reader to
  // reconstruct from per-finding blocks. "How many of these did somebody actually RUN" is
  // the first question a reader has about a list grouped by severity, and the answer is a
  // count, not a scrolling exercise.
  //
  // `confirmed` is exact (the stored verdict) and "run at all" is a different, weaker fact
  // — a DISCONFIRMED run is still a run, and it belongs in the second bucket's denominator,
  // not hidden inside "static claims".
  const verified = findings.filter((f) => f.verification?.confirmed === true).length;
  const ranUnconfirmed = findings.filter((f) => f.verification && !f.verification.confirmed).length;
  if (findings.length > 0) {
    lines.push(`| ${t.rowVerified} | **${verified}/${findings.length}** |`);
    if (ranUnconfirmed > 0) {
      lines.push(`| ${t.rowUnverified} | ${findings.length - verified} |`);
    }
    lines.push("");
    if (verified > 0 || ranUnconfirmed > 0) {
      lines.push(t.probesOnNote(verified, findings.length));
    } else {
      lines.push(t.probesOffNote(verified, findings.length));
    }
    lines.push("");
  }
  if (findings.length === 0) {
    lines.push(deep ? t.noFindingsDeep : t.noFindings);
    lines.push("");
  }

  // ---- coverage -----------------------------------------------------------
  if (coverage) {
    lines.push(t.coverageTitle);
    lines.push("");
    lines.push(`| | |`);
    lines.push(`|---|---|`);
    lines.push(`| ${t.rowCited} | ${coverageHeadline(coverage, lang)} |`);
    lines.push(`| ${t.rowGapDirs} | ${coverage.gaps.length} |`);
    lines.push("");
    if (coverage.projectFiles === null) {
      lines.push(t.coverageNotMeasured(coverage.reason));
    } else if (coverage.gaps.length === 0) {
      lines.push(t.coverageNoGap);
    } else {
      lines.push(t.coverageGapNote);
      lines.push("");
      for (const gap of coverage.gaps) lines.push(t.coverageGapLine(gap.dir, gap.files));
    }
    lines.push("");
  }

  // ---- the attack surface ---------------------------------------------
  //
  // BEFORE the findings, because it is the answer to the question the findings cannot
  // answer: how much of this project did the run actually analyse. A list of findings
  // with no denominator reads as "this is what there is"; with one it reads as "this is
  // what was found in the part that was looked at".
  const progress = surfaceProgress(snapshot);
  lines.push(deep ? t.questionTitle : t.surfaceTitle);
  lines.push("");
  if (progress.total === 0) {
    lines.push(t.surfaceNone);
    lines.push("");
  } else {
    lines.push(deep ? t.questionIntro : t.surfaceIntro);
    lines.push("");
    lines.push("| | |");
    lines.push("|---|---|");
    lines.push(`| ${t.rowSurfaceTotal} | ${progress.total} |`);
    lines.push(`| ${t.rowSurfaceExamined} | **${progress.examined}** (${pct(progress.examined, progress.total)}%) |`);
    lines.push(`| ${t.rowSurfaceCleared} | ${progress.cleared} |`);
    lines.push(`| ${t.rowSurfaceProductive} | ${progress.productive} |`);
    if (progress.digging > 0) lines.push(`| ${t.rowSurfaceDigging} | ${progress.digging} |`);
    const unresolved = snapshot.surfaces.filter((x) => x.status === "open" && (x.attempts ?? 0) > 0).length;
    if (unresolved > 0) lines.push(`| ${t.rowSurfaceAttempted} | ${unresolved} |`);
    // THE COST OF ENUMERATION, stated rather than hidden.
    //
    // A surface round is a full model turn, and the loop runs one every time the list
    // empties — so the share is 1/(k+1) for a sweep of k items. A model that sweeps
    // 10-30 items spends under 10% of its turns here; one that adds a single item per
    // sweep spends HALF. Nothing about that is wrong (the run still progresses, and
    // measured over 200 rounds a one-item sweep still produced 12 findings and never
    // repeated an item) but it is the operator's compute and they should be able to
    // see where it went.
    const secRounds = snapshot.roundRecords.filter((r) => r.findingCountAtStart !== undefined);
    const surfaceRounds = secRounds.filter((r) => r.kind === "surface").length;
    if (secRounds.length > 0) {
      lines.push(
        `| ${t.rowSurfaceRounds} | ${surfaceRounds}/${secRounds.length} (${pct(surfaceRounds, secRounds.length)}%) |`,
      );
    }
    lines.push("");
    if (progress.open === 0) {
      lines.push(t.surfaceAllExamined);
      lines.push("");
    }
  }

  // ---- the chains ---------------------------------------------------------
  //
  // BEFORE the findings, because they are the heaviest thing in the document and a
  // reader who scrolls a list of individual findings has to assemble them by hand.
  if (chains.length > 0) {
    lines.push(t.chainTitle);
    lines.push("");
    lines.push(t.chainNote);
    lines.push("");
    const byId = new Map(findings.map((f) => [f.id, f]));
    for (const c of chains) {
      const parts = (c.chainOf ?? [])
        .map((id) => (byId.has(id) ? `${id} (${clip(byId.get(id)!.title, 70)})` : id))
        .join(" + ");
      lines.push(t.chainLine(c.id, c.severity ? severityLabel(c.severity, lang) : t.rowUnrated.replace(/\*/g, ""), c.title, parts));
    }
    lines.push("");
  }

  // ---- the findings -------------------------------------------------------
  lines.push(t.findingsTitle(findings.length));
  lines.push("");
  if (findings.length === 0) {
    lines.push(t.noneRecorded);
    lines.push("");
  } else {
    [...rated, ...unrated].forEach((f, i) =>
      lines.push(...renderSecFinding(f, i + 1, t, lang, fenceLanguage, depthCtx)),
    );
  }

  // ---- what was not read --------------------------------------------------
  const diggingItems = snapshot.surfaces.filter((s) => s.status === "digging");
  if (diggingItems.length > 0) {
    lines.push(t.diggingTitle);
    lines.push("");
    lines.push(t.diggingNote);
    lines.push("");
    for (const s of diggingItems) {
      lines.push(t.diggingLine(s.id, s.title, s.digRounds ?? 0, SEC_DIG_BUDGET));
    }
    lines.push("");
  }
  // SPLIT IN TWO, because the old single list was lying. Every `open` item was printed under
  // 尚未分析 with "没看过" — including items the run HAD looked at and left unresolved, which is
  // the ordinary outcome of a round that produces nothing. On a run with unproductive rounds
  // that was most of the list, and the section that exists to bound the audit's honesty was
  // making the audit look narrower than it was.
  const openItems = snapshot.surfaces.filter((s) => s.status === "open" && (s.attempts ?? 0) === 0);
  if (openItems.length > 0) {
    lines.push(t.surfaceOpenTitle);
    lines.push("");
    lines.push(t.surfaceOpenNote);
    lines.push("");
    for (const s of openItems) {
      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : ""));
    }
    lines.push("");
  }
  const touchedItems = snapshot.surfaces.filter((s) => s.status === "open" && (s.attempts ?? 0) > 0);
  if (touchedItems.length > 0) {
    lines.push(t.surfaceTouchedTitle);
    lines.push("");
    lines.push(t.surfaceTouchedNote);
    lines.push("");
    for (const s of touchedItems) {
      lines.push(t.surfaceOpenLine(s.id, s.kind, s.title, s.location ? `${s.location.file}:${s.location.line}` : ""));
    }
    lines.push("");
  }
  const clearedItems = snapshot.surfaces.filter((s) => s.status === "cleared");
  if (clearedItems.length > 0) {
    lines.push(t.surfaceClearedTitle);
    lines.push("");
    lines.push(t.surfaceClearedNote);
    lines.push("");
    for (const s of clearedItems) {
      const guard = s.guardLocation ? `${s.guardLocation.file}:${s.guardLocation.line}` : "（未记录位置）";
      lines.push(t.surfaceClearedLine(s.id, s.title, s.clearedReason ?? "", guard));
    }
    lines.push("");
  }
  // A DEEP RUN DOES NOT PRINT THE COVERAGE-GAP LIST.
  //
  // "These directories were never read" is a statement about a SWEEP — it answers "how much of this
  // project did the run analyse". A deep run has one target and never claimed to read the rest, so the
  // list is a category error: it reads as a gap where there is a different design, and on a large
  // project it buries the single finding the report is about. The deep banner already says the run is
  // scoped to one finding, which is the honest version of the same fact.
  if (coverage && coverage.gaps.length > 0 && !deep) {
    lines.push(t.notReadTitle);
    lines.push("");
    lines.push(t.notReadNote);
    lines.push("");
    for (const gap of coverage.gaps) lines.push(t.coverageGapLine(gap.dir, gap.files));
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(t.footer);
  lines.push("");
  return lines.join("\n");
}

/** A whole-number percentage, for the examined/total ratio. */
function pct(part: number, whole: number): number {
  return whole === 0 ? 0 : Math.round((part / whole) * 100);
}

/**
 * One finding, ordered the way a hunter reads it.
 *
 *   what it is       the title, as a blockquote so it reads as the CLAIM
 *   where / auth     ONE line, not four labelled ones
 *   how to run it    the PoC — BEFORE the chain, because a hunter wants to paste it
 *   the call chain   a fenced NUMBERED list of file:line steps, when one was recorded
 *   notes            the prose, when a structured chain exists as well
 *   the evidence     the artifact
 *
 * The old order was 位置 / 来自攻击面 / 是否需要身份认证 / 记录于 / 为什么 / 物证 / PoC —
 * seven blocks, four of them labels, the PoC LAST, and the chain buried in Chinese prose
 * where the `file:line` references could not be scanned. Measured on a real X-Road
 * report: 27-102 lines per finding, 8-9 of them metadata and 2 a disclaimer the preamble
 * already carried.
 */
/** What `renderSecFinding` needs to name the SAME depth judgement the loop made. */
interface DepthCtx {
  probesAllowed: boolean;
  pursuitBudget: number;
}

function renderSecFinding(
  f: SecFinding,
  index: number,
  t: SecStrings,
  lang: ReportLanguage,
  fenceLanguage: string,
  depthCtx: DepthCtx,
): string[] {
  const lines: string[] = [];
  const sev = f.severity ? severityLabel(f.severity, lang) : t.rowUnrated.replace(/\*/g, "");
  lines.push(`### ${index}. ${f.id} · ${sev} · ${f.category}`);
  lines.push("");
  lines.push(`> ${f.title}`);
  lines.push("");

  // ONE metadata line. A hunter needs to know where it is and whether it needs auth;
  // the round and the surface item are for tracing it back, and none of them deserves
  // a label of its own.
  const meta: string[] = [];
  if (f.location) meta.push(`\`${f.location.file}:${f.location.line}\``);
  meta.push(
    `${t.authShort}${f.preAuth === true ? t.authPre : f.preAuth === false ? t.authPost : t.authUnassessed}`,
  );
  meta.push(t.roundShort(f.round));
  if (f.surfaceId) meta.push(t.surfaceShort(f.surfaceId));
  if (f.chainOf && f.chainOf.length > 0) {
    meta.push(t.chainOfLabel(f.chainOf.map((id) => `\`${id}\``).join(" + ")).replace(/\*\*/g, ""));
  }
  lines.push(meta.join(t.metaSeparator));
  lines.push("");

  // WHY THE RUN WENT DEEP ON THIS ONE, and how much of the budget that has cost.
  //
  // The depth reflex is the whole reason a breakthrough is pursued instead of filed, and it left no
  // trace in the report: a reader could see that a finding had been pursued only when it carried a
  // gate, because that is the one case the gate block prints. An UNGATED finding that the run
  // stopped everything to finish looked exactly like one it never touched.
  //
  // The reasons come from `depthReasons`, the same function the loop ranks with, fed the same
  // `probesAllowed` — so the report cannot describe a different judgement than the one made.
  if (f.deepen === true || (f.pursuitSpent ?? 0) > 0) {
    const reasons = depthReasons(f, depthCtx.probesAllowed);
    const named = reasons
      .map((r) =>
        r === "gate" ? t.depthReasonGate : r === "deepen" ? t.depthReasonDeepen : t.depthReasonUnproven,
      )
      .join("；");
    lines.push(t.depthLine(named, f.pursuitSpent ?? 0, depthCtx.pursuitBudget));
    lines.push("");
  }

  // The tag goes on the OPENING fence only: a closing fence must be bare, or the
  // renderer reads it as content.
  const fenced = (label: string, body: string): void => {
    lines.push(label);
    lines.push("");
    const fence = fenceFor(body);
    lines.push(fence + fenceLanguage);
    for (const line of body.split("\n")) lines.push(line);
    lines.push(fence);
    lines.push("");
  };

  if (f.poc) fenced(t.pocHeading, f.poc);

  // ---- the GATE, when the finding is real but not yet reachable -----------------------
  //
  // BEFORE the PoC, because it changes how everything below should be read: a post-auth RCE on a
  // pre-auth objective is not a pre-auth finding, and the gate is the difference. It also carries
  // the PURSUIT outcome, so "we attacked this gate and could not open it" is distinguishable from
  // "nobody ever tried" — the same distinction the rest of this report is built on.
  //
  // `gatesOfFinding` decides, not `f.blockers`: a POST-AUTH finding has an IMPLICIT gate even when
  // nobody wrote a blocker list, and printing the gate is how a reader sees that the run treated it
  // as a near miss rather than filing it.
  const gateList = gatesOfFinding(f);
  if (gateList.length > 0 || f.pursuitClosed) {
    const gateBody: string[] = [];
    for (const b of gateList) gateBody.push(`- ${b}`);
    if (gateList.length === 0) gateBody.push(t.gateOpen);
    gateBody.push("");
    gateBody.push(f.pursuitClosed ? t.pursuitClosed(f.pursuitSpent ?? 0, f.pursuitClosed) : t.pursuitOpen(f.pursuitSpent ?? 0));
    fenced(t.gateHeading, gateBody.join("\n"));
  }

  if (f.path && f.path.length > 0) {
    // The numbered list, with the location on its own line above the detail — so the
    // `file:line` column can be read down the page instead of hunted for in a sentence.
    const body = f.path
      .map((step, i) =>
        step.file
          ? `${i + 1}. ${step.file}${step.line ? `:${step.line}` : ""}\n   ${step.detail}`
          : `${i + 1}. ${step.detail}`,
      )
      .join("\n");
    fenced(t.chainHeading, body);
  }

  if (f.reasoning) {
    // The sink→source reasoning ALWAYS gets the fence, whether or not a structured
    // chain exists beside it. Unfenced prose broke the page in the reader's eyes:
    // `**` markers render as literal asterisks in plain text, `file:line` refs get
    // lost in the paragraph, and the section stopped looking like the sibling of
    // 怎么打 / 调用链 above it. Same section, same shape.
    fenced(t.notesHeading, f.reasoning);
  }

  if (f.evidence) fenced(t.evidenceHeading, f.evidence);

  // ---- what RUNNING it produced, when it was run ------------------------------------
  //
  // Fenced like every other block, and it carries the command VERBATIM: a reader who does not
  // trust the verdict can re-run the line. The pre-stated expectation is printed beside the
  // output so a reader can see for themselves whether the two match — the report does not ask
  // to be believed about it.
  if (f.verification) {
    const v = f.verification;
    const body: string[] = [
      `${t.verifyCommand}  ${v.command}`,
      `${t.verifyExit}  ${v.timedOut ? t.verifyTimeout : (v.exitCode ?? "?")}`,
      `${t.verifyExpect}  ${v.expect}`,
      "",
      t.verifyOutput,
    ];
    for (const line of v.output.split("\n")) body.push(`  ${line}`);
    fenced(t.verifyHeading, body.join("\n"));
    lines.push(v.confirmed ? t.verifyConfirmed : t.verifyNotConfirmed);
    lines.push("");
  }

  // The remaining gaps, stated per finding. A finding that WAS run is not thereby verified —
  // nobody tried to refute it — and saying only "VERIFIED" would overclaim in exactly the way
  // this report exists to avoid.
  lines.push(f.verification ? t.notFalsifiedShort : t.notVerifiedShort);
  lines.push("");
  return lines;
}

/** A fence longer than anything inside it. See reportText.ts on why this matters. */
function fenceFor(text: string): string {
  let longest = 0;
  for (const m of text.match(/`+/g) ?? []) longest = Math.max(longest, m.length);
  return "`".repeat(Math.max(3, longest + 1));
}

function severityZh(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "严重";
    case "high":
      return "高危";
    case "medium":
      return "中危";
    case "low":
      return "低危";
    case "info":
      return "信息";
  }
}

/** Kept for the renderers that have no language in hand (the `/loopsec tree` line). */
export { severityZh };

/** A compact view of the findings, for `/loopsec tree`. */
export function renderSecFindings(snapshot: TreeSnapshot): string[] {
  const p = surfaceProgress(snapshot);
  const lines: string[] = [];
  if (p.total > 0) {
    lines.push(
      `Attack surface: ${p.examined}/${p.total} examined · ${p.cleared} cleared · ${p.productive} produced a finding · ${p.open} open`,
    );
    for (const s of snapshot.surfaces.filter((x) => x.status === "open").slice(0, 8)) {
      const where = s.location ? `  ${s.location.file}:${s.location.line}` : "";
      lines.push(`  ${s.id} [${s.kind}] ${clip(s.title, 80)}${where}`);
    }
    const open = p.open;
    if (open > 8) lines.push(`  … +${open - 8} more open`);
    lines.push("");
  }
  if (snapshot.findings.length === 0) {
    // The surface still has to show — a sec run with a work list and no findings is
    // the NORMAL case early on, and the old early-return here hid the one thing that
    // says whether it is working.
    lines.push(snapshot.secNote ? "No findings recorded yet." : "No recon note and no findings yet — round 1 reads the project.");
    return lines;
  }
  lines.push(`${snapshot.findings.length} finding(s):`, "");
  for (const f of [...snapshot.findings].sort(compareFinding)) {
    const where = f.location ? `  ${f.location.file}:${f.location.line}` : "  (evidence only)";
    const auth = f.preAuth === true ? " [pre-auth]" : f.preAuth === false ? " [auth]" : " [auth NOT assessed]";
    const chain = f.chainOf && f.chainOf.length > 0 ? `  ⛓ ${f.chainOf.join("+")}` : "";
    lines.push(`  ${f.id} [${f.severity ?? "unrated"}] ${f.category}${auth}${where}${chain}`);
    lines.push(`     ${clip(f.title, 100)}`);
  }
  return lines;
}

// -----------------------------------------------------------------
// Writing
// -----------------------------------------------------------------

export function writeSecReport(
  projectRoot: string,
  snapshot: TreeSnapshot,
  loop: AuditLoopState | null,
  opts: SecReportOptions = {},
): Result<string> {
  const reportPath = secReportPath(projectRoot);
  try {
    fs.mkdirSync(secStateDir(projectRoot), { recursive: true });
    const text = renderSecReport(snapshot, loop, {
      ...opts,
      // Read here rather than taken from the caller, for the same reason
      // `writeReport` does: a caller that forgets the language produces an English
      // report for a Chinese operator, and the setting looks broken.
      language: opts.language ?? reportLanguageOf(projectRoot),
      fenceLanguage: opts.fenceLanguage ?? fenceLanguageOf(projectRoot),
      coverageReport: opts.coverageReport ?? secCoverage(snapshot, projectRoot),
      // Read here for the same reason as the language: a caller that forgets them would print a depth
      // budget of 0/M and silently omit the `unproven` reason, making the report describe a judgement
      // the run did not make.
      probesAllowed: opts.probesAllowed ?? allowCommandProbesOf(projectRoot),
      pursuitBudget: opts.pursuitBudget ?? pursuitRoundsOf(projectRoot),
    });
    // Only the append-and-truncate pair this project uses everywhere: no rename,
    // no held fd, so a non-NTFS volume cannot fail the write.
    fs.writeFileSync(reportPath, text, "utf-8");
  } catch (error) {
    return { ok: false, errors: [`could not write the report: ${(error as Error).message}`] };
  }
  return { ok: true, value: reportPath, warnings: [] };
}

/**
 * Append one round to the journal.
 *
 * CUMULATIVE, like the hypothesis ledger and for the same reason: this is written
 * when the round is PREPARED, so it cannot contain the round's own output. Listing
 * only `finding.round === round` therefore printed "no finding recorded this round"
 * for every round and showed the findings in NONE of them — measured, 2 findings and
 * five entries all claiming zero.
 *
 * The full list also makes the journal readable on its own: a reader can see what
 * the run knew at each point without diffing consecutive entries.
 */
export function appendSecLedger(
  projectRoot: string,
  snapshot: TreeSnapshot,
  round: number,
  summary: readonly string[],
  at = nowIso(),
): boolean {
  const findings = [...snapshot.findings].sort(compareFinding);
  const body: string[] = [];
  body.push("");
  body.push(`## Round ${round} — ${at}`);
  body.push("");
  const fence = fenceFor(summary.join("\n"));
  body.push(fence);
  body.push(...summary);
  body.push(fence);
  body.push("");
  body.push(`### Findings so far (${findings.length})`);
  body.push("");
  if (findings.length === 0) {
    body.push("_none yet_");
  } else {
    for (const f of findings) {
      const where = f.location ? ` — ${f.location.file}:${f.location.line}` : "";
      const when = f.round > 0 ? ` (r${f.round})` : "";
      body.push(`- [${f.severity ?? "unrated"}] **${f.id}** ${f.title} — ${f.category}${where}${when}`);
    }
  }
  body.push("");
  try {
    fs.mkdirSync(secStateDir(projectRoot), { recursive: true });
    fs.appendFileSync(secLedgerPath(projectRoot), body.join("\n"), "utf-8");
    return true;
  } catch {
    return false;
  }
}

/**
 * The skill guidance is NOT appended here.
 *
 * `loop.ts` owns brief assembly — it appends the operator's notes, the run's scope,
 * the output requirements and the skill guidance to every brief in every mode, in
 * one place. Doing it here as well would apply it twice in sec mode and would put
 * the same decision in two files.
 */
export function secRoundBrief(
  snapshot: TreeSnapshot,
  objective: string,
  round: number,
  opts: SecBriefOptions = {},
): string {
  // THE RECON PHASE IS COUNTED IN SECTIONS — see `reconSections`. The brief is told which round
  // of the phase it is by the number of sections already recorded, so a run that recorded nothing
  // gets round 1 again rather than moving on with an empty ceiling.
  const reconRounds = opts.reconRounds ?? 1;
  if (!reconPhaseOver(snapshot, reconRounds)) {
    return renderSecReconBrief(snapshot, objective, round, reconSections(snapshot) + 1, reconRounds);
  }
  // DEPTH OUTRANKS THE WORK LIST. A finding that came out of a breakthrough is one step from the
  // objective, and finishing it is what converts a lead into a result — so it is deepened before
  // the next item on the plan. Two things bound it: the per-finding budget, and the RUN's share
  // (`pursuitAllowed`, see `depthAllowed`) so the sweep cannot be starved.
  const pursuitTarget = nextPursuit(snapshot, opts.pursuitBudget ?? 0, opts.probesAllowed === true);
  const depthBlocked = pursuitTarget !== null && opts.pursuitAllowed === false;
  if (pursuitTarget && !depthBlocked) return renderSecPursuitBrief(snapshot, objective, round, pursuitTarget, opts);
  const item = nextOpenSurface(snapshot, opts.digBudget ?? SEC_DIG_BUDGET);
  // A DEEP RUN WITH AN EMPTY LIST IS NOT A SWEEP SHORT OF PLACES — it is a deep run that needs its
  // next sub-questions. Same round kind, opposite instruction, so the branch lives here rather than
  // being inferred by the loop.
  const brief = item
    ? renderSecAnalyzeBrief(snapshot, objective, round, item, opts)
    : snapshot.loop?.deep
      ? renderSecDeepQuestionBrief(snapshot, objective, round)
      : renderSecSurfaceBrief(snapshot, objective, round);
  // A BLOCKED DEPTH TARGET IS SAID OUT LOUD, not silently dropped. Without this line the model
  // cannot tell "there is nothing worth deepening" from "the ratio cap is holding it", and the
  // second one must not read as the first: the finding keeps its budget and comes back.
  if (!depthBlocked) return brief;
  return [
    `(DEPTH QUEUED, NOT DROPPED: ${pursuitTarget!.id} still has ${(opts.pursuitBudget ?? 0) - (pursuitTarget!.pursuitSpent ?? 0)} depth round(s)`,
    " left, but the run's share of depth rounds is used up for now — the sweep goes first, and this",
    " finding is picked again once it has caught up. Do not close it.)",
    "",
    brief,
  ].join("\n");
}
