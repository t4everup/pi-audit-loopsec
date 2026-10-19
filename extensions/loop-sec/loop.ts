/**
 * pi-audit-loopsec — extensions/loop-sec/loop.ts
 *
 * Stage 5: `/goal` and `/loop` — the round engine.
 *
 * -----------------------------------------------------------------------
 * The six-step round, and who owns which step
 * -----------------------------------------------------------------------
 *
 *   1. the scheduler picks a node            → the EXTENSION (mechanical)
 *   2. the node is examined                  → the MODEL's turn
 *   3. status + evidence are updated         → the MODEL, through tools
 *   4. whether to combine is decided         → the EXTENSION (mechanical trigger)
 *   5. the findings ledger is written        → the EXTENSION
 *   6. a round summary is emitted            → the EXTENSION
 *
 * The extension cannot examine a hypothesis — that is the model's job — so a
 * round is driven by handing the model a BRIEF and letting its turn do steps
 * 2–3. Everything the extension can do mechanically, it does; nothing it cannot
 * do is faked.
 *
 * -----------------------------------------------------------------------
 * The anti-stacking fence
 * -----------------------------------------------------------------------
 *
 * `AuditLoopState.awaitingRound` records the round whose turn is in flight. A
 * tick only sends a brief when nothing is awaiting completion, so a slow,
 * failed, or aborted turn cannot pile rounds on top of each other. The next tick
 * evaluates the finished round before deciding anything.
 *
 * That evaluation is DERIVED, not recorded: the round record stores the node's
 * status and evidence count at the start, and the tick compares them against
 * now. Derived beats recorded because there is no window in which the two can
 * disagree — a second "outcome" event could be lost to a crash, and then the
 * stall counter would be wrong forever.
 *
 * -----------------------------------------------------------------------
 * Why the loop stops itself
 * -----------------------------------------------------------------------
 *
 * A loop with no exit is a loop that burns a night producing nothing. Three
 * bounds, all mechanical:
 *
 *   - the COMPLETION CONTRACT is satisfied (`/goal` only);
 *   - the PLATEAU: `plateauWindow` consecutive rounds that produced neither a
 *     verdict nor new evidence — the well is dry;
 *   - `maxRounds`.
 *
 * Each stop records a reason, and every reason distinguishes "finished" from
 * "gave up".
 */

import * as fs from "node:fs";
import * as path from "node:path";

import {
  type AuditLoopKind,
  loopCommandName,
  type AuditLoopState,
  type CompletionContract,
  type Hypothesis,
  type HypothesisStatus,
  type ReconSegment,
  type RoundKind,
  type RoundRecord,
  type Severity,
  type TreeSnapshot,
  describeTiming,
  formatDuration,
  chainState,
  authReach,
  hasBeenChallenged,
  isResolved,
  isSchedulable,
  isVerdict,
  meetsSeverity,
  loopTiming,
  severityRank,
  type LoopTiming,
  type ReportLanguage,
  verificationTier,
} from "./types.js";
import {
  SEC_STATE_DIR_NAME,
  STATE_DIR_NAME,
  appendEvent,
  appendSecEvent,
  load,
  loadSec,
  nowIso,
  secTreeLogPath,
  treeLogPath,
  type TreeEvent,
} from "./store.js";

// -----------------------------------------------------------------
// Which log does this loop own?
// -----------------------------------------------------------------
//
// `/goal` and `/loop` keep the hypothesis tree in `.pi-hypothesis`; `/loopsec`
// keeps its findings in `.pi-loopsec`. The event log follows the mode, so every
// write in this file routes through `appendLoopEvent` and every path in an error
// message names the log the command actually reads.

/** The event log the loop kind owns. */
export function loopLogPath(projectRoot: string, kind: AuditLoopKind): string {
  return kind === "sec" ? secTreeLogPath(projectRoot) : treeLogPath(projectRoot);
}

function appendLoopEvent(projectRoot: string, kind: AuditLoopKind, event: TreeEvent): boolean {
  return kind === "sec" ? appendSecEvent(projectRoot, event) : appendEvent(projectRoot, event);
}
import { markNotesDelivered, pendingNotes, renderNotesSection, renderNotesStatus, writeOperatorMirror } from "./notes.js";
import { loadSettings, reportLanguageOf } from "./settings.js";
import {
  SEC_DIG_BUDGET,
  appendSecLedger,
  nextOpenSurface,
  secCoverage,
  gatesOfFinding,
  nextPursuit,
  reconPhaseOver,
  reconSections,
  secRoundBrief,
  updateFinding,
  surfaceProgress,
  updateSurface,
  writeSecReport,
} from "./sec.js";
import { type CoverageReport } from "./coverage.js";
import { clip } from "./types.js";
import { fenceFor } from "./reportText.js";

// -----------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------

export const LOOP_DEFAULTS = {
  /** `/goal` gives up after this many unproductive rounds. */
  GOAL_PLATEAU: 5,
  /** `/loop` is more patient — it is meant to run for hours. */
  LOOP_PLATEAU: 8,
  /** `/goal` round cap. 0 would be unbounded; a goal should not be. */
  GOAL_MAX_ROUNDS: 20,
  /** `/loop` is unbounded by default. */
  LOOP_MAX_ROUNDS: 0,
  /**
   * Minimum rounds between challenges.
   *
   * THE CADENCE'S JOB MOVED TO THE ROTATION, so this is now only a floor and 1 or
   * 2 measure identically. It used to be the thing that stopped challenge from
   * eating every round, and it was set to 5 on that reasoning — but it could not do
   * that job, because the kind that sat above challenge took the slots the cadence
   * freed instead. Measured on the real Checkmk tree, 80 rounds:
   *
   *   interval 1  challenge 18, consolidate 12, pursue 18, verify 32, 22 attacked
   *   interval 2  challenge 18, consolidate 12, pursue 18, verify 32, 22 attacked
   *   interval 3  challenge 11, consolidate 11, pursue 12, verify 32, 15 attacked
   *   interval 5  challenge 11, consolidate 11, pursue 12, verify 32, 15 attacked
   *
   * 1 and 2 are identical because two of the rules already guarantee the spacing a
   * cadence would: the side-quest rule means no two side quests are adjacent, and
   * `nextChallengeCandidate` returns null once every confirmation has been attacked,
   * so this can never become a loop of re-attacking the same finding.
   *
   * 2 rather than 1 so the constant still states a real bound rather than reading as
   * a disabled one — the value is a floor, not the mechanism.
   */
  CHALLENGE_INTERVAL: 2,
  /**
   * Is a pursuit already OPEN (started, not finished)?
   *
   * An open pursuit outranks a due combination pass. The pass sits above challenge
   * and pursue in the chain, and its trigger fires on almost every new finding, so
   * on a real audit the sequence became `consolidate, verify, consolidate, verify`
   * — seven passes in 27 rounds, combining nothing, with the depth round never
   * getting a slot. A pursuit is BOUNDED (two rounds per finding, closed the moment
   * it produces nothing), so it cannot starve anything by going first.
   */
  /**
   * Rounds between PURSUE rounds.
   *
   * This is the anti-starvation invariant, and it is the lesson from the
   * combination bug: a round kind that can pre-empt every other kind eventually
   * does exactly that. A gap of 2 means two pursue rounds are never adjacent, so
   * verification keeps at least half the rounds no matter how many findings want
   * depth.
   */
  PURSUE_INTERVAL: 2,
  /** Nodes listed in a ledger tree snapshot. */
  LEDGER_TREE_LINES: 40,
} as const;

export const FINDINGS_LEDGER_NAME = "findings.md";

export function findingsLedgerPath(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME, FINDINGS_LEDGER_NAME);
}

// -----------------------------------------------------------------
// The completion contract
// -----------------------------------------------------------------

export interface ContractClauses {
  confirmed?: number;
  severity?: Severity;
  category?: string[];
  requireConsolidated?: boolean;
  requireArtifact?: boolean;
  requireReproduced?: boolean;
  requireChallenged?: boolean;
  requireImpact?: boolean;
  requireExploitable?: boolean;
  requirePreAuth?: boolean;
}

/**
 * Build a contract from parsed command flags.
 *
 * The DEFAULTS are what a code audit actually wants, because the old ones were
 * not: `minConfirmed: 1` alone let the first confirmed finding end the goal,
 * including an unrated one or one resting on nothing but an argument. A security
 * audit means "at least one HIGH-or-worse finding that is anchored in code", so
 * that is the default.
 */
export function buildContract(clauses: ContractClauses): CompletionContract {
  return {
    minConfirmed: clauses.confirmed ?? 1,
    minSeverity: clauses.severity ?? "high",
    ...(clauses.category && clauses.category.length > 0 ? { categories: clauses.category } : {}),
    requireConsolidated: clauses.requireConsolidated ?? true,
    requireArtifact: clauses.requireArtifact ?? true,
    requireReproduced: clauses.requireReproduced ?? false,
    requireChallenged: clauses.requireChallenged ?? true,
    requireImpact: clauses.requireImpact ?? false,
    requireExploitable: clauses.requireExploitable ?? false,
    requirePreAuth: clauses.requirePreAuth ?? false,
  };
}

export function describeContract(contract: CompletionContract | null): string {
  if (!contract) return "none (runs until stopped)";
  const parts = [`at least ${contract.minConfirmed} confirmed finding(s)`];
  if (contract.minSeverity) parts.push(`at severity >= ${contract.minSeverity}`);
  if (contract.categories && contract.categories.length > 0) parts.push(`in ${contract.categories.join(" or ")}`);
  if (contract.requireArtifact) parts.push("each anchored in real code (not reasoning alone)");
  if (contract.requireReproduced) parts.push("each reproduced by a command");
  if (contract.requireChallenged) parts.push("each having SURVIVED an attempt to refute it");
  if (contract.requireImpact) parts.push("each stating what an attacker gains");
  if (contract.requireExploitable) parts.push("each with a COMPLETE exploitation chain (no unverified precondition)");
  if (contract.requirePreAuth) parts.push("each reachable WITHOUT authentication");
  if (contract.requireConsolidated) parts.push("with no combination pass pending");
  return parts.join(", ");
}

export interface ContractEvaluation {
  met: boolean;
  /** Human lines, always including the numbers, so a reader can see the gap. */
  detail: string[];
}

/**
 * Evaluate the completion contract against the folded tree.
 *
 * Every clause is mechanical. A completion condition the extension cannot check
 * is a condition the model grades itself on, which is the failure this project
 * exists to avoid.
 */
export function contractMet(snapshot: TreeSnapshot, contract: CompletionContract | null): ContractEvaluation {
  if (!contract) return { met: false, detail: ["no contract (a /loop has no finish line)"] };

  const allConfirmed = snapshot.nodes.filter((n) => n.status === "confirmed");
  const inScope = allConfirmed.filter((n) => {
    if (contract.categories && contract.categories.length > 0 && !contract.categories.includes(n.category)) return false;
    return true;
  });
  const detail: string[] = [];

  // Tier filtering: a finding that rests on an argument is not a finding.
  const qualifying = inScope.filter((n) => {
    const tier = verificationTier(n);
    if (contract.requireArtifact && tier === "reasoning-only") return false;
    if (contract.requireReproduced && tier !== "reproduced") return false;
    if (contract.requireChallenged && !hasBeenChallenged(n)) return false;
    if (contract.requireImpact && !n.attackVector?.impact?.trim()) return false;
    if (contract.requirePreAuth && authReach(n.attackVector) !== "pre-auth") return false;
    if (contract.requireExploitable) {
      const chain = chainState(n, (id) => snapshot.byId.get(id)).state;
      // `standalone` counts: a finding with no gates has a complete chain by
      // definition, and excluding it would make the clause mean "must have a
      // gate" rather than "must be usable".
      if (chain !== "standalone" && chain !== "chain-ready") return false;
    }
    return true;
  });
  const droppedForTier = inScope.length - qualifying.length;

  const countOk = qualifying.length >= contract.minConfirmed;
  detail.push(
    `${qualifying.length}/${contract.minConfirmed} qualifying confirmed finding(s)` +
      (contract.categories && contract.categories.length > 0 ? ` in ${contract.categories.join(" or ")}` : "") +
      (droppedForTier > 0
        ? ` (${droppedForTier} confirmed finding(s) excluded: ${
            contract.requireChallenged ? "not yet challenged" : contract.requireReproduced ? "not reproduced by a command" : "reasoning only, no artifact"
          })`
        : ""),
  );
  if (contract.requireChallenged && inScope.length > 0) {
    const challenged = inScope.filter((n) => hasBeenChallenged(n)).length;
    detail.push(`${challenged}/${inScope.length} confirmed finding(s) have been challenged`);
  }
  if (contract.requirePreAuth && inScope.length > 0) {
    const pre = inScope.filter((n) => authReach(n.attackVector) === "pre-auth").length;
    const notAssessed = inScope.filter((n) => authReach(n.attackVector) === "unassessed").length;
    detail.push(
      `${pre}/${inScope.length} confirmed finding(s) are reachable WITHOUT authentication` +
        (notAssessed > 0
          ? ` — ${notAssessed} have NOT been assessed and do not count: "nobody determined it" is not "pre-auth"`
          : ""),
    );
  }
  if (contract.requireExploitable && inScope.length > 0) {
    const usable = inScope.filter((n) => {
      const state = chainState(n, (id) => snapshot.byId.get(id)).state;
      return state === "standalone" || state === "chain-ready";
    }).length;
    detail.push(
      `${usable}/${inScope.length} confirmed finding(s) have a COMPLETE exploitation chain` +
        (usable < inScope.length
          ? ` — ${inScope.length - usable} are real but gated on an unverified precondition (the sink is confirmed, the way in is not)`
          : ""),
    );
  }

  let severityOk = true;
  if (contract.minSeverity) {
    const rated = qualifying.filter((n) => n.severity);
    severityOk = rated.some((n) => meetsSeverity(n.severity, contract.minSeverity!));
    const unrated = qualifying.length - rated.length;
    detail.push(
      `${rated.filter((n) => meetsSeverity(n.severity, contract.minSeverity!)).length} at severity >= ${contract.minSeverity}` +
        (unrated > 0 ? ` (${unrated} qualifying finding(s) carry no severity yet — they are NOT counted as low)` : ""),
    );
  }

  // requireConsolidated died with the combination pass. A contract carrying it can
  // only come from an old log; treat the clause as satisfied rather than lose the loop.
  return { met: countOk && severityOk, detail };
}

// -----------------------------------------------------------------
// Loop state
// -----------------------------------------------------------------

export interface StartLoopOptions {
  kind: AuditLoopKind;
  objective: string;
  contract?: CompletionContract | null;
  maxRounds?: number;
  plateauWindow?: number;
  /** The classes this run is FOR. See AuditLoopState.focus. */
  focus?: string[];
  at?: string;
}

export interface StartLoopResult {
  ok: boolean;
  errors: string[];
  loop?: AuditLoopState;
  /** True when an existing PAUSED loop was resumed instead of a new one started. */
  resumed?: boolean;
}

/**
 * Can `/start` be satisfied by resuming the loop that is already there?
 *
 * Two things make it a DIFFERENT audit rather than a continuation, and resuming
 * would then silently keep the old one:
 *
 *   - a different KIND (`/goal` start over a paused `/loop`),
 *   - a different OBJECTIVE.
 */
function canResumeInPlace(existing: AuditLoopState, opts: StartLoopOptions): boolean {
  if (existing.kind !== opts.kind) return false;
  const wanted = opts.objective.trim();
  return !wanted || wanted === existing.objective.trim();
}

/**
 * Why `/start` could not be honoured, naming the exact command that would work.
 *
 * A refusal that says "stop it first or resume it" without the arguments is a
 * refusal the reader has to guess their way out of.
 */
function describeStartRefusal(existing: AuditLoopState, opts: StartLoopOptions): string {
  const where = `at round ${existing.round} ("${clip(existing.objective, 60)}")`;
  if (existing.status === "running") {
    return (
      `the /${loopCommandName(existing.kind)} audit is already RUNNING ${where}. ` +
      `/${loopCommandName(existing.kind)} status to watch it, or /${loopCommandName(existing.kind)} pause to stop the clock.`
    );
  }
  if (existing.kind !== opts.kind) {
    return (
      `a PAUSED /${loopCommandName(existing.kind)} exists ${where}, so /${loopCommandName(opts.kind)} start would abandon it. ` +
      `Resume it with /${loopCommandName(existing.kind)} resume, or end it with /${loopCommandName(existing.kind)} stop first.`
    );
  }
  return (
    `a PAUSED /${loopCommandName(existing.kind)} exists ${where} with a DIFFERENT objective, and resuming would silently keep that one. ` +
    `Resume it with /${loopCommandName(existing.kind)} resume, or end it with /${loopCommandName(existing.kind)} stop and then start this one.`
  );
}

/**
 * Start an audit, or RESUME the paused one that is already there.
 *
 * A paused loop is resumed rather than refused. "start" is the word a person
 * types when they want the audit to go again, and with a paused loop present
 * that is exactly what they mean: the tree and the round state are preserved
 * either way, and the old refusal left them holding a message that named neither
 * the right verb nor its arguments.
 *
 * A RUNNING loop is still refused — there is nothing to do but watch it — and so
 * is a paused loop with a different kind or objective, because resuming that
 * would silently keep an objective the user is no longer asking for.
 */
export function startLoop(projectRoot: string, snapshot: TreeSnapshot, opts: StartLoopOptions): StartLoopResult {
  const existing = snapshot.loop;
  if (existing && (existing.status === "running" || existing.status === "paused")) {
    if (existing.status === "paused" && canResumeInPlace(existing, opts)) {
      const resumed = resumeLoop(projectRoot, snapshot, {
        ...(opts.maxRounds !== undefined ? { maxRounds: opts.maxRounds } : {}),
      });
      if (!resumed.ok || !resumed.loop) return { ok: false, errors: resumed.errors };
      return { ok: true, errors: [], loop: resumed.loop, resumed: true };
    }
    return { ok: false, errors: [describeStartRefusal(existing, opts)] };
  }
  // A `/loopSEC` run has NO hypothesis tree — its record is a list of findings — so
  // the missing root is expected there and fatal everywhere else. Requiring one made
  // `/loopsec` refuse to start at all.
  if (!snapshot.rootId && opts.kind !== "sec") {
    return { ok: false, errors: ["no hypothesis tree in this project — create one with `/hypothesis new \"<falsifiable assertion>\"` first"] };
  }

  const at = opts.at ?? nowIso();
  const loop: AuditLoopState = {
    kind: opts.kind,
    objective: opts.objective,
    contract: opts.kind === "goal" ? (opts.contract ?? buildContract({})) : null,
    status: "running",
    startedAt: at,
    updatedAt: at,
    round: 0,
    awaitingRound: null,
    maxRounds: opts.maxRounds ?? (opts.kind === "goal" ? LOOP_DEFAULTS.GOAL_MAX_ROUNDS : LOOP_DEFAULTS.LOOP_MAX_ROUNDS),
    plateauWindow: opts.plateauWindow ?? (opts.kind === "goal" ? LOOP_DEFAULTS.GOAL_PLATEAU : LOOP_DEFAULTS.LOOP_PLATEAU),
    stallRounds: 0,
    ...(opts.focus && opts.focus.length > 0 ? { focus: [...opts.focus] } : {}),
    pausedMs: 0,
    pausedAt: null,
    endedAt: null,
  };
  if (!appendLoopEvent(projectRoot, opts.kind, { type: "loop_updated", at, loop })) {
    return { ok: false, errors: ["the loop state could not be written — nothing changed"] };
  }
  return { ok: true, errors: [], loop };
}

/** Write an updated loop state (latest wins). `null` clears it. */
export function writeLoop(projectRoot: string, loop: AuditLoopState, at = nowIso()): boolean {
  const next = { ...loop, updatedAt: at };
  return appendLoopEvent(projectRoot, loop.kind, { type: "loop_updated", at, loop: next });
}

export interface LoopControlResult {
  ok: boolean;
  errors: string[];
  loop?: AuditLoopState;
  message?: string;
}

/**
 * "There is no loop" — but WHICH there, and is it really absent?
 *
 * The bare message was actively misleading on a real run: the operator had a loop at
 * round 30 and `/loopsec pause 1` said "no audit loop in this project". Two things can
 * produce that, and the message could not tell them apart:
 *
 *   - the command is running from a DIFFERENT directory than the audit, so there is no
 *     log here at all;
 *   - the log is here but records no loop.
 *
 * Neither is "the loop vanished", and the path is the one fact that settles it. The
 * read-failure case is handled by the CALLER, which has the `readError` — see the
 * `loadOrReport` helper in index.ts.
 */
function noLoopErrors(projectRoot: string, kind: AuditLoopKind): string[] {
  const file = loopLogPath(projectRoot, kind);
  const cmd = loopCommandName(kind);
  const here = fs.existsSync(file);
  return here
    ? [
        `no audit loop in ${projectRoot} — the log exists at ${file} but records no loop.`,
        `Start one with /${cmd} start.`,
      ]
    : [
        `no audit loop here — there is no log at ${file} at all.`,
        `Run this from the directory the audit was started in, or start one here with /${cmd} start.`,
      ];
}

/** Which log should a "no loop" message point at? The command's mode when the
 *  caller knows it, the snapshot's loop kind otherwise — a stopped-and-cleared
 *  loop carries neither, and that is fine: the message then names the caller's
 *  own command, which is the one the operator can act on. */
function noLoopKind(snapshot: TreeSnapshot, kindHint?: AuditLoopKind): AuditLoopKind {
  return kindHint ?? snapshot.loop?.kind ?? "sec";
}

export function pauseLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string, at = nowIso(), kindHint?: AuditLoopKind): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: noLoopErrors(projectRoot, noLoopKind(snapshot, kindHint)) };
  if (loop.status !== "running") {
    return {
      ok: false,
      errors: [
        loop.status === "paused"
          ? `the /${loopCommandName(loop.kind)} audit is ALREADY PAUSED at round ${loop.round}. Resume it with /${loopCommandName(loop.kind)} resume.`
          : `the /${loopCommandName(loop.kind)} audit is ${loop.status}, so there is no clock to stop. Start a new one with /${loopCommandName(loop.kind)} start.`,
      ],
    };
  }
  // `pausedAt` opens a pause interval. It is CLOSED by resumeLoop (banking the
  // span into pausedMs) or, if the loop is stopped while paused, by `endedAt`
  // in loopTiming — so a pause that is never resumed is still counted.
  const next: AuditLoopState = { ...loop, status: "paused", pausedReason: reason, pausedAt: at };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Paused at round ${loop.round}.` };
}

/**
 * Run `rounds` more rounds and then pause.
 *
 * Refuses when the loop is already paused: "run 20 more" from a stopped clock is a
 * resume, and doing it silently would hide that the loop was not running.
 */
export function pauseAfterRounds(
  projectRoot: string,
  snapshot: TreeSnapshot,
  rounds: number,
  at = nowIso(),
  kindHint?: AuditLoopKind,
): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: noLoopErrors(projectRoot, noLoopKind(snapshot, kindHint)) };
  if (!Number.isInteger(rounds) || rounds < 1) {
    return { ok: false, errors: [`the round count must be a whole number of at least 1 (got "${rounds}")`] };
  }
  if (loop.status !== "running") {
    return {
      ok: false,
      errors: [
        `the /${loopCommandName(loop.kind)} audit is ${loop.status}, so there is nothing to run ${rounds} more round(s) OF.`,
        `Resume it with a budget instead:  /${loopCommandName(loop.kind)} resume ${rounds}`,
      ],
    };
  }
  const until = loop.round + rounds;
  const next: AuditLoopState = { ...loop, pauseAfterRound: until };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return {
    ok: true,
    errors: [],
    loop: next,
    message:
      `Will pause after ${rounds} more round(s), at round ${until} (now at ${loop.round}).` +
      `\n  /${loopCommandName(loop.kind)} pause            to pause now instead` +
      `\n  /${loopCommandName(loop.kind)} pause <n>        to change the budget`,
  };
}

export function resumeLoop(
  projectRoot: string,
  snapshot: TreeSnapshot,
  opts: { maxRounds?: number; forRounds?: number } = {},
  at = nowIso(),
  kindHint?: AuditLoopKind,
): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: noLoopErrors(projectRoot, noLoopKind(snapshot, kindHint)) };
  if (loop.status === "complete") return { ok: false, errors: ["this run already met its contract — start a new one instead of resuming"] };
  if (loop.status === "running") {
    return { ok: false, errors: [`the /${loopCommandName(loop.kind)} audit is already RUNNING at round ${loop.round} — nothing to resume.`] };
  }

  // The round cap is DURABLE, so resuming past it does nothing: the tick would
  // immediately re-stop with the same reason. Silently "succeeding" there is
  // worse than refusing — the user sees a resume message and no progress.
  //
  // The PLATEAU does not have this problem: resume resets `stallRounds`, so a
  // plateau stop genuinely recovers in place.
  const capReached = loop.maxRounds > 0 && loop.round >= loop.maxRounds;
  const raised = opts.maxRounds !== undefined && opts.maxRounds > loop.maxRounds;
  if (capReached && !raised) {
    const suggested = loop.round + 10;
    return {
      ok: false,
      errors: [
        `the round cap (${loop.maxRounds}) is already reached at round ${loop.round}, so resuming would stop again immediately and send no round.`,
        `Raise the cap in place:  /${loopCommandName(loop.kind)} resume maxRounds=${suggested}`,
        `Or start a new one:      /${loopCommandName(loop.kind)} start "<objective>" maxRounds=${suggested}  (the tree and its hypotheses are kept either way)`,
      ],
    };
  }

  const { pausedReason, stopReason, ...rest } = loop;
  void pausedReason;
  void stopReason;
  // Resuming is work: bring the widget back if the operator had closed it.
  const { widgetHidden, ...restWithoutHidden } = rest;
  void widgetHidden;
  // Bank the pause interval being closed, so `activeMs` does not include time
  // the audit spent unable to work. Clamped at zero for a backwards clock jump.
  const pausedAt = loop.pausedAt ? Date.parse(loop.pausedAt) : NaN;
  const resumedAt = Date.parse(at);
  const closedPause =
    Number.isFinite(pausedAt) && Number.isFinite(resumedAt) ? Math.max(0, resumedAt - pausedAt) : 0;
  const next: AuditLoopState = {
    ...restWithoutHidden,
    status: "running",
    stallRounds: 0,
    // A spent budget must not survive a resume, or the loop pauses again
    // immediately. A new one is set below when asked for.
    pauseAfterRound: null,
    pausedMs: loop.pausedMs + closedPause,
    pausedAt: null,
    ...(opts.maxRounds !== undefined && opts.maxRounds > 0 ? { maxRounds: opts.maxRounds } : {}),
    ...(opts.forRounds !== undefined && opts.forRounds > 0
      ? { pauseAfterRound: loop.round + opts.forRounds }
      : {}),
  };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return {
    ok: true,
    errors: [],
    loop: next,
    message:
      `Resumed at round ${loop.round}; the stall counter was reset so the plateau starts fresh.` +
      (raised ? ` Round cap raised to ${opts.maxRounds}.` : "") +
      (next.pauseAfterRound !== null ? ` Will pause after ${opts.forRounds} more round(s), at round ${next.pauseAfterRound}.` : ""),
  };
}

/**
 * Park the loop after a brief could not be delivered.
 *
 * The FENCE IS CLEARED, not left set. `awaitingRound` means "a turn for this
 * round is in flight"; a brief that never reached the model has no turn, so
 * leaving the fence set would make the next tick judge a round that never ran
 * as unproductive and burn a plateau slot for nothing.
 *
 * The loop is PAUSED rather than left running, because a failed send has no
 * automatic retry path: the agent is idle, so no further lifecycle event will
 * arrive to try again. Parking hands the decision back to the user with an
 * explicit resume.
 */
export function parkOnSendFailure(projectRoot: string, reason: string, at = nowIso()): boolean {
  // The run's own log, whichever mode it belongs to: a /loopsec run whose brief
  // could not be delivered must park in .pi-loopsec, not be invisible.
  const loop = loadSec(projectRoot).snapshot.loop ?? load(projectRoot).snapshot.loop;
  if (!loop) return false;
  return appendLoopEvent(projectRoot, loop.kind, { type: "loop_updated", at, loop: { ...loop, status: "paused", awaitingRound: null, pausedReason: reason, updatedAt: at } });
}

export function stopLoop(projectRoot: string, snapshot: TreeSnapshot, reason: string, at = nowIso(), kindHint?: AuditLoopKind): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: noLoopErrors(projectRoot, noLoopKind(snapshot, kindHint)) };
  if (loop.status === "stopped" || loop.status === "complete") return { ok: false, errors: [`the /${loopCommandName(loop.kind)} audit is already ${loop.status}`] };
  // `endedAt` freezes the clock. Without it a stopped loop's elapsed time would
  // keep growing every time the status was printed.
  const next: AuditLoopState = { ...loop, status: "stopped", stopReason: reason, awaitingRound: null, endedAt: at };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Stopped at round ${loop.round} after ${formatDuration(loopTiming(next)?.activeMs ?? 0)}: ${reason}` };
}

/**
 * The round records belonging to the CURRENT run.
 *
 * `/loop start` on an existing tree restarts the round counter at 0, so round
 * numbers are NOT unique across a tree's life: a tree that ran 48 rounds and was
 * then restarted has two records for round 1. Every lookup by round number alone
 * therefore has to say WHICH run it means, and `startedAt` is what separates
 * them.
 *
 * Without this, a restarted loop evaluating its round 1 found the PREVIOUS run's
 * round 1 — a round that had been productive — and reset its stall counter to
 * zero, so the plateau never fired and the widget showed `stall 0/8` while
 * dozens of unproductive rounds went by.
 */
export function currentRunRounds(snapshot: TreeSnapshot): RoundRecord[] {
  const loop = snapshot.loop;
  if (!loop) return snapshot.roundRecords;
  return snapshot.roundRecords.filter((r) => r.at >= loop.startedAt);
}

// -----------------------------------------------------------------
// Round evaluation
// -----------------------------------------------------------------

export interface RoundOutcome {
  round: number;
  kind: RoundRecord["kind"];
  /** The node the round examined, when it had one. */
  nodeId?: string | null;
  /** A verdict was reached on the round's node (or a finding was confirmed). */
  verdictReached: boolean;
  /** New evidence landed. */
  evidenceAdded: boolean;
  /** One line for the summary. */
  detail: string;
  /** True when the round moved the audit forward in any way. */
  produced: boolean;
}

/**
 * Judge a finished round by comparing the tree against the round's baseline.
 *
 * Derived rather than recorded — see the module header. `produced` is the
 * plateau signal: a round that reached no verdict and added no evidence is a
 * round that spent tokens and learned nothing.
 */
export function evaluateRound(snapshot: TreeSnapshot, record: RoundRecord): RoundOutcome {
  const confirmedNow = snapshot.nodes.filter((n) => n.status === "confirmed").length;
  const confirmedGrew = confirmedNow > record.confirmedAtStart;

  // A `/loopSEC` round.
  //
  // Identified by the BASELINE it carries, not by its kind: a sec recon round and a
  // hypothesis recon round are both `recon` and mean different things. There is no
  // verdict and no evidence entry in this mode, so "did it produce" has to be one of
  // the two things a sec round can actually do — record a finding, or record the
  // note. A round that did neither is what the plateau counts, and it should: a dig
  // round that comes back empty is a round that found nothing.
  if (record.findingCountAtStart !== undefined) {
    if (record.kind === "recon") {
      const submitted = snapshot.secNote !== null;
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: false,
        detail: submitted ? "recon note recorded — the surface round is next" : "no recon note was submitted this round",
        produced: submitted,
      };
    }
    if (record.kind === "surface") {
      // A surface round produces the WORK LIST, so "did it produce" is "did the list
      // grow". An enumeration that adds nothing has told the run nothing it did not
      // already know, and that is what the plateau should count.
      const before = record.surfaceCountAtStart ?? 0;
      const grew = snapshot.surfaces.length - before;
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: grew > 0,
        detail: grew > 0 ? `${grew} surface item(s) enumerated` : "no new surface item was enumerated",
        produced: grew > 0,
      };
    }
    // AN ANALYZE ROUND IS PRODUCTIVE WHEN AN ITEM GETS EXAMINED, not when a bug turns
    // up. This is the difference between an analysis and a bug hunt: reading five
    // files, tracing the whole data flow and correctly concluding "guarded" is work,
    // and counting it as nothing made the plateau stop a run that was doing exactly
    // what it was asked to do.
    const before = record.surfaceExaminedAtStart ?? 0;
    const examined = surfaceProgress(snapshot).examined - before;
    const added = snapshot.findings.length - record.findingCountAtStart;
    // A DEPTH ROUND IS PROGRESS. The item was already being examined, so `examined` does not
    // move and no finding may have landed — and without this line the model pays a plateau
    // slot for being thorough, which pays it to close an item hastily instead of finishing
    // the trace. Bounded by construction: `digging` can only be set `digBudget` times.
    const dug = record.surfaceWasDigging === true;

    // A PURSUIT ROUND IS A DIFFERENT AXIS, and its progress signal has to be different too: there
    // is no status to flip (the finding's item was already examined when the finding landed), so
    // "did it produce" is about the GATE — was the blocker list refined, cleared, or the pursuit
    // closed with a reason? A refined blocker counts: the model learned something about the gate,
    // and calling that nothing would pay it to give up instead of finishing the trace. Bounded by
    // construction: `pursuitSpent` cannot exceed `pursuitBudget`.
    if (record.kind === "pursue") {
      const target = record.findingId ? snapshot.findings.find((f) => f.id === record.findingId) : undefined;
      if (!target) {
        return {
          round: record.round,
          kind: record.kind,
          verdictReached: false,
          evidenceAdded: false,
          detail: record.findingId ? `the pursued finding ${record.findingId} is no longer in the run` : "the pursuit round named no finding",
          produced: false,
        };
      }
      const now = (target.blockers ?? []).join(" | ");
      const gateChanged = now !== (record.pursuitBlockersAtStart ?? "");
      const closed = !!target.pursuitClosed;
      const bits: string[] = [];
      if (closed) bits.push(`pursuit closed: ${clip(target.pursuitClosed!, 120)}`);
      else if (gateChanged) bits.push(`gate refined: ${(target.blockers ?? []).length} blocker(s)`);
      if (added > 0) bits.push(`${added} finding(s) recorded`);
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: gateChanged || closed || added > 0,
        detail: bits.length > 0 ? `${target.id} — ${bits.join(", ")}` : `${target.id}'s gate is unchanged and nothing was recorded`,
        produced: gateChanged || closed || added > 0,
      };
    }

    const bits: string[] = [];
    if (added > 0) bits.push(`${added} finding(s) recorded`);
    if (examined > 0) bits.push(`${examined} item(s) examined`);
    if (bits.length === 0 && dug) bits.push("a depth round on the item you asked to keep digging");
    return {
      round: record.round,
      kind: record.kind,
      verdictReached: false,
      evidenceAdded: added > 0 || examined > 0 || dug,
      detail: bits.length > 0 ? bits.join(", ") : "nothing was examined and nothing was recorded",
      produced: added > 0 || examined > 0 || dug,
    };
  }

  if (record.kind === "recon") {
    // A recon round produces the segment inventory itself, so "did it produce"
    // is "was a note submitted after this round started". ISO strings compare
    // correctly as strings, and the round's own `at` is the baseline.
    const submitted = snapshot.reconAt !== null && snapshot.reconAt >= record.at;
    const detail = submitted
      ? `recon note submitted — ${snapshot.segments.length} segment(s) to generate from`
      : "no recon note was submitted this round";
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: submitted };
  }

  if (record.kind === "generate") {
    // A legacy hypothesis-mode round. segment state lives in the recon module that
    // was removed with the tree; "produced" falls back to "a node carries this
    // segment id", which is the fact the summary needs.
    const id = record.segmentId ?? null;
    const produced = id ? snapshot.nodes.filter((n) => n.segmentId === id).length : 0;
    const detail = id
      ? produced > 0
        ? `segment ${id} produced ${produced} hypothesis(es)`
        : `segment ${id} produced nothing`
      : "the generate round named no segment";
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: produced > 0 };
  }

  if (record.kind === "challenge") {
    const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
    if (!node) {
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: false,
        detail: record.nodeId ? `the challenged finding ${record.nodeId} is no longer in the tree` : "the challenge round named no finding",
        produced: false,
      };
    }
    const refuted = node.status === "rejected";
    const evidenceAdded = node.evidence.length > record.nodeEvidenceAtStart;
    const detail = refuted
      ? `${node.id} was REFUTED by the challenge — a false positive removed`
      : evidenceAdded
        ? `${node.id} survived the challenge (${node.evidence.length} evidence entry/entries)`
        : `${node.id} was challenged but nothing was recorded either way`;
    return { round: record.round, kind: record.kind, verdictReached: refuted, evidenceAdded, detail, produced: refuted || evidenceAdded };
  }

  if (record.kind === "coverage") {
    // A coverage round produces a NEW recon note, exactly like the first recon. The
    // test is whether one arrived after this round started — the note replaces the
    // segment inventory, so a later note is what "produced something" means here.
    const submitted = snapshot.reconAt !== null && snapshot.reconAt >= record.at;
    const detail = submitted
      ? `coverage recon submitted — ${snapshot.segments.length} new segment(s) from the untouched areas`
      : "no coverage recon note was submitted this round";
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: submitted };
  }

  if (record.kind === "pursue") {
    const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
    const added = Math.max(0, snapshot.nodes.length - record.nodeCountAtStart);
    const children = node ? snapshot.nodes.filter((n) => n.parentId === node.id).length : 0;
    if (!node) {
      return {
        round: record.round,
        kind: record.kind,
        verdictReached: false,
        evidenceAdded: false,
        detail: record.nodeId ? `the pursued finding ${record.nodeId} is no longer in the tree` : "the pursue round named no finding",
        produced: false,
      };
    }
    // The ONLY output a pursue round has is new hypotheses. Adding none means the
    // lead is exhausted — which is a result, and it closes the pursuit rather
    // than spending the rest of the budget on it.
    const detail =
      added > 0
        ? `${node.id} pursued for depth — ${added} new hypothesis(es) derived from it (${children} child(ren) total)`
        : `${node.id} produced no new hypothesis — this lead looks exhausted, so the pursuit stops here`;
    return { round: record.round, kind: record.kind, verdictReached: false, evidenceAdded: false, detail, produced: added > 0, nodeId: node.id };
  }

  if (record.kind === "consolidate") {
    const evidenceAdded = false;
    // THE PASS'S OWN OUTPUT IS NEW COMBINATION NODES, not whether a finding happened
    // to be confirmed while it ran. `confirmedGrew` was measuring the model's other
    // work, which made a pass that combined nothing look productive — and a pass
    // that combined nothing is exactly what should count against the plateau.
    const combined = Math.max(0, snapshot.nodes.length - record.nodeCountAtStart);
    const verdictReached = combined > 0 || confirmedGrew;
    const detail =
      combined > 0
        ? `the pass produced ${combined} new combination(s)`
        : confirmedGrew
          ? `a finding was confirmed during the pass (${record.confirmedAtStart} → ${confirmedNow})`
          : "the pass handed over candidates and nothing was combined — the next one is backed off";
    return { round: record.round, kind: record.kind, verdictReached, evidenceAdded, detail, produced: verdictReached };
  }

  const node = record.nodeId ? snapshot.byId.get(record.nodeId) : undefined;
  if (!node) {
    return {
      round: record.round,
      kind: record.kind,
      verdictReached: false,
      evidenceAdded: false,
      detail: record.nodeId ? `${record.nodeId} is no longer in the tree` : "the round had no node",
      produced: false,
    };
  }

  const verdictReached = isResolved(node.status) && !isResolved(record.nodeStatusAtStart ?? "pending");
  const evidenceAdded = node.evidence.length > record.nodeEvidenceAtStart;
  const detail = verdictReached
    ? node.status === "blocked"
      ? `${node.id} → blocked (a real examination that cannot be settled from the source alone — counted as progress, not as nothing)`
      : `${node.id} → ${node.status} (${node.evidence.length} evidence entry/entries)`
    : evidenceAdded
      ? `${node.id} gained evidence but no verdict yet (${record.nodeEvidenceAtStart} → ${node.evidence.length})`
      : `${node.id} produced no verdict and no new evidence`;
  return { round: record.round, kind: record.kind, verdictReached, evidenceAdded, detail, produced: verdictReached || evidenceAdded || confirmedGrew };
}

// -----------------------------------------------------------------
// The round brief
// -----------------------------------------------------------------

/**
 * Insert a section immediately AFTER a brief's `[...]` banner.
 *
 * The model uses the banner to orient itself, so a section that goes above it
 * reads as a header for the wrong thing; one appended at the end of a long
 * brief is read last. Both the operator's notes and the run's scope belong
 * here.
 */
function afterBanner(brief: string, section: string): string {
  if (!section) return brief;
  const lines = brief.split("\n");
  if (lines[0]?.startsWith("[")) {
    const rest = lines.slice(1);
    while (rest.length > 0 && rest[0] === "") rest.shift();
    return [lines[0], "", section, "", ...rest].join("\n");
  }
  return [section, "", ...lines].join("\n");
}

/**
 * Put the operator's input where it will actually be read.
 */
export function withNotes(brief: string, snapshot: TreeSnapshot): string {
  return afterBanner(brief, renderNotesSection(snapshot));
}

/**
 * Put the operator's input where it will actually be read, and remind the model
 * WHO the words it writes belong to.
 *
 * The hypothesis modes' output requirements (attackVector fields, verdict words,
 * H-xxxx ids) went with those modes — a sec brief that still carried them would
 * tell the model to call tools that no longer exist, and every call would be
 * refused. What a sec brief adds is: the language (the report quotes verbatim),
 * the fence tag note, and the one hard rule — an artifact or nothing.
 *
 * The sec brief itself already says WHICH tool to call for each situation (see
 * `renderSecAnalyzeBrief`); this block only carries what is true for every
 * brief in every round.
 */
export function withBriefExtras(brief: string, snapshot: TreeSnapshot, lang: ReportLanguage): string {
  const focus = snapshot.loop?.focus ?? [];
  const withFocus = focus.length > 0 ? afterBanner(brief, renderFocus(focus)) : brief;
  const p = (...parts: string[]): string => parts.join("\n\n");
  const languageNote =
    lang === "zh"
      ? p(
          "## 输出要求",
          "**中文写。**描述、reasoning、evidence、finding 的每个字段全部用中文写——报告**直接引用这些原文**，不翻译、不改写。",
          "**每条发现都带物证：**一个 `file:line`，或一段摘录。没有物证的记录会被直接丢弃——这是本模式唯一的硬规则。",
          "**标题与编号**用工具返回的 `F-xxxx` / `S-xxxx`，不要自创编号体系。",
          "内容栅栏的语言标签沿用项目设置（默认 `c`）——那是给查看器的提示，不是对文件的断言。",
        )
      : p(
          "## Output requirements",
          "**Write in English.** The report quotes the finding's text VERBATIM — it does not translate.",
          "**Every finding carries an artifact:** a file:line, or an evidence excerpt. A finding recorded with neither is DROPPED — that is the one hard rule of this mode.",
          "**Use the ids the tools return** (F-xxxx / S-xxxx); do not invent your own scheme.",
          "The content fences open with the project's tag (default `c`) — a HINT to the viewer, never a claim about the file.",
        );
  return withNotes(`${withFocus}\n${languageNote}`, snapshot);
}

export function renderFocus(focus: readonly string[]): string {
  return [
    `THIS RUN IS SCOPED TO: ${focus.join(", ")}`,
    "",
    "Spend this round on those classes. If you find something in another class, RECORD it —",
    "a pre-auth RCE is often reached by chaining a finding from somewhere else — but do not",
    "spend this round on it, and do not open a new branch in it.",
  ].join("\n");
}

// -----------------------------------------------------------------
// The round summary and the ledger
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// The tick
// -----------------------------------------------------------------

export interface TickOptions {
  /** Suppress sending the brief; still evaluates and records. */
  dryRun?: boolean;
  at?: string;
}

export interface TickResult {
  action: "sent" | "paused" | "stopped" | "complete" | "idle";
  reason: string;
  round?: number;
  nodeId?: string | null;
  /** For a `generate` round: which segment was handed over. */
  segmentId?: string;
  brief?: string;
  summary?: string[];
  previous?: RoundOutcome | null;
}

/**
 * Advance the audit loop by one round.
 *
 * Evaluates the in-flight round first (if any), then decides whether to send the
 * next brief. Returns the brief rather than sending it, so the caller owns the
 * transport and this module stays testable without a host.
 */
export function tickLoop(projectRoot: string, snapshot: TreeSnapshot, opts: TickOptions = {}): TickResult {
  const at = opts.at ?? nowIso();
  // Read once per tick, so every decision in this round sees the same budget.
  const pursueBudget = pursueRoundsOf(projectRoot);
  const loop = snapshot.loop;
  if (!loop) return { action: "idle", reason: "no audit loop in this project" };
  if (loop.status === "complete") return { action: "complete", reason: loop.stopReason ?? "the completion contract is satisfied" };
  if (loop.status === "stopped") return { action: "stopped", reason: loop.stopReason ?? "stopped" };
  if (loop.status === "paused") return { action: "paused", reason: loop.pausedReason ?? "paused" };
  // A sec run has NO hypothesis tree at all — its record is a list of findings —
  // so the missing root is expected there and fatal everywhere else.
  if (!snapshot.rootId && loop.kind !== "sec") {
    // The scope root is created by the /goal and /loop commands before the loop
    // starts, so reaching this means the tree was wiped underneath a running
    // loop. Say so instead of reporting "no open hypotheses".
    return { action: "idle", reason: "no hypothesis tree in this project — the scope root is missing" };
  }

  let current = loop;
  let previous: RoundOutcome | null = null;

  // 1. Evaluate the in-flight round before deciding anything.
  if (current.awaitingRound !== null) {
    // The LAST record with this round number, not the first: the in-flight round
    // is the most recently appended one, and a previous run may share the number.
    const record = [...currentRunRounds(snapshot)].reverse().find((r) => r.round === current.awaitingRound);
    if (record) {
      previous = evaluateRound(snapshot, record);
      if (previous.kind === "coverage") {
        current = { ...current, coverageRounds: (current.coverageRounds ?? 0) + 1 };
      }
      if (previous.kind === "consolidate") {
        const stall = current.consolidationStall ?? 0;
        current = { ...current, consolidationStall: previous.produced ? 0 : stall + 1 };
      }
      current = {
        ...current,
        awaitingRound: null,
        stallRounds: previous.produced ? 0 : current.stallRounds + 1,
      };
    } else {
      // The record is missing (a torn write, or a wipe). Clearing the fence is
      // the honest move: the round's outcome is unknowable, so do not invent one.
      current = { ...current, awaitingRound: null };
    }
  }

  // 2. The completion contract (`/goal` only).
  if (current.contract) {
    const evaluation = contractMet(snapshot, current.contract);
    if (evaluation.met) {
      const done: AuditLoopState = {
        ...current,
        status: "complete",
        endedAt: at,
        stopReason: `contract satisfied at round ${current.round}: ${evaluation.detail.join("; ")}`,
      };
      writeLoop(projectRoot, done, at);
      return { action: "complete", reason: done.stopReason!, round: current.round, previous };
    }
  }

  // 2b. THE OPERATOR'S ROUND BUDGET.
  //
  // `/loop pause 20` means "twenty more rounds, then pause" — a bound on a run
  // that has no finish line of its own, which `maxRounds` cannot express because
  // that counts from the start rather than from now.
  //
  // Placed BEFORE the plateau so the pause is the operator's instruction taking
  // effect, not an accident of the well running dry at the same moment.
  if (typeof current.pauseAfterRound === "number" && current.round >= current.pauseAfterRound) {
    const spent: AuditLoopState = {
      ...current,
      status: "paused",
      awaitingRound: null,
      // CLEARED, or resuming would pause again on the very next tick.
      pauseAfterRound: null,
      pausedReason: `the ${current.pauseAfterRound}-round budget is spent at round ${current.round} — /${current.kind} resume <n> for another n`,
    };
    writeLoop(projectRoot, spent, at);
    return { action: "paused", reason: spent.pausedReason!, round: current.round, previous };
  }

  // 3. The plateau.
  if (current.stallRounds >= current.plateauWindow) {
    const stopped: AuditLoopState = {
        ...current,
        status: "stopped",
        endedAt: at,
        stopReason:
        `plateau — ${current.stallRounds} consecutive round(s) produced no verdict and no new evidence ` +
        `(window ${current.plateauWindow}); the well looks dry`,    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 4. The round cap.
  if (current.maxRounds > 0 && current.round >= current.maxRounds) {
    const stopped: AuditLoopState = {
        ...current,
        status: "stopped",
        endedAt: at,
        stopReason: `round cap reached (${current.maxRounds})`,
    };
    writeLoop(projectRoot, stopped, at);
    return { action: "stopped", reason: stopped.stopReason!, round: current.round, previous };
  }

  // 5. Which kind of round?
  //
  //    `/loopSEC` answers this differently and returns before the chain below. It
  //    has no nodes to schedule, no segments to generate from, no contract and no
  //    side quests — its rounds are "read the project once, enumerate what is worth
  //    looking at, then work that list one item at a time". Everything above this
  //    point is shared on purpose: the anti-stacking fence, the operator's round
  //    budget, the plateau and the round cap are the parts the operator asked for,
  //    and none of them is about hypotheses.
  if (current.kind === "sec") {
    const round = current.round + 1;
    const lang = reportLanguageOf(projectRoot);
    // Depth is budgeted by the SAME setting the hypothesis mode uses for pursue, because it
    // is the same decision: how many rounds may one item cost on top of the round that found
    // it. `0` disables depth in both modes.
    const digBudget = pursueRoundsOf(projectRoot) || SEC_DIG_BUDGET;
    const assigned = nextOpenSurface(snapshot, digBudget);
    // A depth round is SPENT ON PREPARE, like a pursue: a crash or a stalled turn must not
    // hand out unlimited rounds on one item.
    const wasDigging = assigned?.status === "digging";
    if (assigned) {
      // EVERY analyze round counts as an attempt, whether or not it concludes anything — that is
      // what lets the report tell "never looked at" from "looked at and unfinished".
      // `surfaceExaminedAtStart` is a STATUS count and stays one: the plateau reads it, and
      // widening it would make the day a round is prepared look productive.
      //
      // THE DIG BUDGET IS ENFORCED HERE TOO. digSurface refuses a sec_dig past the budget, but
      // this increment did not: an item the model dug twice and then never concluded kept being
      // assigned, and digRounds grew 3, 4, 5… past a budget of 2 — each round unproductive, the
      // whole plateau window spent on one place. The count stops at the budget; the item then
      // falls into the exhausted rule in nextOpenSurface and must be concluded.
      const digSpent = assigned.digRounds ?? 0;
      updateSurface(projectRoot, assigned.id, {
        attempts: (assigned.attempts ?? 0) + 1,
        ...(wasDigging && digSpent < digBudget ? { digRounds: digSpent + 1 } : {}),
      }, at);
    }
    // THREE KINDS, and the ORDER is the analysis:
    //   recon   — read the project (once)
    //   surface — enumerate the attack surface into a work list
    //   analyze — work ONE item on that list, all the way down
    //
    // The item is ASSIGNED here rather than left to the model, and that is what makes
    // this systematic: the loop walks the list the enumerator wrote, in the order it
    // wrote it, and a round cannot drift onto something else because it found the
    // assigned item uninteresting.
    // ASSIGNED FIRST. The order matters: a model can record a surface item (or a finding)
    // before it ever submits the recon note — the tools do not enforce an order — and with
    // `secNote === null` checked first the round was LABELLED "recon" while it actually
    // analysed an item. `evaluateRound` reads that label, so the round it produced was
    // counted as unproductive, and the plateau advanced for work that was done.
    const secKind: RoundKind =
      assigned ? "analyze" : snapshot.secNote === null ? "recon" : "surface";
    const reconRounds = reconRoundsOf(projectRoot);
    // THE PURSUIT COMES BEFORE THE PLAN. A finding that is real but GATED — a post-auth RCE on a
    // pre-auth objective, an RCE that needs one more controllable field — is one step from the
    // goal, and closing its gate converts it. Before this the finding's surface item was marked
    // examined and the run moved to the next S-xxx: the closest result it could produce was filed
    // and abandoned in the same round. Bounded by `pursuitBudget`, so it cannot eat the run.
    const pursuitBudget = pursuitRoundsOf(projectRoot);
    const pursuitTarget = reconPhaseOver(snapshot, reconRounds) ? nextPursuit(snapshot, pursuitBudget) : null;
    // THE RECON PHASE OUTRANKS AN ITEM, and the two must agree: `secRoundBrief` uses the same
    // `reconPhaseOver` predicate, so a round can never get a recon brief with an `analyze` label
    // (or the reverse) — and the plateau counts those two kinds differently. Counted in SECTIONS,
    // so a run that recorded nothing stays in recon instead of enumerating from an empty note.
    const inReconPhase = !reconPhaseOver(snapshot, reconRounds);
    const kindForRound: RoundKind = inReconPhase ? "recon" : pursuitTarget ? "pursue" : secKind;
    const coverageReport = secCoverage(snapshot, projectRoot);
    const progress = surfaceProgress(snapshot);
    const brief = withBriefExtras(
      secRoundBrief(snapshot, current.objective, round, {
        digBudget,
        reconRounds,
        pursuitBudget,
        lastRound: previous ? `Last round (${previous.round}): ${previous.detail}` : null,
        // The loop AFTER this tick's evaluation — see SecBriefOptions.loop.
        loop: current,
      }),
      snapshot,
      lang,
    );
    const summary =
      kindForRound === "recon"
        ? [
            `SEC ROUND ${round} — reconnaissance ${reconSections(snapshot) + 1}/${reconRounds}`,
            reconSections(snapshot) + 1 === 1
              ? "Nothing can be analysed before the project has been read. This round maps it."
              : "Reading the request lifecycle and the auth wiring — what pre-auth findings turn on.",
          ]
        : kindForRound === "surface"
          ? [
              `SEC ROUND ${round} — enumerate the attack surface`,
              `${progress.total} item(s) on the list, all examined — enumerate what the analysis revealed.`,
            ]
          : kindForRound === "pursue"
            ? [
                `SEC ROUND ${round} — PURSUE ${pursuitTarget!.id}: attack its gate`,
                `${pursuitTarget!.id} [${pursuitTarget!.severity ?? "unrated"}] ${pursuitTarget!.category} — ${clip(pursuitTarget!.title, 90)}`,
                `${gatesOfFinding(pursuitTarget!).length} gate(s), pursuit ${pursuitTarget!.pursuitSpent ?? 0}/${pursuitBudget} — NOT working the work list this round`,
              ]
            : [
              `SEC ROUND ${round} — analyse ${assigned!.id}`,
              `${assigned!.kind}: ${assigned!.title}` +
                (assigned!.location ? ` (${assigned!.location.file}:${assigned!.location.line})` : ""),
              `${progress.examined}/${progress.total} examined · ${snapshot.findings.length} finding(s) so far`,
            ];
    // SPEND THE PURSUIT BUDGET ON PREPARE, like a dig: a crash or a stalled turn must not hand out
    // unlimited rounds on one finding. The blockers are also snapshotted, because that string is the
    // only baseline `evaluateRound` can use to tell a pursuit that learned something from one that
    // did nothing (there is no status to flip here, unlike an analyze round).
    if (pursuitTarget) {
      updateFinding(projectRoot, pursuitTarget.id, { pursuitSpent: (pursuitTarget.pursuitSpent ?? 0) + 1 }, at);
    }
    const record: RoundRecord = {
      round,
      at,
      kind: kindForRound,
      ...(kindForRound === "analyze" && assigned ? { nodeId: null, surfaceId: assigned.id } : { nodeId: null }),
      ...(kindForRound === "pursue" && pursuitTarget
        ? {
            findingId: pursuitTarget.id,
            pursuitBlockersAtStart: (pursuitTarget.blockers ?? []).join(" | "),
          }
        : {}),
      nodeStatusAtStart: null,
      nodeEvidenceAtStart: 0,
      confirmedAtStart: snapshot.nodes.filter((n) => n.status === "confirmed").length,
      nodeCountAtStart: snapshot.nodes.length,
      findingCountAtStart: snapshot.findings.length,
      surfaceCountAtStart: snapshot.surfaces.length,
      surfaceExaminedAtStart: progress.examined,
      ...(wasDigging ? { surfaceWasDigging: true } : {}),
      summary,
    } as RoundRecord;
    if (!appendSecEvent(projectRoot, { type: "round_detail", at, record })) {
      return { action: "idle", reason: "the round record could not be written", round, previous };
    }
    const next: AuditLoopState = { ...current, round, awaitingRound: round };
    if (!opts.dryRun) {
      writeLoop(projectRoot, next, at);
      appendSecLedger(projectRoot, snapshot, round, summary, at);
      // Regenerated every round for the same reason the hypothesis report is: the
      // operator wants to watch it work, and a report that only appears at the end
      // is one they cannot steer by.
      writeSecReport(projectRoot, snapshot, next, { at, coverageReport });
      writeOperatorMirror(projectRoot, snapshot, current.kind);
      const delivered = pendingNotes(snapshot).filter((n) => !n.pinned).map((n) => n.id);
      if (delivered.length > 0) markNotesDelivered(projectRoot, delivered, round, at, current.kind);
    }
    return { action: "sent", reason: `round ${round} prepared`, round, nodeId: null, brief, summary, previous };
  }

  // ONLY /loopsec runs this engine now. The hypothesis round planning — the scheduler,
  // the side quests, the contract gates, the combination passes — was removed together
  // with /goal, /loop and the hypothesis tools. The round kinds stay in the type so an
  // old `.pi-hypothesis` log still folds and its loop still renders in status, but
  // nothing starts or drives one any more.
  return { action: "idle", reason: "only /loopsec runs are driven by this engine — no sec loop is awaiting a round here" };
}

/**
 * The report language, read from the project's settings.
 *
 * Read per call rather than cached: the operator can change it mid-run with
 * `/loopsec config reportLanguage=en`, and a report that keeps coming out in
 * the old language after that is a setting that looks broken.
 */
// MOVED to settings.ts so `sec.ts` can use it without importing this module —
// loop.ts already imports sec.ts, and a cycle would be the price of leaving it here.
// Re-exported because index.ts and the tests import it from here.
export { reportLanguageOf };

/** The per-finding pursue budget, read from the project's settings. */
export function pursueRoundsOf(projectRoot: string): number {
  try {
    return loadSettings(projectRoot).settings.pursueRounds;
  } catch {
    return 2;
  }
}

/**
 * How many PURSUIT rounds one finding's blockers may cost. See `HypothesisSettings.pursuitRounds`.
 *
 * Falls back to 0 on a read failure, NOT to the default 2: this setting spends rounds on a finding
 * instead of the work list, and a settings file that cannot be read must not silently reallocate the
 * run. The safe direction is the one that keeps working the plan.
 */
export function pursuitRoundsOf(projectRoot: string): number {
  try {
    return loadSettings(projectRoot).settings.pursuitRounds;
  } catch {
    return 0;
  }
}

/**
 * How many RECON rounds this run takes. See `HypothesisSettings.reconRounds`.
 *
 * Falls back to 1 on a read failure, not 2: the setting widens the phase, and a settings file
 * that cannot be read must not silently spend extra rounds.
 */
export function reconRoundsOf(projectRoot: string): number {
  try {
    return loadSettings(projectRoot).settings.reconRounds;
  } catch {
    return 1;
  }
}

// -----------------------------------------------------------------
// Status and widget
// -----------------------------------------------------------------

export function renderLoopStatus(snapshot: TreeSnapshot, nowMs = Date.now()): string[] {
  const loop = snapshot.loop;
  if (!loop) {
    return [
      "No audit loop in this project.",
      "  /goal \"<objective>\"   one audited objective, until a contract is met",
      "  /loop                 keep auditing until stopped or the well runs dry",
    ];
  }
  const lines: string[] = [];
  lines.push(`Audit ${loop.kind}: ${loop.status.toUpperCase()} — ${clip(loop.objective, 100)}`);
  lines.push(
    `  round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : " (unbounded)"}` +
      ` · stall ${loop.stallRounds}/${loop.plateauWindow}` +
      (loop.awaitingRound !== null ? ` · round ${loop.awaitingRound} in flight` : " · nothing in flight") +
      (typeof loop.pauseAfterRound === "number"
        ? ` · PAUSES at round ${loop.pauseAfterRound} (${loop.pauseAfterRound - loop.round} more)`
        : ""),
  );
  if (loop.contract) {
    const evaluation = contractMet(snapshot, loop.contract);
    lines.push(`  contract: ${describeContract(loop.contract)} — ${evaluation.met ? "MET" : "not met"}`);
    for (const line of evaluation.detail) lines.push(`    ${line}`);
  }
  if (loop.stopReason) lines.push(`  stop reason: ${loop.stopReason}`);
  if (loop.pausedReason) lines.push(`  paused: ${loop.pausedReason}`);
  // Operator input, when there is any. Shown because "did my hint land?" is the
  // question an operator has while watching a long run, and the pending count
  // answers it without opening the ledger.
  if (snapshot.notes.length > 0) lines.push(`  ${renderNotesStatus(snapshot)}`);
  lines.push(`  ${describeTiming(loopTiming(loop, nowMs), loop.round)}`);
  // A hidden widget is otherwise invisible state: the operator closed the panel
  // and has no way to tell whether it is still there.
  if (loop.widgetHidden) lines.push(`  widget: HIDDEN — /${loopCommandName(loop.kind)} show to bring it back`);
  const waiting = inFlightAge(snapshot, loop, nowMs);
  if (waiting) lines.push(`  the round in flight has been waiting ${waiting} — a turn that is not moving is a stuck turn`);
  lines.push(`  started ${loop.startedAt}, updated ${loop.updatedAt}`);

  const recent = snapshot.roundRecords.slice(-3);
  if (recent.length > 0) {
    lines.push("  recent rounds:");
    for (const record of recent) {
      lines.push(`    r${record.round} ${record.kind} ${record.nodeId ?? "-"} — ${clip(record.summary[0] ?? "", 70)}`);
    }
  }
  return lines;
}

/**
 * Hide the widget without discarding the audit.
 *
 * The widget is re-set on every settle and on every command, so hiding it once
 * is not enough — `setWidget(name, undefined)` is undone by the next refresh
 * unless the STATE says to stay hidden. That is why this is a flag on the loop
 * rather than a one-off UI call.
 *
 * The tree, the round history, the contract, the clock and the report all
 * survive. Dismissing a panel and discarding an audit are different actions.
 */
export function dismissLoop(projectRoot: string, snapshot: TreeSnapshot, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project — there is no widget to close"] };
  if (loop.widgetHidden) return { ok: false, errors: ["the widget is already hidden"] };
  const next: AuditLoopState = { ...loop, widgetHidden: true };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  const stillGoing = loop.status === "running" || loop.status === "paused";
  return {
    ok: true,
    errors: [],
    loop: next,
    message: stillGoing
      ? `Widget hidden. The ${loop.kind} is still ${loop.status} at round ${loop.round} and keeps running — /${loopCommandName(loop.kind)} status still reports it, /${loopCommandName(loop.kind)} show brings the widget back.`
      : `Widget hidden. The ${loop.kind} finished at round ${loop.round}; its report and the tree are untouched. /${loopCommandName(loop.kind)} show brings it back, /${loopCommandName(loop.kind)} start begins a new audit.`,
  };
}

/** Bring a dismissed widget back. */
export function showLoop(projectRoot: string, snapshot: TreeSnapshot, at = nowIso()): LoopControlResult {
  const loop = snapshot.loop;
  if (!loop) return { ok: false, errors: ["no audit loop in this project — /loop start begins one"] };
  if (!loop.widgetHidden) return { ok: false, errors: ["the widget is already showing"] };
  const { widgetHidden, ...rest } = loop;
  void widgetHidden;
  const next: AuditLoopState = { ...rest };
  if (!writeLoop(projectRoot, next, at)) return { ok: false, errors: ["the loop state could not be written"] };
  return { ok: true, errors: [], loop: next, message: `Widget shown again (${loop.kind} ${loop.status}, round ${loop.round}).` };
}

/** A three-line widget: enough to see the loop is alive and where it is. */
export function renderWidget(snapshot: TreeSnapshot, nowMs = Date.now()): string[] | null {
  const loop = snapshot.loop;
  if (!loop) return null;
  // Checked before anything is computed: a dismissed widget must not cost a
  // render, and returning null is what removes it from the editor.
  if (loop.widgetHidden) return null;
  const confirmed = snapshot.nodes.filter((n) => n.status === "confirmed").length;
  const rejected = snapshot.nodes.filter((n) => n.status === "rejected").length;
  // Scope nodes are boundaries, not work. Counting one as "open" would make the
  // widget read one too high for the entire audit — the same reason summarize()
  // skips them.
  const open = snapshot.nodes.filter(
    (n) => n.nodeKind !== "scope" && n.status !== "confirmed" && n.status !== "rejected",
  ).length;
  const glyph = loop.status === "running" ? "▶" : loop.status === "paused" ? "‖" : loop.status === "complete" ? "✓" : "■";
  const contract = loop.contract ? contractMet(snapshot, loop.contract) : null;
  const timing = loopTiming(loop, nowMs);
  const lines = [
    `hypothesis ${glyph} ${loop.kind} round ${loop.round}${loop.maxRounds > 0 ? `/${loop.maxRounds}` : ""} · ${confirmed} confirmed · ${rejected} rejected · ${open} open`,
  ];
  // The clock lives on the state line, next to what the loop is currently doing:
  // "in flight round 15 · 3m" and "elapsed 2h 14m" answer the two questions a
  // watcher has — is it stuck, and how long has this been going.
  const state: string[] = [];
  // The in-flight age is suppressed while paused: the round is frozen, not
  // waiting, and an age that keeps climbing on a paused loop reads as a hang.
  const age = loop.status === "paused" ? null : inFlightAge(snapshot, loop, nowMs);
  if (loop.awaitingRound !== null) {
    state.push(`in flight: round ${loop.awaitingRound}${age ? ` · ${age}` : ""}`);
  }
  state.push(`stall ${loop.stallRounds}/${loop.plateauWindow}`);
  if (typeof loop.pauseAfterRound === "number") state.push(`stops at r${loop.pauseAfterRound}`);
  state.push(shortTiming(loop, timing));
  lines.push(`  ${state.join(" · ")}`);
  if (contract) lines.push(`  contract ${contract.met ? "MET" : "open"}: ${contract.detail[0] ?? ""}`);
  return lines;
}

/**
 * How long the in-flight round has been waiting, or null.
 *
 * A round that has been "in flight" for an hour is a stuck turn, and that is
 * invisible from the round number alone. Measured from the round record's own
 * timestamp, so it survives a reload.
 */
export function inFlightAge(snapshot: TreeSnapshot, loop: AuditLoopState, nowMs = Date.now()): string | null {
  if (loop.awaitingRound === null) return null;
  const record = [...snapshot.roundRecords].reverse().find((r) => r.round === loop.awaitingRound);
  if (!record) return null;
  const started = Date.parse(record.at);
  if (!Number.isFinite(started)) return null;
  return formatDuration(Math.max(0, nowMs - started));
}

/**
 * The clock in its shortest honest form.
 *
 * Active time always, with paused time in parentheses only when there is some:
 * a loop that sat paused overnight must not report a night of work, and a
 * "0m paused" clause on every line is a clause the reader learns to skip.
 */
export function shortTiming(loop: AuditLoopState, timing: LoopTiming | null): string {
  if (!timing) return "elapsed unknown";
  const active = formatDuration(timing.activeMs);
  if (timing.ended) return `ran ${active}`;
  if (loop.status === "paused") return `paused · ${active} active`;
  return timing.pausedMs > 0 ? `elapsed ${active} (${formatDuration(timing.pausedMs)} paused)` : `elapsed ${active}`;
}

export { severityRank };
