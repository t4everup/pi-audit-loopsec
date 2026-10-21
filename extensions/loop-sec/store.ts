/**
 * pi-audit-loopsec — extensions/loop-sec/store.ts
 *
 * Append-only JSONL persistence for the hypothesis tree.
 *
 * -----------------------------------------------------------------------
 * Why append-only, and what is deliberately NOT used
 * -----------------------------------------------------------------------
 *
 * This extension must work on a non-NTFS Windows volume (exFAT). exFAT has no
 * journal and a documented history of returning EISDIR / EPERM on the
 * link-and-rename dance that "atomic write" libraries use, so the store
 * NEVER:
 *
 *   - creates a hard link (`fs.linkSync`) — the observed EISDIR source;
 *   - writes a temp file and renames over the target (`fs.renameSync`);
 *   - opens the log once and keeps the descriptor.
 *
 * It ONLY calls `mkdirSync` and `appendFileSync` with the default `"a"` flag,
 * which is a single O_APPEND write per record on a descriptor that is opened
 * and closed by the call. No rename, no link, no long-held lock — so there is
 * nothing for a non-journaling filesystem to fail on.
 *
 * The cost of giving up atomic replacement is that a crash can tear the LAST
 * line. That is handled rather than hoped away:
 *
 *   - every record is one JSON object terminated by exactly one `\n`;
 *   - a file whose last byte is not `\n` has a torn tail, which the reader
 *     detects precisely (not by "JSON.parse failed", which would also swallow
 *     real corruption) and skips;
 *   - the torn line is reported as `tornLines` so the UI can say so.
 *
 * Recovery is therefore "read the log and fold it", and it is correct after a
 * crash at ANY byte offset: everything up to the last complete newline is
 * intact and already durable.
 *
 * -----------------------------------------------------------------------
 * Compaction without rewriting
 * -----------------------------------------------------------------------
 *
 * A long audit appends one record per status change, so the log grows without
 * bound. The usual answer (rewrite the file with only the latest record per
 * node) requires a temp file + rename, which is exactly what this module
 * cannot do.
 *
 * Instead `compact()` APPENDS a `snapshot` record containing the fully folded
 * state. The reader starts from the newest snapshot and folds only the events
 * after it, so read cost is bounded while the file stays append-only. The
 * file grows monotonically — that is the accepted trade for correctness on a
 * filesystem with no journal, and the snapshots are small relative to the
 * events they subsume (one record per node instead of one per touch).
 */

import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  type AttackVector,
  type AuditLoopState,
  type CombinationKind,
  type CompletionContract,
  type ConsolidationRecord,
  type ConsolidationTrigger,
  type Evidence,
  type FalsificationOverride,
  type RefutationAttempt,
  type Hypothesis,
  type HypothesisStatus,
  type NodeKind,
  type OperatorNote,
  type ReconSegment,
  type RoundKind,
  type RoundRecord,
  type SecFinding,
  type SecFindingPatch,
  type SecLoopDeep,
  type SecFindingStep,
  type SecSurface,
  type SecSurfaceKind,
  type SecSurfacePatch,
  type SecSurfaceStatus,
  type SecVerification,
  type SegmentRecord,
  type SelectionRecord,
  type Severity,
  type TreeSnapshot,
  type VerificationRecord,
  COMBINATION_KINDS,
  NODE_KINDS,
  ROUND_KINDS,
  SEC_SURFACE_KINDS,
  SEVERITIES,
  isVerdict,
} from "./types.js";

// -----------------------------------------------------------------
// Paths
// -----------------------------------------------------------------

/**
 * State directory name, relative to the audited project root.
 *
 * TWO directories, one per mode. `/goal` and `/loop` keep `.pi-hypothesis` — the
 * hypothesis tree, its reports and its settings live there, and every project that
 * ever ran them keeps reading that path. `/loopsec` gets its own `.pi-loopsec`: the
 * two modes keep different records (a tree of assertions vs a list of findings),
 * they can be run against the SAME project, and sharing one directory made the
 * sec run's events land in a log whose name describes the other mode.
 */
export const STATE_DIR_NAME = ".pi-hypothesis";
export const SEC_STATE_DIR_NAME = ".pi-loopsec";
export const TREE_LOG_NAME = "tree.jsonl";

/**
 * How many scheduling decisions the folded snapshot keeps.
 *
 * The scheduler needs the last few selections to compute the descent run, the
 * same-node run, and the category window. It does NOT need the whole history:
 * the unbounded facts (per-node selection counts and last-selected rounds) are
 * stored on the nodes themselves. Bounding this keeps the snapshot small
 * enough that compaction stays cheap.
 */
export const HISTORY_WINDOW = 50;

/** How many consolidation passes the folded snapshot keeps. Each record is
 * small and carries at most a handful of pair keys, so this is generous. */
export const CONSOLIDATION_HISTORY_WINDOW = 200;

/** How many round records the folded snapshot keeps. */
export const ROUND_HISTORY_WINDOW = 100;

/** How many segment-outcome records the folded snapshot keeps. */
export const SEGMENT_HISTORY_WINDOW = 200;

export function treeDir(projectRoot: string): string {
  return path.join(projectRoot, STATE_DIR_NAME);
}

export function treeLogPath(projectRoot: string): string {
  return path.join(treeDir(projectRoot), TREE_LOG_NAME);
}

// -----------------------------------------------------------------
// WHICH RUN IS ACTIVE
// -----------------------------------------------------------------

/**
 * The pointer file naming the run whose directory is live, relative to `.pi-loopsec`.
 *
 * A DEEP RUN writes to its own directory (`deep/F-0008/`) instead of the main one. There is only ONE
 * `loadSec(projectRoot)` signature and twenty call sites, and every one of them means "the run I am
 * working on" — so the run is resolved here, once, rather than threaded through all of them. That is
 * also the reason there can only be ONE active run per project: the eight tools read the same
 * pointer, so two live runs would write into each other's log.
 */
export const ACTIVE_RUN_NAME = "active.json";

/** What the pointer says. `dir` is ALWAYS relative to `.pi-loopsec`. */
export interface ActiveRun {
  dir: string;
  /** Where it came from, for `status` to explain itself: `deep F-0008`. */
  label?: string;
  at?: string;
}

export function secBaseDir(projectRoot: string): string {
  return path.join(projectRoot, SEC_STATE_DIR_NAME);
}

export function activeRunPath(projectRoot: string): string {
  return path.join(secBaseDir(projectRoot), ACTIVE_RUN_NAME);
}

/**
 * Resolve a pointer's `dir` to a real directory INSIDE `.pi-loopsec`, or null.
 *
 * THE POINTER FILE LIVES IN THE AUDITED PROJECT, so it is attacker-influenced in the only sense that
 * matters here: a repository can ship a `.pi-loopsec/active.json` that points at `../../..` and the
 * next write would land outside the project. An audit tool that can be steered by the thing it is
 * auditing is worse than a useless one, so an absolute path, a `..` escape, or the base itself is
 * refused rather than normalised.
 */
function resolveActiveDir(projectRoot: string, dir: string): string | null {
  if (typeof dir !== "string") return null;
  const trimmed = dir.trim();
  if (trimmed === "" || path.isAbsolute(trimmed)) return null;
  const base = path.resolve(secBaseDir(projectRoot));
  const target = path.resolve(base, trimmed);
  const rel = path.relative(base, target);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return target;
}

/**
 * The pointer, if it is well-formed AND its directory exists.
 *
 * The existence check is what makes a stale pointer harmless: a deep run whose directory was deleted
 * (or an operator who removed it by hand) falls back to the main run instead of silently starting a
 * fresh empty one under the same name.
 */
export function readActiveRun(projectRoot: string): ActiveRun | null {
  const file = activeRunPath(projectRoot);
  let raw: string;
  try {
    if (!fs.existsSync(file)) return null;
    raw = fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const o = parsed as Record<string, unknown>;
  const dir = typeof o.dir === "string" ? o.dir : "";
  const resolved = resolveActiveDir(projectRoot, dir);
  if (!resolved || !fs.existsSync(resolved)) return null;
  return {
    dir: dir.trim(),
    ...(typeof o.label === "string" && o.label ? { label: o.label } : {}),
    ...(typeof o.at === "string" && o.at ? { at: o.at } : {}),
  };
}

/**
 * Point the project at another run's directory, or back at the main one with `null`.
 *
 * `null` is written as `{"dir": null}` rather than deleting the pointer: nothing in a state directory
 * is ever removed by this module (the append-only rule), and an absent `dir` already reads as "the main
 * run", so the delete bought nothing and cost a destructive operation on the audit record.
 *
 * Refuses a directory that does not exist: setting the pointer first and creating the directory
 * afterwards would leave a window in which every read falls back to the main run while every write
 * that already resolved the deep path lands in a directory nobody is reading.
 */
export function setActiveRun(projectRoot: string, run: ActiveRun | null): { ok: boolean; errors: string[] } {
  const file = activeRunPath(projectRoot);
  try {
    if (run === null) {
      // Nothing to do when the project never had a pointer — `.pi-loopsec` must not be created by
      // the act of going back to a run that is already the default.
      if (!fs.existsSync(file)) return { ok: true, errors: [] };
      fs.writeFileSync(file, JSON.stringify({ dir: null, at: nowIso() }, null, 2) + "\n", "utf-8");
      return { ok: true, errors: [] };
    }
    const resolved = resolveActiveDir(projectRoot, run.dir);
    if (!resolved) {
      return { ok: false, errors: [`active run dir must be a relative path inside ${SEC_STATE_DIR_NAME}: "${run.dir}"`] };
    }
    if (!fs.existsSync(resolved)) {
      return { ok: false, errors: [`active run dir does not exist: ${run.dir}`] };
    }
    fs.mkdirSync(secBaseDir(projectRoot), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ ...run, at: run.at ?? nowIso() }, null, 2) + "\n", "utf-8");
    return { ok: true, errors: [] };
  } catch (error) {
    return { ok: false, errors: [`could not write ${ACTIVE_RUN_NAME}: ${(error as Error).message}`] };
  }
}

/**
 * The `/loopsec` state directory and its event log. Same file format, same
 * append-only rules — a different directory, because it is a different record.
 *
 * Resolves to the ACTIVE run: the main `.pi-loopsec` normally, `deep/<id>/` while a deep run owns
 * the project. Every path in this module and in sec.ts is built from here, so the pointer is the
 * single place that decides which run a write belongs to.
 */
export function secStateDir(projectRoot: string): string {
  const active = readActiveRun(projectRoot);
  if (!active) return secBaseDir(projectRoot);
  return resolveActiveDir(projectRoot, active.dir) ?? secBaseDir(projectRoot);
}

export function secTreeLogPath(projectRoot: string): string {
  return path.join(secStateDir(projectRoot), TREE_LOG_NAME);
}

// -----------------------------------------------------------------
// Event shapes
// -----------------------------------------------------------------

/** A snapshot's payload — everything needed to reconstruct state without the
 * events it subsumes. */
export interface SnapshotPayload {
  treeId: string;
  objective: string;
  rootId: string;
  nodes: Hypothesis[];
  maxNodeSeq: number;
  rounds: number;
  compactions: number;
  /** Bounded scheduling history, oldest first. */
  selections: SelectionRecord[];
  /** Bounded consolidation history, oldest first. */
  consolidations: ConsolidationRecord[];
  /** The audit loop, or null. */
  loop: AuditLoopState | null;
  /** Bounded round history, oldest first. */
  roundRecords: RoundRecord[];
  /** Operator input, oldest first. Never windowed — see pushNote in foldEvents. */
  notes?: OperatorNote[];
  /** The chunked recon note. */
  segments: ReconSegment[];
  /** Bounded segment outcomes, oldest first. */
  segmentRecords: SegmentRecord[];
  /** ISO timestamp of the newest recon submission. */
  reconAt: string | null;
  /** `/loopSEC` findings, oldest first. */
  findings?: SecFinding[];
  /** The `/loopSEC` attack surface, oldest first. */
  surfaces?: SecSurface[];
  /** The `/loopSEC` recon note, or null. */
  secNote?: string | null;
}

export type TreeEvent =
  | { type: "tree_created"; at: string; treeId: string; objective: string }
  | { type: "node_added"; at: string; node: Hypothesis }
  | { type: "node_updated"; at: string; id: string; patch: NodePatch }
  /** What a verification run concluded. Latest wins; see Hypothesis.lastVerification. */
  | { type: "verification_recorded"; at: string; id: string; record: VerificationRecord }
  | { type: "round_recorded"; at: string; round: number }
  | { type: "selection_recorded"; at: string; record: SelectionRecord }
  | { type: "consolidation_recorded"; at: string; record: ConsolidationRecord }
  /** Latest wins. `loop: null` clears it (a wipe, or a completed `/goal`). */
  | { type: "loop_updated"; at: string; loop: AuditLoopState | null }
  /** Operator input handed to a running audit. Append-only, like everything else. */
  | { type: "operator_note_recorded"; at: string; note: OperatorNote }
  /** A note went into a brief. Recorded, not inferred — see OperatorNote. */
  | { type: "operator_note_delivered"; at: string; id: string; round: number }
  | { type: "round_detail"; at: string; record: RoundRecord }
  /**
   * The recon note, already chunked.
   *
   * The SEGMENTS travel with the event rather than being recomputed from the
   * note at read time, because a segment id is content+position derived: a
   * reader that re-chunked a note the model had since edited would silently
   * un-cover segments that were already processed.
   */
  | { type: "recon_submitted"; at: string; note: string; segments: ReconSegment[] }
  /**
   * A `/loopSEC` finding.
   *
   * Append-only like everything else, and NOT windowed: a finding is the only
   * record of what the run produced, so dropping an old one to save space would
   * silently shrink the deliverable.
   */
  | { type: "finding_recorded"; at: string; finding: SecFinding }
  | { type: "finding_updated"; at: string; id: string; patch: SecFindingPatch }
  /** The `/loopSEC` recon note. Latest wins. */
  | { type: "sec_recon_submitted"; at: string; note: string }
  /** One item on the `/loopSEC` attack surface. Append-only, never windowed. */
  | { type: "surface_recorded"; at: string; surface: SecSurface }
  | { type: "surface_updated"; at: string; id: string; patch: SecSurfacePatch }
  | { type: "segment_recorded"; at: string; record: SegmentRecord }
  | { type: "snapshot"; at: string; snapshot: SnapshotPayload };

/**
 * The fields a node update may change.
 *
 * `id`, `createdAt`, `depth` and `parentId` are absent on purpose:
 *   - `id` is identity;
 *   - `createdAt` is history;
 *   - `depth` is derived (a reparent must recompute it for the whole subtree,
 *     which is a tree operation, not a field patch);
 *   - `parentId` moves a subtree, which is also a tree operation.
 * Reparenting is stage-2 work (`tree.moveSubtree`); until it exists, refusing
 * the field here is better than accepting a patch that would silently make
 * `depth` a lie.
 */
export interface NodePatch {
  description?: string;
  category?: string;
  status?: HypothesisStatus;
  evidence?: Evidence[];
  lastTouchedAt?: string;
  score?: number;
  spawnedFrom?: string[];
  /** Gate ids. See Hypothesis.requires. */
  requires?: string[];
  /** See Hypothesis.falsificationOverride. */
  refutation?: RefutationAttempt;
  falsificationOverride?: FalsificationOverride;
  roundIntroduced?: number;
  timesSelected?: number;
  lastSelectedRound?: number | null;
  combinationKind?: CombinationKind;
  attackVector?: AttackVector;
  segmentId?: string;
  challengedRound?: number | null;
  pursueSpent?: number;
  severity?: Severity;
  statusReason?: string;
}

// -----------------------------------------------------------------
// Serialization
// -----------------------------------------------------------------

/** One record = one JSON object + exactly one newline. */
export function serializeEvent(event: TreeEvent): string {
  return JSON.stringify(event) + "\n";
}

/**
 * Parse a log's text into events, reporting the exact number of lines that
 * could not be used.
 *
 * `torn` counts a final line that has no terminating newline — a crash
 * artifact. `malformed` counts complete lines that are not valid event
 * objects — real corruption. They are counted separately because the
 * responses differ: a torn tail is expected and harmless, corruption is a
 * reason to stop and tell the user.
 */
export function parseEvents(text: string): {
  events: TreeEvent[];
  torn: number;
  malformed: number;
  unknown: number;
} {
  const events: TreeEvent[] = [];
  let torn = 0;
  let malformed = 0;
  let unknown = 0;
  if (!text) return { events, torn, malformed, unknown };

  const endsWithNewline = text.endsWith("\n");
  const lines = text.split("\n");
  // A trailing "" after the final newline is not a line.
  if (endsWithNewline) lines.pop();

  lines.forEach((line, index) => {
    const isLast = index === lines.length - 1;
    if (!line.trim()) return;
    // The last line of a file with no trailing newline is a torn write.
    if (isLast && !endsWithNewline) {
      torn++;
      return;
    }
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      malformed++;
      return;
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      malformed++;
      return;
    }
    const type = (raw as { type?: unknown }).type;
    if (typeof type !== "string") {
      malformed++;
      return;
    }
    const event = normalizeEvent(raw as Record<string, unknown>);
    if (!event) {
      unknown++;
      return;
    }
    events.push(event);
  });

  return { events, torn, malformed, unknown };
}

/** Narrow an arbitrary parsed object to a known event, or null. Unknown
 * event types are counted rather than silently dropped, so a newer writer
 * cannot be mistaken for corruption. */
function normalizeEvent(raw: Record<string, unknown>): TreeEvent | null {
  const at = typeof raw.at === "string" ? raw.at : "";
  switch (raw.type) {
    case "tree_created": {
      if (typeof raw.treeId !== "string" || typeof raw.objective !== "string") return null;
      return { type: "tree_created", at, treeId: raw.treeId, objective: raw.objective };
    }
    case "node_added": {
      const node = normalizeNode(raw.node);
      if (!node) return null;
      return { type: "node_added", at, node };
    }
    case "verification_recorded": {
      if (typeof raw.id !== "string" || !raw.id) return null;
      const record = normalizeVerificationRecord(raw.record);
      if (!record) return null;
      return { type: "verification_recorded", at, id: raw.id, record };
    }
    case "node_updated": {
      if (typeof raw.id !== "string") return null;
      const patch = normalizePatch(raw.patch);
      if (!patch) return null;
      return { type: "node_updated", at, id: raw.id, patch };
    }
    case "round_recorded": {
      const round = typeof raw.round === "number" && Number.isFinite(raw.round) ? Math.max(0, Math.floor(raw.round)) : 0;
      return { type: "round_recorded", at, round };
    }
    case "selection_recorded": {
      const record = normalizeSelectionRecord(raw.record);
      if (!record) return null;
      return { type: "selection_recorded", at, record };
    }
    case "consolidation_recorded": {
      const record = normalizeConsolidationRecord(raw.record);
      if (!record) return null;
      return { type: "consolidation_recorded", at, record };
    }
    case "loop_updated": {
      // `loop: null` is meaningful (clear it), so an absent key is the only
      // thing that yields no event.
      if (!("loop" in raw)) return null;
      return { type: "loop_updated", at, loop: normalizeLoopState(raw.loop) };
    }
    case "operator_note_recorded": {
      const note = normalizeOperatorNote(raw.note);
      if (!note) return null;
      return { type: "operator_note_recorded", at, note };
    }
    case "operator_note_delivered": {
      if (typeof raw.id !== "string" || !raw.id) return null;
      const round = typeof raw.round === "number" && Number.isFinite(raw.round) ? Math.floor(raw.round) : 0;
      return { type: "operator_note_delivered", at, id: raw.id, round };
    }
    case "round_detail": {
      const record = normalizeRoundRecord(raw.record);
      if (!record) return null;
      return { type: "round_detail", at, record };
    }
    case "finding_recorded": {
      const finding = normalizeFinding(raw.finding);
      if (!finding) return null;
      return { type: "finding_recorded", at, finding };
    }
    case "finding_updated": {
      if (typeof raw.id !== "string" || !raw.id) return null;
      const patch = normalizeFindingPatch(raw.patch);
      if (!patch) return null;
      return { type: "finding_updated", at, id: raw.id, patch };
    }
    case "sec_recon_submitted": {
      if (typeof raw.note !== "string") return null;
      return { type: "sec_recon_submitted", at, note: raw.note };
    }
    case "surface_recorded": {
      const surface = normalizeSurface(raw.surface);
      if (!surface) return null;
      return { type: "surface_recorded", at, surface };
    }
    case "surface_updated": {
      if (typeof raw.id !== "string" || !raw.id) return null;
      const patch = normalizeSurfacePatch(raw.patch);
      if (!patch) return null;
      return { type: "surface_updated", at, id: raw.id, patch };
    }
    case "recon_submitted": {
      if (typeof raw.note !== "string") return null;
      const segments: ReconSegment[] = [];
      if (Array.isArray(raw.segments)) {
        for (const s of raw.segments) {
          const segment = normalizeReconSegment(s);
          if (segment) segments.push(segment);
        }
      }
      return { type: "recon_submitted", at, note: raw.note, segments };
    }
    case "segment_recorded": {
      const record = normalizeSegmentRecord(raw.record);
      if (!record) return null;
      return { type: "segment_recorded", at, record };
    }
    case "snapshot": {
      const snapshot = normalizeSnapshot(raw.snapshot);
      if (!snapshot) return null;
      return { type: "snapshot", at, snapshot };
    }
    default:
      return null;
  }
}

const STATUSES = new Set<HypothesisStatus>(["pending", "testing", "confirmed", "rejected", "blocked"]);

const SEC_SURFACE_STATUSES: readonly string[] = ["open", "examined", "cleared", "digging"];

function normalizeNode(value: unknown): Hypothesis | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id.trim()) return null;
  if (typeof o.description !== "string") return null;
  const status = typeof o.status === "string" && STATUSES.has(o.status as HypothesisStatus)
    ? (o.status as HypothesisStatus)
    : "pending";
  const attackVector = normalizeAttackVector(o.attackVector);
  return {
    id: o.id,
    // A node written before stage 6 has no kind; every such node was a
    // hypothesis, because that was the only thing a tree could hold.
    nodeKind: typeof o.nodeKind === "string" && NODE_KINDS.includes(o.nodeKind as NodeKind)
      ? (o.nodeKind as NodeKind)
      : "hypothesis",
    parentId: typeof o.parentId === "string" && o.parentId ? o.parentId : null,
    description: o.description,
    category: typeof o.category === "string" && o.category ? o.category : "other",
    status,
    evidence: normalizeEvidenceList(o.evidence),
    depth: typeof o.depth === "number" && Number.isFinite(o.depth) ? Math.max(0, Math.floor(o.depth)) : 0,
    createdAt: typeof o.createdAt === "string" ? o.createdAt : "",
    lastTouchedAt: typeof o.lastTouchedAt === "string" ? o.lastTouchedAt : "",
    score: typeof o.score === "number" && Number.isFinite(o.score) ? o.score : 0,
    spawnedFrom: Array.isArray(o.spawnedFrom) ? o.spawnedFrom.filter((s): s is string => typeof s === "string" && !!s) : [],
    // An explicit EMPTY array is meaningful: it means the gates were assessed and
    // there are none.  means nobody asked. Collapsing the two made
    // every unassessed finding report as usable.
    ...(normalizeVerificationRecord(o.lastVerification) ? { lastVerification: normalizeVerificationRecord(o.lastVerification)! } : {}),
    ...(normalizeRefutation(o.refutation) ? { refutation: normalizeRefutation(o.refutation)! } : {}),
  ...(normalizeFalsificationOverride(o.falsificationOverride) ? { falsificationOverride: normalizeFalsificationOverride(o.falsificationOverride)! } : {}),
    ...(Array.isArray(o.requires)
      ? { requires: (o.requires as unknown[]).filter((r): r is string => typeof r === "string" && !!r) }
      : {}),
    roundIntroduced: typeof o.roundIntroduced === "number" && Number.isFinite(o.roundIntroduced) ? Math.max(0, Math.floor(o.roundIntroduced)) : 0,
    timesSelected: typeof o.timesSelected === "number" && Number.isFinite(o.timesSelected) ? Math.max(0, Math.floor(o.timesSelected)) : 0,
    lastSelectedRound: typeof o.lastSelectedRound === "number" && Number.isFinite(o.lastSelectedRound) ? Math.max(0, Math.floor(o.lastSelectedRound)) : null,
    ...(typeof o.combinationKind === "string" && COMBINATION_KINDS.includes(o.combinationKind as CombinationKind)
      ? { combinationKind: o.combinationKind as CombinationKind }
      : {}),
    ...(attackVector ? { attackVector } : {}),
    ...(typeof o.segmentId === "string" && o.segmentId ? { segmentId: o.segmentId } : {}),
    ...(typeof o.challengedRound === "number" && Number.isFinite(o.challengedRound) ? { challengedRound: Math.max(0, Math.floor(o.challengedRound)) } : {}),
    ...(typeof o.pursueSpent === "number" && Number.isFinite(o.pursueSpent) && o.pursueSpent > 0
      ? { pursueSpent: Math.max(0, Math.floor(o.pursueSpent)) }
      : {}),
    ...(typeof o.severity === "string" && SEVERITIES.includes(o.severity as Severity)
      ? { severity: o.severity as Severity }
      : {}),
    ...(typeof o.statusReason === "string" && o.statusReason ? { statusReason: o.statusReason } : {}),
  };
}

/** Tolerant attack-vector parser: a malformed vector is dropped rather than
 * losing the node, and the drop is visible as an absent field. */
function normalizeAttackVector(value: unknown): AttackVector | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.entrypoint !== "string" || !o.entrypoint.trim()) return null;
  if (typeof o.technique !== "string" || !o.technique.trim()) return null;
  const path: AttackVector["path"] = [];
  if (Array.isArray(o.path)) {
    for (const step of o.path) {
      if (!step || typeof step !== "object") continue;
      const s = step as Record<string, unknown>;
      if (typeof s.detail !== "string" || !s.detail) continue;
      const location = s.location && typeof s.location === "object"
        ? (() => {
            const l = s.location as Record<string, unknown>;
            if (typeof l.file !== "string" || !l.file) return undefined;
            const line = typeof l.line === "number" && Number.isFinite(l.line) ? Math.max(1, Math.floor(l.line)) : 1;
            return { file: l.file, line };
          })()
        : undefined;
      path.push({ ...(location ? { location } : {}), detail: s.detail });
    }
  }
  const preconditions = Array.isArray(o.preconditions)
    ? o.preconditions.filter((p): p is string => typeof p === "string" && !!p)
    : undefined;
  return {
    entrypoint: o.entrypoint,
    path,
    technique: o.technique,
    ...(typeof o.payload === "string" && o.payload ? { payload: o.payload } : {}),
    ...(typeof o.impact === "string" && o.impact.trim() ? { impact: o.impact } : {}),
    ...(typeof o.poc === "string" && o.poc.trim() ? { poc: o.poc } : {}),
    ...(typeof o.pocExpected === "string" && o.pocExpected.trim() ? { pocExpected: o.pocExpected } : {}),
    // An explicit `false` is meaningful (POST-AUTH) and must not be dropped as
    // falsy — that would turn a recorded "requires a session" into "unassessed".
    ...(typeof o.preAuth === "boolean" ? { preAuth: o.preAuth } : {}),
    ...(preconditions && preconditions.length > 0 ? { preconditions } : {}),
  };
}

function normalizeEvidenceList(value: unknown): Evidence[] {
  if (!Array.isArray(value)) return [];
  const out: Evidence[] = [];
  for (const item of value) {
    const e = normalizeEvidence(item);
    if (e) out.push(e);
  }
  return out;
}

function normalizeEvidence(value: unknown): Evidence | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.detail !== "string" || !o.detail) return null;
  const kind = typeof o.kind === "string" ? o.kind : "reasoning";
  const location = normalizeLocation(o.location);
  return {
    kind: kind as Evidence["kind"],
    at: typeof o.at === "string" ? o.at : "",
    ...(location ? { location } : {}),
    ...(typeof o.command === "string" && o.command ? { command: o.command } : {}),
    // A FIELD ALLOWLIST, so a new Evidence field is invisible until it is added
    // here. This bit the `reproduces` flag: it was written to the log, dropped on
    // the way back in, and the tier it exists to control could never change — with
    // no error anywhere, because the record that lost it still validated.
    ...(o.reproduces === true ? { reproduces: true } : {}),
    detail: o.detail,
  };
}

/** `{ file, line }` or undefined. Shared so the two normalizers cannot drift. */
function normalizeLocation(value: unknown): Evidence["location"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const l = value as Record<string, unknown>;
  if (typeof l.file !== "string" || !l.file) return undefined;
  const line = typeof l.line === "number" && Number.isFinite(l.line) ? Math.max(1, Math.floor(l.line)) : 1;
  return { file: l.file, line };
}

/**
 * Rebuild a `/loopSEC` finding from stored JSON.
 *
 * A FIELD ALLOWLIST, like every normalizer here — and that has bitten this file
 * once already: `Evidence.reproduces` was written to the log and silently dropped
 * on the way back in, so the tier it controlled could never change and nothing
 * errored. Every field of `SecFinding` therefore appears below, and there is a
 * round-trip test for the class rather than for one field.
 */
function normalizeFinding(value: unknown): SecFinding | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id) return null;
  if (typeof o.title !== "string" || !o.title.trim()) return null;
  const location = normalizeLocation(o.location);
  const evidence = typeof o.evidence === "string" && o.evidence.trim() ? o.evidence : undefined;
  const chainOf = Array.isArray(o.chainOf)
    ? o.chainOf.filter((x): x is string => typeof x === "string" && !!x)
    : [];
  // THE ONE REQUIREMENT THIS MODE KEEPS: an artifact. Dropped on READ as well as
  // refused on write, so a hand-edited log cannot reintroduce a bare claim.
  //
  // A CHAIN IS THE OTHER WAY PAST IT, and this check has to know that: its artifact is
  // its PARTS, each of which carries one. Without this line the write side accepted a
  // chain and the read side silently dropped it — `recordFinding` returned ok and the
  // finding was not in the snapshot, which is the same shape as the allowlist bug that
  // has eaten four fields in this file.
  if (!location && !evidence && chainOf.length < 2) return null;
  const severity =
    typeof o.severity === "string" && (SEVERITIES as readonly string[]).includes(o.severity)
      ? (o.severity as Severity)
      : undefined;
  return {
    id: o.id,
    at: typeof o.at === "string" ? o.at : "",
    round: typeof o.round === "number" && Number.isFinite(o.round) ? Math.floor(o.round) : 0,
    title: o.title,
    category: typeof o.category === "string" && o.category ? o.category : "other",
    ...(severity ? { severity } : {}),
    ...(typeof o.preAuth === "boolean" ? { preAuth: o.preAuth } : {}),
    ...(location ? { location } : {}),
    ...(evidence ? { evidence } : {}),
    ...(typeof o.reasoning === "string" && o.reasoning ? { reasoning: o.reasoning } : {}),
    ...(typeof o.poc === "string" && o.poc ? { poc: o.poc } : {}),
    ...(typeof o.surfaceId === "string" && o.surfaceId ? { surfaceId: o.surfaceId } : {}),
    // A FIELD ALLOWLIST, and it has now eaten a new field FOUR times in this file:
    // `Evidence.reproduces`, `AuditLoopKind: "sec"`, the `SecSurface` fields, and now
    // this. Each one was written to the log and silently dropped on the way back in
    // with no error anywhere, because the record that lost it still validated.
    ...(chainOf.length >= 2 ? { chainOf } : {}),
    ...(normalizeStepList(o.path).length > 0 ? { path: normalizeStepList(o.path) } : {}),
    ...(normalizeVerification(o.verification) ? { verification: normalizeVerification(o.verification)! } : {}),
    ...(normalizeBlockers(o.blockers).length > 0 ? { blockers: normalizeBlockers(o.blockers) } : {}),
    ...(typeof o.pursuitSpent === "number" && Number.isFinite(o.pursuitSpent) && o.pursuitSpent > 0
      ? { pursuitSpent: Math.floor(o.pursuitSpent) }
      : {}),
    ...(typeof o.pursuitClosed === "string" && o.pursuitClosed ? { pursuitClosed: o.pursuitClosed } : {}),
    ...(o.deepen === true ? { deepen: true } : {}),
  };
}

/**
 * A blocker list, or nothing.
 *
 * A blocker is a STATE OF THE WORLD, so an empty entry is not a blocker — it is a blank line, and
 * keeping it would make the list look longer than the reasoning behind it. Same rule the evidence
 * list and the call chain use: what fails its own requirement is dropped on read, so a hand-edited
 * log cannot add a gate that says nothing.
 */
function normalizeBlockers(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((b): b is string => typeof b === "string" && b.trim() !== "").map((b) => b.trim());
}

/**
 * A recorded verification run, or nothing.
 *
 * `command` is what makes it a record: without it the entry would say "something was run"
 * and a reader could not re-run it. `confirmed` is recomputed from the exit-code and the
 * output substring rather than trusted from the log, so a hand-edited `true` cannot flip a
 * disconfirmed run into a reproduced finding.
 */
function normalizeVerification(value: unknown): SecVerification | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const o = value as Record<string, unknown>;
  if (typeof o.command !== "string" || !o.command.trim()) return undefined;
  const exitCode = typeof o.exitCode === "number" && Number.isFinite(o.exitCode) ? Math.floor(o.exitCode) : null;
  const timedOut = o.timedOut === true;
  const output = typeof o.output === "string" ? o.output : "";
  const expect = typeof o.expect === "string" ? o.expect : "";
  // RECOMPUTED. The log carries the verdict, but the verdict is a function of the run —
  // trusting the stored boolean would let a tampered log claim a reproduction that the
  // recorded exit code and output contradict.
  const expectExit = o.expectExit === "nonzero" ? "nonzero" : "zero";
  const expectOutput = typeof o.expectOutput === "string" && o.expectOutput ? o.expectOutput : null;
  const exitOk = exitCode !== null && (expectExit === "zero" ? exitCode === 0 : exitCode !== 0);
  const outputOk = expectOutput === null ? true : output.includes(expectOutput);
  return {
    at: typeof o.at === "string" ? o.at : "",
    command: o.command,
    output,
    exitCode,
    timedOut,
    expect,
    expectExit,
    ...(expectOutput !== null ? { expectOutput } : {}),
    confirmed: !timedOut && exitOk && outputOk,
  };
}

/** A call-chain step, or nothing. `detail` is what makes it a step. */
function normalizeStep(value: unknown): SecFindingStep | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.detail !== "string" || !o.detail.trim()) return null;
  const location = normalizeLocation({ file: o.file, line: o.line });
  return { detail: o.detail, ...(location ? { file: location.file, line: location.line } : {}) };
}

function normalizeStepList(value: unknown): SecFindingStep[] {
  if (!Array.isArray(value)) return [];
  const out: SecFindingStep[] = [];
  for (const item of value) {
    const step = normalizeStep(item);
    if (step) out.push(step);
  }
  return out;
}

function normalizeFindingList(value: unknown): SecFinding[] {
  if (!Array.isArray(value)) return [];
  const out: SecFinding[] = [];
  for (const item of value) {
    const finding = normalizeFinding(item);
    if (finding) out.push(finding);
  }
  return out;
}

/**
 * Rebuild one surface item. A FIELD ALLOWLIST, like every normalizer here.
 *
 * The allowlist has now silently eaten a new field twice in this file —
 * `Evidence.reproduces` and `AuditLoopKind: "sec"` — so every field of `SecSurface`
 * appears below, and the round-trip test covers the class rather than one field.
 */
function normalizeSurface(value: unknown): SecSurface | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id) return null;
  if (typeof o.title !== "string" || !o.title.trim()) return null;
  const status = typeof o.status === "string" && SEC_SURFACE_STATUSES.includes(o.status as SecSurfaceStatus)
    ? (o.status as SecSurfaceStatus)
    : "open";
  const kind = typeof o.kind === "string" && (SEC_SURFACE_KINDS as readonly string[]).includes(o.kind)
    ? (o.kind as SecSurfaceKind)
    : "other";
  const location = normalizeLocation(o.location);
  const categories = Array.isArray(o.categories) ? o.categories.filter((c): c is string => typeof c === "string" && !!c) : [];
  return {
    id: o.id,
    at: typeof o.at === "string" ? o.at : "",
    round: typeof o.round === "number" && Number.isFinite(o.round) ? Math.floor(o.round) : 0,
    kind,
    title: o.title,
    ...(location ? { location } : {}),
    ...(categories.length > 0 ? { categories } : {}),
    // The FIFTH field this allowlist has had to be taught. Every one was written to the
    // log and dropped on the way back in with no error, because the record that lost it
    // still validated.
    ...(typeof o.priority === "number" && Number.isFinite(o.priority) && o.priority !== 0
      ? { priority: Math.floor(o.priority) }
      : {}),
    ...(typeof o.digRounds === "number" && Number.isFinite(o.digRounds) && o.digRounds > 0
      ? { digRounds: Math.max(0, Math.floor(o.digRounds)) }
      : {}),
    ...(typeof o.attempts === "number" && Number.isFinite(o.attempts) && o.attempts > 0
      ? { attempts: Math.max(0, Math.floor(o.attempts)) }
      : {}),
    status,
    ...(typeof o.clearedReason === "string" && o.clearedReason ? { clearedReason: o.clearedReason } : {}),
    ...(normalizeLocation(o.guardLocation) ? { guardLocation: normalizeLocation(o.guardLocation)! } : {}),
    ...(typeof o.examinedAt === "string" && o.examinedAt ? { examinedAt: o.examinedAt } : {}),
    ...(typeof o.findingId === "string" && o.findingId ? { findingId: o.findingId } : {}),
  };
}

function normalizeSurfaceList(value: unknown): SecSurface[] {
  if (!Array.isArray(value)) return [];
  const out: SecSurface[] = [];
  for (const item of value) {
    const surface = normalizeSurface(item);
    if (surface) out.push(surface);
  }
  return out;
}

function normalizeSurfacePatch(value: unknown): SecSurfacePatch | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const patch: SecSurfacePatch = {};
  if (typeof o.status === "string" && SEC_SURFACE_STATUSES.includes(o.status as SecSurfaceStatus)) {
    patch.status = o.status as SecSurfaceStatus;
  }
  if (typeof o.clearedReason === "string" && o.clearedReason) patch.clearedReason = o.clearedReason;
  const guard = normalizeLocation(o.guardLocation);
  if (guard) patch.guardLocation = guard;
  if (typeof o.priority === "number" && Number.isFinite(o.priority)) patch.priority = Math.floor(o.priority);
  if (typeof o.digRounds === "number" && Number.isFinite(o.digRounds)) patch.digRounds = Math.max(0, Math.floor(o.digRounds));
  if (typeof o.attempts === "number" && Number.isFinite(o.attempts)) patch.attempts = Math.max(0, Math.floor(o.attempts));
  if (typeof o.examinedAt === "string" && o.examinedAt) patch.examinedAt = o.examinedAt;
  if (typeof o.findingId === "string" && o.findingId) patch.findingId = o.findingId;
  if (Array.isArray(o.categories)) {
    const categories = o.categories.filter((c): c is string => typeof c === "string" && !!c);
    if (categories.length > 0) patch.categories = categories;
  }
  if (typeof o.title === "string" && o.title.trim()) patch.title = o.title;
  const location = normalizeLocation(o.location);
  if (location) patch.location = location;
  return Object.keys(patch).length > 0 ? patch : null;
}

/** Apply a patch. A field the patch omits is KEPT, not cleared. */
function applySurfacePatch(surface: SecSurface, patch: SecSurfacePatch): SecSurface {
  return {
    ...surface,
    ...(patch.status !== undefined ? { status: patch.status } : {}),
    ...(patch.clearedReason !== undefined ? { clearedReason: patch.clearedReason } : {}),
    ...(patch.guardLocation !== undefined ? { guardLocation: patch.guardLocation } : {}),
    ...(patch.examinedAt !== undefined ? { examinedAt: patch.examinedAt } : {}),
    ...(patch.priority !== undefined ? { priority: patch.priority } : {}),
    ...(patch.digRounds !== undefined ? { digRounds: patch.digRounds } : {}),
    ...(patch.attempts !== undefined ? { attempts: patch.attempts } : {}),
    ...(patch.findingId !== undefined ? { findingId: patch.findingId } : {}),
    ...(patch.categories !== undefined ? { categories: patch.categories } : {}),
    ...(patch.title !== undefined ? { title: patch.title } : {}),
    ...(patch.location !== undefined ? { location: patch.location } : {}),
  };
}

function normalizeFindingPatch(value: unknown): SecFindingPatch | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const patch: SecFindingPatch = {};
  if (typeof o.title === "string" && o.title.trim()) patch.title = o.title;
  if (typeof o.category === "string" && o.category) patch.category = o.category;
  if (typeof o.severity === "string" && (SEVERITIES as readonly string[]).includes(o.severity)) {
    patch.severity = o.severity as Severity;
  }
  if (typeof o.preAuth === "boolean") patch.preAuth = o.preAuth;
  const location = normalizeLocation(o.location);
  if (location) patch.location = location;
  if (typeof o.evidence === "string" && o.evidence.trim()) patch.evidence = o.evidence;
  if (typeof o.reasoning === "string" && o.reasoning) patch.reasoning = o.reasoning;
  if (typeof o.poc === "string" && o.poc) patch.poc = o.poc;
  if (Array.isArray(o.path)) {
    const path = normalizeStepList(o.path);
    if (path.length > 0) patch.path = path;
  }
  if (Array.isArray(o.chainOf)) {
    const chain = o.chainOf.filter((x): x is string => typeof x === "string" && !!x);
    if (chain.length > 0) patch.chainOf = chain;
  }
  const verification = normalizeVerification(o.verification);
  if (verification) patch.verification = verification;
  // PRESENT-BUT-EMPTY IS MEANINGFUL HERE, unlike every other list in this file: an empty
  // `blockers` array is how the model says "the gate is open" — the pursuit is over because the
  // precondition now holds. Dropping it (the usual "empty list, no field" rule) would make the
  // gate impossible to clear, and the finding would be pursued until its budget ran out.
  if (Array.isArray(o.blockers)) patch.blockers = normalizeBlockers(o.blockers);
  if (typeof o.pursuitSpent === "number" && Number.isFinite(o.pursuitSpent) && o.pursuitSpent >= 0) {
    patch.pursuitSpent = Math.floor(o.pursuitSpent);
  }
  if (typeof o.pursuitClosed === "string" && o.pursuitClosed.trim()) patch.pursuitClosed = o.pursuitClosed.trim();
  if (typeof o.deepen === "boolean") patch.deepen = o.deepen;
  return Object.keys(patch).length > 0 ? patch : null;
}

/** Apply a patch. A field the patch omits is KEPT, not cleared. */
function applyFindingPatch(finding: SecFinding, patch: SecFindingPatch): SecFinding {
  return {
    ...finding,
    ...(patch.title !== undefined ? { title: patch.title } : {}),
    ...(patch.category !== undefined ? { category: patch.category } : {}),
    ...(patch.severity !== undefined ? { severity: patch.severity } : {}),
    ...(patch.preAuth !== undefined ? { preAuth: patch.preAuth } : {}),
    ...(patch.location !== undefined ? { location: patch.location } : {}),
    ...(patch.evidence !== undefined ? { evidence: patch.evidence } : {}),
    ...(patch.reasoning !== undefined ? { reasoning: patch.reasoning } : {}),
    ...(patch.poc !== undefined ? { poc: patch.poc } : {}),
    ...(patch.chainOf !== undefined ? { chainOf: patch.chainOf } : {}),
    ...(patch.path !== undefined ? { path: patch.path } : {}),
    ...(patch.verification !== undefined ? { verification: patch.verification } : {}),
    ...(patch.blockers !== undefined ? { blockers: patch.blockers } : {}),
    ...(patch.pursuitSpent !== undefined ? { pursuitSpent: patch.pursuitSpent } : {}),
    ...(patch.pursuitClosed !== undefined ? { pursuitClosed: patch.pursuitClosed } : {}),
    ...(patch.deepen !== undefined ? { deepen: patch.deepen } : {}),
  };
}

function normalizePatch(value: unknown): NodePatch | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const patch: NodePatch = {};
  if (typeof o.description === "string") patch.description = o.description;
  if (typeof o.category === "string") patch.category = o.category;
  if (typeof o.status === "string" && STATUSES.has(o.status as HypothesisStatus)) patch.status = o.status as HypothesisStatus;
  if (Array.isArray(o.evidence)) patch.evidence = normalizeEvidenceList(o.evidence);
  if (typeof o.lastTouchedAt === "string") patch.lastTouchedAt = o.lastTouchedAt;
  if (typeof o.score === "number" && Number.isFinite(o.score)) patch.score = o.score;
  if (Array.isArray(o.spawnedFrom)) patch.spawnedFrom = o.spawnedFrom.filter((s): s is string => typeof s === "string" && !!s);
  // An explicit EMPTY array is meaningful here: it removes the gates, which is how
  // a finding that turns out to stand alone stops being reported as gated.
  if (Array.isArray(o.requires)) patch.requires = o.requires.filter((r): r is string => typeof r === "string" && !!r);
  if (typeof o.roundIntroduced === "number" && Number.isFinite(o.roundIntroduced)) patch.roundIntroduced = Math.max(0, Math.floor(o.roundIntroduced));
  if (typeof o.timesSelected === "number" && Number.isFinite(o.timesSelected)) patch.timesSelected = Math.max(0, Math.floor(o.timesSelected));
  // `lastSelectedRound: null` is meaningful ("never selected"), so an explicit
  // null must survive the normalizer instead of collapsing to undefined.
  if ("lastSelectedRound" in o) {
    patch.lastSelectedRound = typeof o.lastSelectedRound === "number" && Number.isFinite(o.lastSelectedRound)
      ? Math.max(0, Math.floor(o.lastSelectedRound))
      : null;
  }
  if (typeof o.combinationKind === "string" && COMBINATION_KINDS.includes(o.combinationKind as CombinationKind)) {
    patch.combinationKind = o.combinationKind as CombinationKind;
  }
  const vector = normalizeAttackVector(o.attackVector);
  if (vector) patch.attackVector = vector;
  if (typeof o.segmentId === "string" && o.segmentId) patch.segmentId = o.segmentId;
  if (normalizeRefutation(o.refutation)) patch.refutation = normalizeRefutation(o.refutation)!;
  if (normalizeFalsificationOverride(o.falsificationOverride)) patch.falsificationOverride = normalizeFalsificationOverride(o.falsificationOverride)!;
  if (typeof o.challengedRound === "number" && Number.isFinite(o.challengedRound)) patch.challengedRound = Math.max(0, Math.floor(o.challengedRound));
  // An explicit null is meaningful: it clears the challenge record when a
  // finding leaves `confirmed`, so a re-confirmation is a NEW claim.
  else if ("challengedRound" in o && o.challengedRound === null) patch.challengedRound = null;
  if (typeof o.pursueSpent === "number" && Number.isFinite(o.pursueSpent)) patch.pursueSpent = Math.max(0, Math.floor(o.pursueSpent));
  if (typeof o.severity === "string" && SEVERITIES.includes(o.severity as Severity)) {
    patch.severity = o.severity as Severity;
  }
  if (typeof o.statusReason === "string") patch.statusReason = o.statusReason;
  return patch;
}

/**
 * A note the operator handed to a running audit.
 *
 * Returns null rather than a repaired note when the text is missing: an empty
 * note would be rendered as a heading with nothing under it, which reads as
 * "the operator said something" when they said nothing.
 */
function normalizeOperatorNote(value: unknown): OperatorNote | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id) return null;
  if (typeof o.text !== "string" || !o.text.trim()) return null;
  const delivered =
    typeof o.deliveredRound === "number" && Number.isFinite(o.deliveredRound) ? Math.max(0, Math.floor(o.deliveredRound)) : null;
  return {
    id: o.id,
    text: o.text,
    pinned: o.pinned === true,
    at: typeof o.at === "string" ? o.at : "",
    deliveredRound: delivered,
  };
}

function normalizeRefutation(value: unknown): RefutationAttempt | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  // An empty attempt is no attempt: recording one would satisfy the gate without
  // saying anything, which is worse than not having the gate.
  if (typeof o.attempt !== "string" || !o.attempt.trim()) return null;
  return { at: typeof o.at === "string" ? o.at : "", attempt: o.attempt };
}

function normalizeFalsificationOverride(value: unknown): FalsificationOverride | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.reason !== "string" || !o.reason.trim()) return null;
  return {
    at: typeof o.at === "string" ? o.at : "",
    reason: o.reason,
    counterexamples: Array.isArray(o.counterexamples)
      ? o.counterexamples.filter((c): c is string => typeof c === "string" && !!c)
      : [],
  };
}

function normalizeVerificationRecord(value: unknown): VerificationRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const verdicts = ["confirmed", "rejected", "inconclusive"];
  if (typeof o.suggestedVerdict !== "string" || !verdicts.includes(o.suggestedVerdict)) return null;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.floor(v)) : 0);
  return {
    at: typeof o.at === "string" ? o.at : "",
    suggestedVerdict: o.suggestedVerdict as VerificationRecord["suggestedVerdict"],
    survived: num(o.survived),
    falsified: num(o.falsified),
    inconclusive: num(o.inconclusive),
    counterexamples: Array.isArray(o.counterexamples)
      ? o.counterexamples.filter((c): c is string => typeof c === "string" && !!c)
      : [],
  };
}

function normalizeSnapshot(value: unknown): SnapshotPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.treeId !== "string" || typeof o.rootId !== "string") return null;
  const nodes: Hypothesis[] = [];
  if (Array.isArray(o.nodes)) {
    for (const n of o.nodes) {
      const node = normalizeNode(n);
      if (node) nodes.push(node);
    }
  }
  const selections: SelectionRecord[] = [];
  if (Array.isArray(o.selections)) {
    for (const s of o.selections) {
      const record = normalizeSelectionRecord(s);
      if (record) selections.push(record);
    }
  }
  const consolidations: ConsolidationRecord[] = [];
  if (Array.isArray(o.consolidations)) {
    for (const c of o.consolidations) {
      const record = normalizeConsolidationRecord(c);
      if (record) consolidations.push(record);
    }
  }
  const roundRecords: RoundRecord[] = [];
  if (Array.isArray(o.roundRecords)) {
    for (const r of o.roundRecords) {
      const record = normalizeRoundRecord(r);
      if (record) roundRecords.push(record);
    }
  }
  const segments: ReconSegment[] = [];
  if (Array.isArray(o.segments)) {
    for (const s of o.segments) {
      const segment = normalizeReconSegment(s);
      if (segment) segments.push(segment);
    }
  }
  const segmentRecords: SegmentRecord[] = [];
  if (Array.isArray(o.segmentRecords)) {
    for (const r of o.segmentRecords) {
      const record = normalizeSegmentRecord(r);
      if (record) segmentRecords.push(record);
    }
  }
  const notes: OperatorNote[] = [];
  if (Array.isArray(o.notes)) {
    for (const n of o.notes) {
      const note = normalizeOperatorNote(n);
      if (note && !notes.some((existing) => existing.id === note.id)) notes.push(note);
    }
  }
  return {
    treeId: o.treeId,
    objective: typeof o.objective === "string" ? o.objective : "",
    rootId: o.rootId,
    nodes,
    maxNodeSeq: typeof o.maxNodeSeq === "number" && Number.isFinite(o.maxNodeSeq) ? Math.max(0, Math.floor(o.maxNodeSeq)) : nodes.length,
    rounds: typeof o.rounds === "number" && Number.isFinite(o.rounds) ? Math.max(0, Math.floor(o.rounds)) : 0,
    compactions: typeof o.compactions === "number" && Number.isFinite(o.compactions) ? Math.max(0, Math.floor(o.compactions)) : 0,
    selections,
    consolidations,
    loop: normalizeLoopState(o.loop),
    roundRecords,
    notes,
    segments,
    segmentRecords,
    reconAt: typeof o.reconAt === "string" && o.reconAt ? o.reconAt : null,
    findings: normalizeFindingList(o.findings),
    surfaces: normalizeSurfaceList(o.surfaces),
    secNote: typeof o.secNote === "string" && o.secNote ? o.secNote : null,
  };
}

const LOOP_STATUSES = new Set<string>(["running", "paused", "stopped", "complete"]);

function normalizeContract(value: unknown): CompletionContract | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const minConfirmed = typeof o.minConfirmed === "number" && Number.isFinite(o.minConfirmed) ? Math.max(0, Math.floor(o.minConfirmed)) : 0;
  const categories = Array.isArray(o.categories) ? o.categories.filter((c): c is string => typeof c === "string" && !!c) : undefined;
  return {
    minConfirmed,
    ...(typeof o.minSeverity === "string" && SEVERITIES.includes(o.minSeverity as Severity)
      ? { minSeverity: o.minSeverity as Severity }
      : {}),
    ...(categories && categories.length > 0 ? { categories } : {}),
    requireConsolidated: o.requireConsolidated === true,
    // Legacy contracts predate the tier gate. A finding that rests on an
    // argument was never a finding, so the safe default for an old record is
    // to require an artifact — refusing to complete is recoverable, reporting
    // an opinion as a vulnerability is not.
    requireArtifact: o.requireArtifact !== false,
    requireReproduced: o.requireReproduced === true,
    requireChallenged: o.requireChallenged !== false,
    requireImpact: o.requireImpact === true,
    requireExploitable: o.requireExploitable === true,
    requirePreAuth: o.requirePreAuth === true,
  };
}

function normalizeSecLoopDeep(value: unknown): SecLoopDeep | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const findingId = typeof o.findingId === "string" ? o.findingId.trim() : "";
  const category = typeof o.category === "string" ? o.category : "";
  if (!findingId) return null;
  return {
    findingId,
    title: typeof o.title === "string" ? o.title : "",
    ...(typeof o.severity === "string" && (SEVERITIES as readonly string[]).includes(o.severity)
      ? { severity: o.severity as SecLoopDeep["severity"] }
      : {}),
    category,
    parentDir: typeof o.parentDir === "string" && o.parentDir ? o.parentDir : ".",
  };
}

function normalizeLoopState(value: unknown): AuditLoopState | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  // THE KIND WHITELIST. `/loopSEC` was added to `AuditLoopKind` and not here, so the
  // loop was written to the log and dropped on the way back in — `/loopsec` reported
  // "Loop started" and then every later command said "no audit loop in this
  // project". Same class as the `Evidence.reproduces` allowlist bug: a new variant
  // of an existing union is invisible until this switch is taught about it.
  if (o.kind !== "goal" && o.kind !== "loop" && o.kind !== "sec") return null;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.floor(v)) : 0);
  return {
    kind: o.kind,
    objective: typeof o.objective === "string" ? o.objective : "",
    contract: normalizeContract(o.contract),
    status: typeof o.status === "string" && LOOP_STATUSES.has(o.status) ? (o.status as AuditLoopState["status"]) : "paused",
    startedAt: typeof o.startedAt === "string" ? o.startedAt : "",
    updatedAt: typeof o.updatedAt === "string" ? o.updatedAt : "",
    round: num(o.round),
    awaitingRound: typeof o.awaitingRound === "number" && Number.isFinite(o.awaitingRound) ? Math.max(0, Math.floor(o.awaitingRound)) : null,
    maxRounds: num(o.maxRounds),
    ...(Array.isArray(o.focus) && o.focus.some((f) => typeof f === "string" && !!f)
      ? { focus: (o.focus as unknown[]).filter((f): f is string => typeof f === "string" && !!f) }
      : {}),
    // THE DEEP-RUN MARKER, round-tripped through its own allowlist. Every field that governs how a
    // round behaves has to survive this function or the run silently stops being the run it was
    // started as — the failure this file has produced five times now.
    ...(normalizeSecLoopDeep(o.deep) ? { deep: normalizeSecLoopDeep(o.deep)! } : {}),
    ...(typeof o.consolidationStall === "number" && Number.isFinite(o.consolidationStall) && o.consolidationStall > 0
      ? { consolidationStall: Math.max(0, Math.floor(o.consolidationStall)) }
      : {}),
    ...(typeof o.coverageRounds === "number" && Number.isFinite(o.coverageRounds) && o.coverageRounds > 0
      ? { coverageRounds: Math.max(0, Math.floor(o.coverageRounds)) }
      : {}),
    // `null` is MEANINGFUL here and is preserved: it is how a spent budget is
    // cleared, and collapsing it to `undefined` would make "spent" and "never
    // set" the same value in the record. Same rule as `challengedRound`.
    ...(typeof o.pauseAfterRound === "number" && Number.isFinite(o.pauseAfterRound)
      ? { pauseAfterRound: Math.max(0, Math.floor(o.pauseAfterRound)) }
      : "pauseAfterRound" in o && o.pauseAfterRound === null
        ? { pauseAfterRound: null }
        : {}),
    plateauWindow: num(o.plateauWindow),
    stallRounds: num(o.stallRounds),
    // A loop written before these fields existed has no banked pause time and is
    // not mid-pause, which is exactly what these defaults say.
    pausedMs: num(o.pausedMs),
    pausedAt: typeof o.pausedAt === "string" && o.pausedAt ? o.pausedAt : null,
    endedAt: typeof o.endedAt === "string" && o.endedAt ? o.endedAt : null,
    ...(o.widgetHidden === true ? { widgetHidden: true } : {}),
    ...(typeof o.stopReason === "string" && o.stopReason ? { stopReason: o.stopReason } : {}),
    ...(typeof o.pausedReason === "string" && o.pausedReason ? { pausedReason: o.pausedReason } : {}),
  };
}

function normalizeRoundRecord(value: unknown): RoundRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.floor(v)) : 0);
  return {
    round: num(o.round),
    at: typeof o.at === "string" ? o.at : "",
    kind: typeof o.kind === "string" && ROUND_KINDS.includes(o.kind as RoundKind) ? (o.kind as RoundKind) : "verify",
    ...(typeof o.segmentId === "string" && o.segmentId ? { segmentId: o.segmentId } : {}),
    nodeId: typeof o.nodeId === "string" && o.nodeId ? o.nodeId : null,
    nodeStatusAtStart: typeof o.nodeStatusAtStart === "string" && STATUSES.has(o.nodeStatusAtStart as HypothesisStatus)
      ? (o.nodeStatusAtStart as HypothesisStatus)
      : null,
    nodeEvidenceAtStart: num(o.nodeEvidenceAtStart),
    confirmedAtStart: num(o.confirmedAtStart),
    // A record written before this field existed gets 0, which makes a pursue
    // round look like it added nothing — the safe direction, because it CLOSES a
    // pursuit rather than extending one on bad information.
    nodeCountAtStart: num(o.nodeCountAtStart),
    // ABSENT means "not a sec round", and that is different from 0. Defaulting it
    // to 0 would make every hypothesis round look like a sec round with an empty
    // baseline, and `evaluateRound` would judge it by the wrong signal.
    ...(typeof o.findingCountAtStart === "number" && Number.isFinite(o.findingCountAtStart)
      ? { findingCountAtStart: Math.max(0, Math.floor(o.findingCountAtStart)) }
      : {}),
    ...(typeof o.surfaceId === "string" && o.surfaceId ? { surfaceId: o.surfaceId } : {}),
    ...(typeof o.findingId === "string" && o.findingId ? { findingId: o.findingId } : {}),
    ...(typeof o.pursuitBlockersAtStart === "string" ? { pursuitBlockersAtStart: o.pursuitBlockersAtStart } : {}),
    // RoundRecord.surfaceWasDigging — THE SIXTH field this file has had to be taught, and
    // the first one that landed in the WRONG normalizer: this anchor (a `surfaceId` string)
    // appears in both `normalizeFinding` and `normalizeRoundRecord`, and `replace(…, 1)`
    // took the earlier one. The symptom was a depth round still burning a plateau slot,
    // because the flag was never read back.
    ...(o.surfaceWasDigging === true ? { surfaceWasDigging: true } : {}),
    ...(typeof o.surfaceCountAtStart === "number" && Number.isFinite(o.surfaceCountAtStart)
      ? { surfaceCountAtStart: Math.max(0, Math.floor(o.surfaceCountAtStart)) }
      : {}),
    ...(typeof o.surfaceExaminedAtStart === "number" && Number.isFinite(o.surfaceExaminedAtStart)
      ? { surfaceExaminedAtStart: Math.max(0, Math.floor(o.surfaceExaminedAtStart)) }
      : {}),
    summary: Array.isArray(o.summary) ? o.summary.filter((s): s is string => typeof s === "string") : [],
  };
}

function normalizeReconSegment(value: unknown): ReconSegment | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.id !== "string" || !o.id) return null;
  if (typeof o.text !== "string" || !o.text) return null;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.floor(v)) : 0);
  return {
    id: o.id,
    index: num(o.index),
    paragraphs: num(o.paragraphs),
    text: o.text,
    hash: typeof o.hash === "string" ? o.hash : "",
  };
}

function normalizeSegmentRecord(value: unknown): SegmentRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.segmentId !== "string" || !o.segmentId) return null;
  const outcome = o.outcome === "nothing-found" ? "nothing-found" : "produced";
  return {
    segmentId: o.segmentId,
    at: typeof o.at === "string" ? o.at : "",
    outcome,
    hypothesisIds: Array.isArray(o.hypothesisIds) ? o.hypothesisIds.filter((h): h is string => typeof h === "string" && !!h) : [],
    ...(typeof o.note === "string" && o.note ? { note: o.note } : {}),
  };
}

const TRIGGERS = new Set<string>(["interval", "new-finding", "manual"]);

/** Tolerant consolidation-record parser. A damaged history entry must not lose
 * the tree, and an unknown trigger is dropped rather than trusted. */
function normalizeConsolidationRecord(value: unknown): ConsolidationRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.floor(v)) : 0);
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : []);
  return {
    round: num(o.round),
    at: typeof o.at === "string" ? o.at : "",
    trigger: typeof o.trigger === "string" && TRIGGERS.has(o.trigger) ? (o.trigger as ConsolidationTrigger) : "manual",
    confirmedIds: strings(o.confirmedIds),
    pairKeys: strings(o.pairKeys),
    singleIds: strings(o.singleIds),
    skipped: typeof o.skipped === "string" ? o.skipped : null,
  };
}

const CONSTRAINTS = new Set<string>(["max-same-node-rounds", "max-consecutive-depth", "max-category-ratio"]);

/** Tolerant selection-record parser: a damaged history entry must not lose the
 * whole tree, and an unknown constraint name is dropped rather than trusted. */
function normalizeSelectionRecord(value: unknown): SelectionRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.nodeId !== "string" || !o.nodeId) return null;
  const b = (o.breakdown ?? {}) as Record<string, unknown>;
  const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const vetoes: SelectionRecord["vetoes"] = [];
  if (Array.isArray(o.vetoes)) {
    for (const v of o.vetoes) {
      if (!v || typeof v !== "object") continue;
      const vo = v as Record<string, unknown>;
      if (typeof vo.nodeId !== "string" || typeof vo.constraint !== "string" || !CONSTRAINTS.has(vo.constraint)) continue;
      vetoes.push({ nodeId: vo.nodeId, constraint: vo.constraint as SelectionRecord["vetoes"][number]["constraint"], detail: typeof vo.detail === "string" ? vo.detail : "" });
    }
  }
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : []);
  return {
    round: num(o.round),
    nodeId: o.nodeId,
    at: typeof o.at === "string" ? o.at : "",
    score: num(o.score),
    breakdown: {
      novelty: num(b.novelty),
      evidence: num(b.evidence),
      categoryDiversity: num(b.categoryDiversity),
      depthPenalty: num(b.depthPenalty),
      recencyPenalty: num(b.recencyPenalty),
      blockedPenalty: num(b.blockedPenalty),
      gateBoost: num(b.gateBoost),
      focusBoost: num(b.focusBoost),
      testingBoost: num(b.testingBoost),
      total: num(b.total),
    },
    reasons: strings(o.reasons),
    vetoes,
    relaxations: strings(o.relaxations),
    candidates: num(o.candidates),
    populationSkew: strings(o.populationSkew),
  };
}

/**
 * Merge a node update over the previous node.
 *
 * `present` is the key set of the raw patch. Presence — not value — decides
 * what wins: a status-only patch omits `category`, and the normalizer's
 * default for a missing category would otherwise reset a node's category to
 * "other" on every status change. (`spawnedFrom`/`evidence` are the
 * exception: an explicitly empty array is a clear, so it is skipped only when
 * the patch did not carry the key at all.)
 */
export function applyPatch(prev: Hypothesis, patch: NodePatch, present?: ReadonlySet<string>): Hypothesis {
  const next: Hypothesis = { ...prev };
  const keys = present ?? new Set(Object.keys(patch));
  const target = next as unknown as Record<string, unknown>;
  for (const [key, value] of Object.entries(patch) as [keyof NodePatch, unknown][]) {
    if (value === undefined) continue;
    if (present && !keys.has(key)) continue;
    if ((key === "evidence" || key === "spawnedFrom") && Array.isArray(value) && value.length === 0) continue;
    target[key] = value;
  }
  return next;
}

// -----------------------------------------------------------------
// Fold
// -----------------------------------------------------------------

/** An empty snapshot for a project with no tree yet. */
export function emptySnapshot(): TreeSnapshot {
  return {
    treeId: "",
    objective: "",
    rootId: "",
    nodes: [],
    byId: new Map(),
    order: [],
    selections: [],
    consolidations: [],
    loop: null,
    roundRecords: [],
    notes: [],
    segments: [],
    segmentRecords: [],
    reconAt: null,
    findings: [],
    surfaces: [],
    secNote: null,
    maxNodeSeq: 0,
    rounds: 0,
    tornLines: 0,
    compactions: 0,
    updatedAt: "",
  };
}

/**
 * Fold a parsed event stream into a snapshot.
 *
 * Latest record wins per node id. The fold is pure so it can be tested
 * against hand-written logs, including deliberately damaged ones.
 */
export function foldEvents(events: readonly TreeEvent[]): TreeSnapshot {
  let treeId = "";
  let objective = "";
  let rootId = "";
  let maxNodeSeq = 0;
  let rounds = 0;
  let compactions = 0;
  let updatedAt = "";
  let selections: SelectionRecord[] = [];
  let consolidations: ConsolidationRecord[] = [];
  let loop: AuditLoopState | null = null;
  let roundRecords: RoundRecord[] = [];
  let segments: ReconSegment[] = [];
  let segmentRecords: SegmentRecord[] = [];
  let reconAt: string | null = null;
  let findings: SecFinding[] = [];
  let surfaces: SecSurface[] = [];
  let secNote: string | null = null;
  let notes: OperatorNote[] = [];
  const order: string[] = [];
  const byId = new Map<string, Hypothesis>();

  const pushSelection = (record: SelectionRecord): void => {
    selections.push(record);
    if (selections.length > HISTORY_WINDOW) selections = selections.slice(-HISTORY_WINDOW);
  };
  const pushConsolidation = (record: ConsolidationRecord): void => {
    consolidations.push(record);
    if (consolidations.length > CONSOLIDATION_HISTORY_WINDOW) {
      consolidations = consolidations.slice(-CONSOLIDATION_HISTORY_WINDOW);
    }
  };
  const pushRoundDetail = (record: RoundRecord): void => {
    roundRecords.push(record);
    if (roundRecords.length > ROUND_HISTORY_WINDOW) roundRecords = roundRecords.slice(-ROUND_HISTORY_WINDOW);
  };
  const pushSegmentRecord = (record: SegmentRecord): void => {
    segmentRecords.push(record);
    if (segmentRecords.length > SEGMENT_HISTORY_WINDOW) segmentRecords = segmentRecords.slice(-SEGMENT_HISTORY_WINDOW);
  };
  // Operator notes are deliberately NOT windowed. Everything else here is an
  // observation that can be re-derived by re-reading the project; a note is the
  // only thing in the ledger that exists nowhere else, so dropping one would
  // lose an instruction the operator gave and nothing could recover it.
  const pushNote = (note: OperatorNote): void => {
    if (notes.some((n) => n.id === note.id)) return;
    notes.push(note);
  };

  const put = (node: Hypothesis, at: string): void => {
    if (!byId.has(node.id)) order.push(node.id);
    byId.set(node.id, node);
    if (at) updatedAt = at;
  };

  for (const event of events) {
    switch (event.type) {
      case "tree_created": {
        treeId = event.treeId;
        objective = event.objective;
        if (event.at) updatedAt = event.at;
        break;
      }
      case "node_added": {
        put(event.node, event.at);
        maxNodeSeq = Math.max(maxNodeSeq, seqOf(event.node.id));
        if (event.node.parentId === null) rootId = event.node.id;
        break;
      }
      case "verification_recorded": {
        const target = byId.get(event.id);
        // A verification for a node that is not in the tree is ignored rather
        // than creating one: the node is the record, this is an annotation.
        if (target) put({ ...target, lastVerification: event.record }, event.at);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "node_updated": {
        const prev = byId.get(event.id);
        if (!prev) break; // an update for a node the log never added
        put(applyPatch(prev, event.patch), event.at);
        break;
      }
      case "round_recorded": {
        rounds = Math.max(rounds, event.round);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "selection_recorded": {
        pushSelection(event.record);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "consolidation_recorded": {
        pushConsolidation(event.record);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "loop_updated": {
        loop = event.loop;
        if (event.at) updatedAt = event.at;
        break;
      }
      case "operator_note_recorded": {
        pushNote(event.note);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "operator_note_delivered": {
        const target = notes.find((n) => n.id === event.id);
        // A delivery for an unknown note is ignored rather than creating one:
        // the note is the record, the delivery is only an annotation on it.
        if (target && target.deliveredRound === null) {
          notes = notes.map((n) => (n.id === event.id ? { ...n, deliveredRound: event.round } : n));
        }
        if (event.at) updatedAt = event.at;
        break;
      }
      case "round_detail": {
        pushRoundDetail(event.record);
        rounds = Math.max(rounds, event.record.round);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "recon_submitted": {
        // A recon submission REPLACES the segment inventory. Segment ids are
        // content+position derived, so a note the model edited keeps the ids of
        // the segments whose text did not change — and only those segments stay
        // covered.
        segments = [...event.segments];
        reconAt = event.at || reconAt;
        if (event.at) updatedAt = event.at;
        break;
      }
      case "finding_recorded": {
        // Append-only and never windowed: see TreeEvent. A duplicate id would make
        // the report count the same finding twice, so it is dropped rather than
        // trusted.
        if (!findings.some((f) => f.id === event.finding.id)) findings = [...findings, event.finding];
        if (event.at) updatedAt = event.at;
        break;
      }
      case "finding_updated": {
        findings = findings.map((f) => (f.id === event.id ? applyFindingPatch(f, event.patch) : f));
        if (event.at) updatedAt = event.at;
        break;
      }
      case "sec_recon_submitted": {
        secNote = event.note;
        if (event.at) updatedAt = event.at;
        break;
      }
      case "surface_recorded": {
        // Append-only, and a duplicate id is dropped rather than trusted: the report
        // counts examined/total, and a double-counted item makes that ratio a lie.
        if (!surfaces.some((x) => x.id === event.surface.id)) surfaces = [...surfaces, event.surface];
        if (event.at) updatedAt = event.at;
        break;
      }
      case "surface_updated": {
        surfaces = surfaces.map((x) => (x.id === event.id ? applySurfacePatch(x, event.patch) : x));
        if (event.at) updatedAt = event.at;
        break;
      }
      case "segment_recorded": {
        pushSegmentRecord(event.record);
        if (event.at) updatedAt = event.at;
        break;
      }
      case "snapshot": {
        // A snapshot REPLACES the folded state; events after it are folded on
        // top. That is what makes compaction bounded without a rewrite.
        order.length = 0;
        byId.clear();
        treeId = event.snapshot.treeId;
        objective = event.snapshot.objective;
        rootId = event.snapshot.rootId;
        maxNodeSeq = event.snapshot.maxNodeSeq;
        rounds = Math.max(rounds, event.snapshot.rounds);
        compactions = Math.max(compactions, event.snapshot.compactions);
        selections = event.snapshot.selections.slice(-HISTORY_WINDOW);
        consolidations = event.snapshot.consolidations.slice(-CONSOLIDATION_HISTORY_WINDOW);
        loop = event.snapshot.loop;
        roundRecords = event.snapshot.roundRecords.slice(-ROUND_HISTORY_WINDOW);
        // Notes are replaced, not merged: the snapshot IS the folded state of
        // every note event before it, so merging would be a no-op that hides a
        // genuinely missing note behind a stale one.
        notes = [...(event.snapshot.notes ?? [])];
        segments = [...event.snapshot.segments];
        segmentRecords = event.snapshot.segmentRecords.slice(-SEGMENT_HISTORY_WINDOW);
        reconAt = event.snapshot.reconAt;
        // Findings are NOT windowed — see TreeEvent. A snapshot carries all of
        // them, because dropping one would silently shrink the deliverable.
        findings = [...(event.snapshot.findings ?? [])];
        surfaces = [...(event.snapshot.surfaces ?? [])];
        secNote = event.snapshot.secNote ?? null;
        for (const node of event.snapshot.nodes) put(node, event.at);
        if (event.at) updatedAt = event.at;
        break;
      }
    }
  }

  const nodes = order.map((id) => byId.get(id)!);
  for (const node of nodes) maxNodeSeq = Math.max(maxNodeSeq, seqOf(node.id));
  if (!rootId) {
    const root = nodes.find((n) => n.parentId === null);
    if (root) rootId = root.id;
  }

  return {
    treeId, objective, rootId, nodes, byId, order, selections, consolidations, loop, roundRecords,
    notes, segments, segmentRecords, reconAt, findings, surfaces, secNote, maxNodeSeq, rounds, tornLines: 0, compactions, updatedAt,
  };
}

function seqOf(id: string): number {
  const m = /^H-(\d+)$/.exec(id);
  return m ? Number(m[1]) : 0;
}

// -----------------------------------------------------------------
// I/O
// -----------------------------------------------------------------

export interface LoadResult {
  snapshot: TreeSnapshot;
  /** Lines with no terminating newline (crash artifact). */
  torn: number;
  /** Complete lines that were not valid events (real corruption). */
  malformed: number;
  /** Complete lines carrying an event type this build does not know. */
  unknown: number;
  /** True when the log exists but could not be read at all. */
  readError?: string;
}

/**
 * Read and fold the log.
 *
 * Never throws: a missing log is an empty tree, and an unreadable log is an
 * empty tree PLUS a `readError` the caller must surface. Failing closed on an
 * empty snapshot would silently discard a real audit.
 */
export function load(projectRoot: string): LoadResult {
  return loadFrom(treeLogPath(projectRoot));
}

/** The `/loopsec` twin of `load`: same fold, same failure semantics, a different log. */
export function loadSec(projectRoot: string): LoadResult {
  return loadFrom(secTreeLogPath(projectRoot));
}

function loadFrom(file: string): LoadResult {
  let text: string;
  try {
    if (!fs.existsSync(file)) {
      return { snapshot: emptySnapshot(), torn: 0, malformed: 0, unknown: 0 };
    }
    text = fs.readFileSync(file, "utf-8");
  } catch (error) {
    return {
      snapshot: emptySnapshot(),
      torn: 0,
      malformed: 0,
      unknown: 0,
      readError: error instanceof Error ? error.message : String(error),
    };
  }
  const parsed = parseEvents(text);
  const snapshot = foldEvents(parsed.events);
  snapshot.tornLines = parsed.torn;
  return { snapshot, torn: parsed.torn, malformed: parsed.malformed, unknown: parsed.unknown };
}

/** Append one event. Returns false when the write failed — callers must
 * surface that, never assume success. */
export function appendEvent(projectRoot: string, event: TreeEvent): boolean {
  return appendTo(treeLogPath(projectRoot), event);
}

/** The `/loopsec` twin of `appendEvent`. */
export function appendSecEvent(projectRoot: string, event: TreeEvent): boolean {
  return appendTo(secTreeLogPath(projectRoot), event);
}

function appendTo(file: string, event: TreeEvent): boolean {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // `"a"` opens with O_APPEND and the descriptor is closed by this call:
    // one write, no rename, no link, no held lock.
    fs.appendFileSync(file, serializeEvent(event), "utf-8");
    return true;
  } catch {
    return false;
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function newTreeId(): string {
  return `T-${randomUUID().slice(0, 8)}`;
}

/** Stable short hash of an assertion, used to detect an exact duplicate
 * hypothesis recorded twice under different ids. */
export function descriptionKey(description: string): string {
  const normalized = description
    .toLowerCase()
    .replace(/[`'"“”‘’]/g, "")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/g, " ");
  return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

// -----------------------------------------------------------------
// Compaction (append-only)
// -----------------------------------------------------------------

/** Records-after-snapshot threshold at which `compactIfNeeded` fires. */
export const COMPACT_AFTER_EVENTS = 400;

/** Count the events after the newest snapshot. This is the read cost the
 * next `load()` will pay. */
export function eventsSinceSnapshot(projectRoot: string): number {
  const file = treeLogPath(projectRoot);
  try {
    if (!fs.existsSync(file)) return 0;
    const { events } = parseEvents(fs.readFileSync(file, "utf-8"));
    let lastSnapshot = -1;
    events.forEach((e, i) => {
      if (e.type === "snapshot") lastSnapshot = i;
    });
    return events.length - lastSnapshot - 1;
  } catch {
    return 0;
  }
}

/**
 * Append a snapshot of the current folded state.
 *
 * This is compaction, NOT a rewrite: the file is only ever appended to. Read
 * cost becomes O(nodes) instead of O(events).
 *
 * Refuses to compact a tree with no root (nothing to snapshot) or when a
 * snapshot would be larger than the events it subsumes (a young tree).
 */
export function compact(projectRoot: string): boolean {
  const { snapshot, readError } = load(projectRoot);
  if (readError || !snapshot.rootId || snapshot.nodes.length === 0) return false;
  const since = eventsSinceSnapshot(projectRoot);
  if (since === 0) return false;
  const payload: SnapshotPayload = {
    treeId: snapshot.treeId,
    objective: snapshot.objective,
    rootId: snapshot.rootId,
    nodes: snapshot.nodes,
    maxNodeSeq: snapshot.maxNodeSeq,
    rounds: snapshot.rounds,
    compactions: snapshot.compactions + 1,
    selections: snapshot.selections.slice(-HISTORY_WINDOW),
    consolidations: snapshot.consolidations.slice(-CONSOLIDATION_HISTORY_WINDOW),
    loop: snapshot.loop,
    roundRecords: snapshot.roundRecords.slice(-ROUND_HISTORY_WINDOW),
    notes: snapshot.notes,
    segments: [...snapshot.segments],
    segmentRecords: snapshot.segmentRecords.slice(-SEGMENT_HISTORY_WINDOW),
    reconAt: snapshot.reconAt,
    findings: [...snapshot.findings],
    surfaces: [...snapshot.surfaces],
    secNote: snapshot.secNote,
  };
  return appendEvent(projectRoot, { type: "snapshot", at: nowIso(), snapshot: payload });
}

/** Compact when the log has grown past the threshold. Returns whether a
 * snapshot was written. */
export function compactIfNeeded(projectRoot: string, threshold = COMPACT_AFTER_EVENTS): boolean {
  if (eventsSinceSnapshot(projectRoot) < threshold) return false;
  return compact(projectRoot);
}

// -----------------------------------------------------------------
// Crash recovery
// -----------------------------------------------------------------

export interface RepairResult {
  repaired: boolean;
  /** Bytes removed from the torn tail (0 when nothing was torn). */
  droppedBytes: number;
  reason: string;
}

/**
 * Truncate a torn tail so the next append starts from a clean line boundary.
 *
 * This is the ONLY operation that shortens the log, and it only ever removes
 * bytes after the last newline — i.e. a partial record that was never
 * durable. `truncateSync` is used rather than a rewrite+rename because
 * truncation is in-place and needs no second file (exFAT-safe).
 *
 * Safe to call at any time; a log with a clean tail is left untouched.
 */
export function repairTornTail(projectRoot: string): RepairResult {
  const file = treeLogPath(projectRoot);
  let text: string;
  try {
    if (!fs.existsSync(file)) return { repaired: false, droppedBytes: 0, reason: "no log" };
    text = fs.readFileSync(file, "utf-8");
  } catch (error) {
    return { repaired: false, droppedBytes: 0, reason: error instanceof Error ? error.message : String(error) };
  }
  if (!text || text.endsWith("\n")) return { repaired: false, droppedBytes: 0, reason: "clean tail" };
  const lastNewline = text.lastIndexOf("\n");
  const keep = lastNewline + 1; // 0 when there is no newline at all
  const dropped = Buffer.byteLength(text, "utf-8") - Buffer.byteLength(text.slice(0, keep), "utf-8");
  try {
    fs.truncateSync(file, keep);
    return { repaired: true, droppedBytes: dropped, reason: "dropped a torn tail" };
  } catch (error) {
    return { repaired: false, droppedBytes: 0, reason: error instanceof Error ? error.message : String(error) };
  }
}

/** Convenience predicate for callers that only need "is this node a verdict". */
export { isVerdict };
