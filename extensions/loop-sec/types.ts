/**
 * pi-audit-loopsec — extensions/loop-sec/types.ts
 *
 * The data model. Read this file first: the whole extension is a consequence
 * of one decision — **a node is a falsifiable ASSERTION, not a task.**
 *
 * "Check whether the login handler validates the JWT signature" is a task. It
 * cannot be confirmed or rejected; it can only be "done", and a done task
 * produces no knowledge. "The login handler does not validate the JWT
 * signature" is a hypothesis: reading `src/auth/jwt.ts:41` either supports it
 * or refutes it, and either outcome is a durable fact about the codebase.
 *
 * Everything downstream depends on that distinction:
 *   - a node has a STATUS that is a verdict (confirmed / rejected), not a
 *     progress marker;
 *   - a node has EVIDENCE, because a verdict without raw evidence is an
 *     opinion;
 *   - a node has CHILDREN, because refuting "the handler validates the
 *     signature" immediately raises "then how is the signature trusted?" —
 *     the tree grows by falsification, not by decomposition.
 */

// -----------------------------------------------------------------
// Hypothesis
// -----------------------------------------------------------------

/**
 * Verdict lifecycle.
 *
 *   pending    — recorded, not yet examined.
 *   testing    — currently being examined (exactly one node per round in the
 *                default scheduler, so this is also the "in flight" marker).
 *   confirmed  — evidence supports the assertion. A confirmed node is a
 *                FINDING and becomes an input to vulnerability combination.
 *   rejected   — evidence refutes the assertion. A rejection is a RESULT, not
 *                a failure: it is what prunes the search space.
 *   blocked    — cannot be examined yet (needs a runtime, a credential, a
 *                sibling hypothesis to resolve first). Blocked nodes are
 *                re-queued, never silently dropped.
 */
export type HypothesisStatus = "pending" | "testing" | "confirmed" | "rejected" | "blocked";

/** Statuses that are terminal verdicts — a node here is never re-tested
 * unless it is explicitly reopened with new evidence. */
export const VERDICT_STATUSES: readonly HypothesisStatus[] = ["confirmed", "rejected"];

/** Statuses that still need work from the scheduler. */
export const OPEN_STATUSES: readonly HypothesisStatus[] = ["pending", "testing", "blocked"];

export function isVerdict(status: HypothesisStatus): boolean {
  return status === "confirmed" || status === "rejected";
}

// -----------------------------------------------------------------
// Severity
// -----------------------------------------------------------------

/**
 * How bad it is if the assertion is true.
 *
 * Kept separate from `category` (what kind of bug) because the two answer
 * different questions and a completion contract needs the first: "find one
 * verified high-severity vulnerability" is not expressible in terms of classes
 * alone. It is OPTIONAL — an audit that has not yet judged impact should not be
 * forced to guess — and the `/goal` contract treats "unset" as "not yet rated",
 * never as "low".
 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Rank for comparison: lower is worse, so `severityRank(a) <= severityRank(b)`
 * means "a is at least as bad as b". */
export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

/** True when `severity` is at least as bad as `floor`. */
export function meetsSeverity(severity: Severity | undefined, floor: Severity): boolean {
  if (!severity) return false;
  return severityRank(severity) <= severityRank(floor);
}

export function isOpen(status: HypothesisStatus): boolean {
  return !isVerdict(status);
}

/**
 * True when the node has left the unexamined pool with a RECORDED JUDGEMENT.
 *
 * Wider than `isVerdict` on purpose, and the difference is the whole point:
 * `blocked` is a real answer. The auditor established the code facts and wrote
 * down what it cannot settle without more data — a deployment config, a live
 * daemon, a decision made outside the source. That is the honest outcome of an
 * examination, and the plateau counter must not read it as "nothing happened".
 *
 * Counting it as nothing punishes honesty. A model that cannot settle a
 * hypothesis is then pushed toward forcing a `rejected` (a false negative) or a
 * `confirmed` (a false positive) rather than admitting the uncertainty — which
 * is a CORRECTNESS problem for the audit, not just a UX one.
 *
 * `isVerdict` deliberately stays narrow: a confirmed/rejected verdict still
 * requires evidence, and a blocked node is still re-testable when the data
 * arrives, because blocked means "not yet", not "decided".
 */
export function isResolved(status: HypothesisStatus): boolean {
  return status === "confirmed" || status === "rejected" || status === "blocked";
}

/**
 * May the scheduler pick this node?
 *
 * A `scope` node is excluded because it has no truth value: it declares a
 * boundary, so a round spent "falsifying" it would produce nothing. Everything
 * that counts "open work" must use this predicate rather than `isOpen` alone,
 * or the scope node would inflate every progress figure by one and the loop
 * would look like it always has something left to do.
 */
export function isSchedulable(node: Pick<Hypothesis, "nodeKind" | "status">): boolean {
  return node.nodeKind !== "scope" && isOpen(node.status);
}

// -----------------------------------------------------------------
// Verification tier — how well a verdict is supported
// -----------------------------------------------------------------

/**
 * How much a verdict actually rests on.
 *
 *   reasoning-only — every evidence entry is an argument with no artifact. The
 *                    verdict is the model's opinion, and a report that presents
 *                    it as a finding is worse than one that omits it.
 *   static         — at least one real `file`/`code-slice` with a location. The
 *                    claim is anchored in code a reader can open.
 *   command-ran    — a `command-output` carrying its command, but nobody declared
 *                    that the output demonstrates the assertion. The command is
 *                    real and re-runnable; what is missing is the link to THIS
 *                    claim. A `grep` that found a sink lands here — and so does a
 *                    genuine reproduction whose author forgot to mark it.
 *   reproduced     — a `command-output` carrying its command AND explicitly marked
 *                    `reproduces: true`: the author states that this output IS
 *                    the demonstration.
 *
 * This is DERIVED from the evidence, never declared by the model: "trustworthy"
 * has to be a property of the record, not a self-assessment. It is what lets a
 * completion contract demand a high-severity finding that is actually anchored,
 * and what lets a report say honestly which findings are opinions.
 *
 * `command-ran` exists because the previous rule — "any command-output with a
 * command is reproduced" — INFLATED the tier. Measured on a real Checkmk audit:
 * 2 of 17 high findings held the reproduced tier on the strength of `ls -l` and
 * `grep -c`, and both findings' own dossiers said in writing "not executed this
 * round; does not claim reproduction". The report printed REPRODUCED in the
 * header and "does not claim reproduction" twenty lines below it. Requiring the
 * author to say WHICH of the two a command is fixes the inflation without
 * discarding the fact that the command ran — that fact is still recorded, it just
 * stops being presented as a reproduction.
 */
export type VerificationTier = "reasoning-only" | "static" | "command-ran" | "reproduced";

export const VERIFICATION_TIERS: readonly VerificationTier[] = ["reasoning-only", "static", "command-ran", "reproduced"];

/** Rank for comparison: higher is better supported. */
export function tierRank(tier: VerificationTier): number {
  return VERIFICATION_TIERS.indexOf(tier);
}

/** True when `tier` is at least as well supported as `floor`. */
export function meetsTier(tier: VerificationTier, floor: VerificationTier): boolean {
  return tierRank(tier) >= tierRank(floor);
}

/**
 * What one verification run concluded, kept on the node.
 *
 * `falsified > 0` is the important field: one counterexample refutes, so a
 * `confirmed` verdict recorded over a falsified probe is a contradiction the
 * tool can see and used to ignore.
 */
export interface VerificationRecord {
  at: string;
  /** What the executor suggested, from the probe outcomes alone. */
  suggestedVerdict: "confirmed" | "rejected" | "inconclusive";
  survived: number;
  falsified: number;
  inconclusive: number;
  /** One line per falsified probe — the counterexamples themselves. */
  counterexamples: string[];
}

/**
 * A written attempt to refute a finding, for when no probe was run.
 *
 * Weaker than a probe, and it is recorded as the weaker thing: a probe produces a
 * mechanical fact the tool can check, while this is the auditor's account of one.
 * It exists because the alternative is a confirmation with NOTHING behind it.
 */
export interface RefutationAttempt {
  at: string;
  /** What would have made this false, and what was found when looking for it. */
  attempt: string;
}

export interface FalsificationOverride {
  at: string;
  reason: string;
  /** The counterexamples that were overridden, so the report can quote them. */
  counterexamples: string[];
}

/** Has this finding survived an attempt to refute it? */
export function hasBeenChallenged(node: Pick<Hypothesis, "challengedRound">): boolean {
  return typeof node.challengedRound === "number";
}

// -----------------------------------------------------------------
// Exploitation chains — is this finding actually USABLE?
// -----------------------------------------------------------------

/**
 * Whether a confirmed finding can actually be exploited.
 *
 *   standalone  — gates were ASSESSED and there are none. `requires: []` was set
 *                 deliberately, so someone asked "what does this depend on?"
 *                 and answered "nothing".
 *   chain-ready — every gate is confirmed. The chain works.
 *   gated       — confirmed, but at least one gate is still unverified.
 *   broken      — a gate was REFUTED, so the chain cannot work as stated.
 *   untracked   — the finding RECORDS preconditions and none of them became a
 *                 hypothesis, so nothing will ever test them.
 *   unassessed  — nobody asked. No gates, and no preconditions either.
 *
 * THE LAST TWO EXIST BECAUSE "no gates recorded" IS NOT "no gates needed".
 * Treating them as the same made every finding whose exploitability was never
 * examined count as USABLE — on a real audit that read as "13/13 usable" for
 * thirteen static, unreproduced claims. The same distinction the impact section
 * already makes ("not assessed" is not "no impact") applies here.
 */
export type ChainState = "standalone" | "chain-ready" | "gated" | "broken" | "untracked" | "unassessed";

/** States in which the finding can actually be used. */
export function isUsable(state: ChainState): boolean {
  return state === "standalone" || state === "chain-ready";
}

export interface ChainStatus {
  state: ChainState;
  /** Gate ids that are still open (pending/testing/blocked). */
  pending: string[];
  /** Gate ids that were REFUTED — any one of these breaks the chain. */
  refuted: string[];
  /** Gate ids that are confirmed. */
  confirmed: string[];
  /** Gate ids that are not in the tree at all. */
  missing: string[];
}

/**
 * Derive whether a node's exploitation chain is usable.
 *
 * Derived, never declared: a model that could mark its own chain "ready" would
 * mark every chain ready, which is the failure this whole project exists to
 * avoid. The answer comes from the gates' own statuses.
 */
export function chainState(
  node: Pick<Hypothesis, "requires" | "attackVector">,
  lookup: (id: string) => Pick<Hypothesis, "status"> | undefined,
): ChainStatus {
  const empty: Omit<ChainStatus, "state"> = { pending: [], refuted: [], confirmed: [], missing: [] };
  // `undefined` means NOBODY ASKED. `[]` means someone asked and answered
  // "nothing". The store preserves that difference, so it is preserved here.
  if (node.requires === undefined) {
    const pre = node.attackVector?.preconditions ?? [];
    return { state: pre.length > 0 ? "untracked" : "unassessed", ...empty };
  }
  const gates = node.requires;
  if (gates.length === 0) return { state: "standalone", ...empty };
  const pending: string[] = [];
  const refuted: string[] = [];
  const confirmed: string[] = [];
  const missing: string[] = [];
  for (const id of gates) {
    const gate = lookup(id);
    if (!gate) missing.push(id);
    else if (gate.status === "confirmed") confirmed.push(id);
    else if (gate.status === "rejected") refuted.push(id);
    else pending.push(id);
  }
  // A refuted gate is checked FIRST: one broken link means the chain cannot work,
  // and reporting it as "gated" would imply it might still come good.
  const state: ChainState =
    refuted.length > 0 ? "broken" : missing.length > 0 || pending.length > 0 ? "gated" : "chain-ready";
  return { state, pending, refuted, confirmed, missing };
}

/**
 * Every node that lists `id` in its `requires` — the reverse index.
 *
 * What it is for: a gate is the single most valuable hypothesis in the tree when
 * its dependent finding is confirmed and HIGH, because confirming the gate turns
 * a sink into a working exploit. The scheduler needs to see that relationship to
 * prioritise it.
 */
export function gatesOf(snapshot: Pick<TreeSnapshot, "nodes">, id: string): Hypothesis[] {
  return snapshot.nodes.filter((n) => (n.requires ?? []).includes(id));
}

export function verificationTier(node: Pick<Hypothesis, "evidence">): VerificationTier {
  const ran = (e: Evidence): boolean =>
    e.kind === "command-output" && typeof e.command === "string" && e.command.trim() !== "";
  // REPRODUCED requires the author to have CLAIMED it. See the type comment: the
  // weaker rule counted a `grep` as a reproduction, and a report that says
  // REPRODUCED for a grep is the kind of thing that costs a reader's trust in
  // every other line.
  if (node.evidence.some((e) => ran(e) && e.reproduces === true)) return "reproduced";
  if (node.evidence.some(ran)) return "command-ran";
  const anchored = node.evidence.some((e) => (e.kind === "code-slice" || e.kind === "file") && e.location);
  if (anchored) return "static";
  return "reasoning-only";
}

/**
 * One piece of information the operator handed to a running audit.
 *
 * `pinned` separates the two kinds. An unpinned note is an instruction for one
 * round ("look at the queue consumer this round") and is consumed when a brief
 * carries it. A pinned note is a durable fact about the project ("the admin API
 * is under /admin/v2") and is carried by every brief.
 *
 * `deliveredRound` is recorded, not inferred: a note that was actually shown to
 * the model is marked, so a crash between preparing a brief and the model
 * answering cannot silently drop the note.
 */
export interface OperatorNote {
  id: string;
  text: string;
  pinned: boolean;
  at: string;
  deliveredRound: number | null;
}

/**
 * How a finding is reached, in the terms a pre-auth audit actually asks in.
 *
 * Derived, like every other label here: the model records the FACT (a tri-state
 * boolean) and this names it.
 */
export type AuthReach = "pre-auth" | "post-auth" | "unassessed";

export function authReach(vector: Pick<AttackVector, "preAuth"> | undefined): AuthReach {
  if (!vector || vector.preAuth === undefined) return "unassessed";
  return vector.preAuth ? "pre-auth" : "post-auth";
}

/** One-line label for a report or a status line. */
export function tierLabel(tier: VerificationTier): string {
  switch (tier) {
    case "reproduced":
      return "REPRODUCED (a command was run and its output IS the finding)";
    case "command-ran":
      return "COMMAND RAN (a command was run, but nobody declared it demonstrates this claim)";
    case "static":
      return "STATIC (anchored in code, not reproduced)";
    case "reasoning-only":
      return "REASONING ONLY (no artifact — an opinion, not a finding)";
  }
}

/**
 * The categories an audit hypothesis can belong to.
 *
 * The set is closed on purpose. The scheduler enforces a per-category share
 * cap (MAX_CATEGORY_RATIO), and a free-form category field would let the
 * agent evade that cap by inventing a new spelling for the same class
 * ("auth-bypass", "authBypass", "authentication-bypass" — three categories,
 * three times the budget). `other` exists for the genuine remainder and is
 * itself capped.
 */
export const HYPOTHESIS_CATEGORIES = [
  // authentication / authorization
  "auth-bypass",
  "idor",
  "privilege-escalation",
  "session-fixation",
  "csrf",
  // injection
  "sqli",
  "nosqli",
  "command-injection",
  "ssti",
  "xxe",
  "ldap-injection",
  "header-injection",
  // data flow / file
  "path-traversal",
  "arbitrary-file-read",
  "arbitrary-file-write",
  "file-upload",
  "ssrf",
  "open-redirect",
  // execution / parsing
  "deserialization",
  "rce",
  "memory-safety",
  "race-condition",
  // disclosure / config
  "info-disclosure",
  "hardcoded-secret",
  "weak-crypto",
  "misconfiguration",
  "dependency-risk",
  // remainder
  "other",
] as const;

export type HypothesisCategory = (typeof HYPOTHESIS_CATEGORIES)[number] | (string & {});

const CATEGORY_SET = new Set<string>(HYPOTHESIS_CATEGORIES);

export function isKnownCategory(category: string): boolean {
  return CATEGORY_SET.has(category);
}

/**
 * Raw evidence. "Raw" is load-bearing: an evidence entry must be quotable
 * verbatim so a human (or a verifier) can re-derive the verdict from the
 * entry alone. A summary is not evidence.
 */
export type EvidenceKind =
  /** A location in the tree: file + line. */
  | "file"
  /** A verbatim code excerpt. */
  | "code-slice"
  /** A request / response pair, or a reproduction command's output. */
  | "request"
  /** Output of a command that was actually run, plus the command. */
  | "command-output"
  /** An explicit reasoning step with no artifact (weakest; recorded so it is
   * visible as weak rather than hidden). */
  | "reasoning";

export const EVIDENCE_KINDS: readonly EvidenceKind[] = ["file", "code-slice", "request", "command-output", "reasoning"];

export interface EvidenceLocation {
  /** Path relative to the audited project root, forward slashes. */
  file: string;
  /** 1-based line number. */
  line: number;
}

export interface Evidence {
  kind: EvidenceKind;
  /** ISO timestamp the evidence was collected. */
  at: string;
  /** Present for `file` / `code-slice`; optional elsewhere when the evidence
   * happens to cite a location. */
  location?: EvidenceLocation;
  /** For `command-output`: the exact command that produced `detail`. */
  command?: string;
  /**
   * For `command-output`: does this output DEMONSTRATE the assertion, or is it a
   * supporting fact?
   *
   * The tool cannot tell the two apart by reading the command — `curl` against a
   * live target and `curl` quoted from documentation look identical — so it does
   * not guess. A `command-output` without this flag is still real evidence that a
   * command ran, and it lands in the `command-ran` tier. Only `reproduces: true`
   * reaches `reproduced`, which is the tier a report presents as re-runnable.
   *
   * Set it when the command's output IS the finding: the injected string came
   * back unescaped, the file appeared on disk, the process ran as root. Do NOT
   * set it for a command that merely located the code or confirmed a supporting
   * fact — `grep`, `sed -n`, `ls`, `find`, `cat`. Those belong to the `static`
   * case, and the honest tier for them is `command-ran`.
   */
  reproduces?: boolean;
  /** The verbatim excerpt, request, or command output. */
  detail: string;
}

/**
 * One node of the hypothesis tree.
 *
 * Field notes that are easy to get wrong:
 *
 * `depth` is derived, never supplied by the caller — `tree.ts` computes it
 * from the parent so the two can never disagree. It is persisted anyway
 * because the scheduler's depth penalty must be computable from a single
 * record without walking the parent chain.
 *
 * `spawnedFrom` records the CONFIRMED findings that produced this hypothesis
 * (vulnerability combination, stage 4). A node derived from a single parent
 * assertion is a plain child and leaves this empty; a node derived from the
 * interaction of several findings lists all of them, which is what makes a
 * vulnerability CHAIN distinguishable from a coincidence.
 *
 * `roundIntroduced` is the loop iteration that created the node, so a
 * hypothesis that has sat unexamined for many rounds is visible as such.
 *
 * `score` is a cache of the scheduler's computation (stage 2). It is stored
 * so the UI and the round summary can show the ranking that was actually
 * used, rather than a recomputation that might differ.
 */
export interface Hypothesis {
  /** Stable id, `H-0001`-style. Assigned by the store, never by the caller. */
  id: string;
  /**
   * What kind of node this is.
   *
   *   hypothesis — a falsifiable assertion. The default, and the only kind that
   *                may be scheduled for verification.
   *   scope      — a BOUNDARY declaration ("the audit covers this project",
   *                "this subsystem"), NOT a claim. Exempt from the assertion
   *                gate, because "audit this project" cannot be confirmed or
   *                refuted and pretending otherwise would put an unfalsifiable
   *                node at the root of a falsification tree.
   *
   * A scope node is never a scheduling candidate: it has no truth value, so
   * asking a model to falsify it is a wasted round. The scheduler filters it
   * out (`planNextRound`).
   */
  nodeKind: NodeKind;
  /** null only for the root. */
  parentId: string | null;
  /**
   * For a `hypothesis`: the falsifiable assertion, stated as a claim about the
   * codebase. MUST read as an assertion ("X does not validate Y"), never as a
   * task ("check X"). Enforced by `validateDescription`.
   *
   * For a `scope`: what the boundary IS. Free prose — no truth value is
   * claimed for it, so the gate does not apply.
   */
  description: string;
  category: HypothesisCategory;
  status: HypothesisStatus;
  evidence: Evidence[];
  /** Derived from the parent chain. Root is 0. */
  depth: number;
  createdAt: string;
  lastTouchedAt: string;
  /** Scheduler priority cache. Defaults to 0 until stage 2 computes it. */
  score: number;
  /** Confirmed findings / hypotheses this node was derived from. */
  spawnedFrom: string[];
  /**
   * Hypotheses that must be CONFIRMED for this finding to be exploitable.
   *
   * This is the missing half of a real exploitation chain. `spawnedFrom` records
   * LINEAGE ("H-0007 came from H-0002 and H-0005") and deliberately not the
   * relationship; `hypothesis_combine` requires every source to be already
   * confirmed, because "A and B together give C" IS speculation if A or B is open.
   *
   * But that leaves the COMMONEST real shape inexpressible:
   *
   *   the sink is real        H-0039: ScheduledTask.a(byte[]) calls readObject()
   *                          with no ObjectInputFilter — CONFIRMED, the code says so
   *   and it needs a way in   H-0040: can anything write schedule_data pre-auth?
   *
   * H-0039 is not speculation. It is a confirmed sink that is EXPLOITABLE ONLY IF
   * H-0040 holds. Without a way to say that, the report presents a gated sink as
   * though it were a working RCE, and nothing ever prompts anyone to go and test
   * the gate.
   *
   * A REFUTED gate breaks the chain rather than leaving it open — see chainState.
   */
  requires?: string[];
  /** Loop round that introduced this node. 0 for the root. */
  roundIntroduced: number;
  /**
   * Scheduler bookkeeping: how many rounds have SELECTED this node.
   *
   * Stored on the node rather than derived from the selection log because the
   * log is kept as a bounded window (see `HISTORY_WINDOW`) and compaction
   * replaces the folded state — a counter that lived only in the window would
   * silently reset and the novelty term would re-award full marks to a node
   * that had already been examined five times.
   */
  timesSelected: number;
  /** The round that last selected this node; null when never selected. */
  lastSelectedRound: number | null;
  /**
   * Which kind of vulnerability combination produced this node (stage 4).
   *
   * `spawnedFrom` records the LINEAGE but not the RELATIONSHIP: "H-0007 came
   * from H-0002 and H-0005" does not say whether H-0007 is a dependency, a
   * shared defect, or a generalization. Recording the kind is what makes the
   * combination report readable, and what lets a later pass ask "have we
   * already looked for a shared root cause between these two?" without
   * re-deriving it from the descriptions.
   */
  combinationKind?: CombinationKind;
  /**
   * How the attacker would actually reach and trigger this assertion (stage 6).
   *
   * A field rather than a child node because a vector is a PROPERTY of the
   * hypothesis — "how would this be exploited" — not another proposition that
   * needs its own falsification. Modelling it as a child would bury a tree of
   * eight hypotheses under twenty-four vector nodes, and the scheduler would
   * spend its anti-tunnelling budget verifying payload sketches.
   */
  attackVector?: AttackVector;
  /** The recon segment that produced this node (stage 6). */
  segmentId?: string;
  /**
   * The round that last tried to REFUTE this finding, or null when it never was.
   *
   * A confirmation is a hypothesis too, and the only thing that catches a false
   * positive is an attempt to falsify it. Recording the attempt makes it
   * bounded (one challenge per confirmation, not a loop) and makes the report
   * able to say which findings have survived an attack and which have only ever
   * been agreed with. Cleared when the status leaves `confirmed`, so a re-opened
   * and re-confirmed finding is a NEW claim and gets attacked again.
   */
  /**
   * What the LAST verification run concluded.
   *
   * Persisted because it used to exist only in the tool's response text, which
   * meant the one place a mechanical fact can contradict the model was thrown
   * away at the end of the turn. `hypothesis_record` reads it to refuse a
   * `confirmed` verdict that the round's own probes refuted.
   */
  lastVerification?: VerificationRecord;
  /**
   * A deliberate override of a falsified probe.
   *
   * A probe CAN be wrong — a bad pattern, the wrong path, a file that moved — and
   * the model may know better than its own grep. That is allowed, but it is a
   * claim, so it is recorded with its reason and printed in the report rather
   * than being invisible.
   */
  /**
   * What the auditor tried in order to prove this finding WRONG.
   *
   * The probe machinery records this when it is used: each probe states what the
   * hypothesis predicts about one mechanical fact, and a prediction that does not
   * hold is a counterexample. But the machinery can be SKIPPED — an auditor can
   * read code, run a command, and record a verdict without ever stating what would
   * have refuted it. Measured on a real run: 7 confirmed findings, and
   * `verification_recorded: 0` — not one probe had run, so the check that refuses a
   * `confirmed` verdict over a falsified probe was inert.
   *
   * So a confirmation with no verification run must carry one of these instead.
   */
  refutation?: RefutationAttempt;
  falsificationOverride?: FalsificationOverride;
  challengedRound?: number | null;
  /**
   * Rounds spent PURSUING this finding for depth.
   *
   * 0 or absent means never pursued. `>= pursueRounds` means the pursuit is
   * closed — either the budget ran out or a round produced nothing, and a round
   * that produces nothing ends the pursuit there rather than spending the rest
   * of the budget on a dead lead.
   *
   * Cleared when the status leaves `confirmed`, so a re-confirmation is a new
   * claim and gets its own pursuit. Same rule as `challengedRound`.
   */
  pursueSpent?: number;
  /**
   * How bad it is if the assertion is true. Optional: an unrated finding is
   * "not yet judged", which is different from "low" — and a completion
   * contract that demanded severity would otherwise force a guess.
   */
  severity?: Severity;
  /**
   * Why the node is `blocked`, or why a verdict was reached without strong
   * evidence. Required for `blocked`; optional otherwise.
   */
  statusReason?: string;
}

// -----------------------------------------------------------------
// Node kind
// -----------------------------------------------------------------

/**
 * A node is either a falsifiable claim or a boundary declaration.
 *
 * The distinction exists because an audit starts from something you do NOT yet
 * understand: "the project rooted at cwd" is a scope, not a hypothesis, and
 * forcing the user to phrase it as a claim produces a root like "this project
 * contains a vulnerability", which no evidence can refute.
 */
export type NodeKind = "scope" | "hypothesis";

export const NODE_KINDS: readonly NodeKind[] = ["scope", "hypothesis"];

/**
 * Truncate on a word boundary where possible, so a cut assertion is still
 * readable.
 *
 * Lives here rather than in render.ts so recon.ts can use it: recon.ts is
 * imported BY the renderer, so importing the renderer back would close a module
 * cycle (render → recon → render).
 */
/** A caller MUST check ok — a false ok means nothing was written. */
export type Result<T> = { ok: true; value: T; warnings: string[] } | { ok: false; errors: string[] };

export function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const space = cut.lastIndexOf(" ");
  return (space > max * 0.6 ? cut.slice(0, space) : cut) + "…";
}

// -----------------------------------------------------------------
// Attack vector (stage 6)
// -----------------------------------------------------------------

/** One step of the path from the entrypoint to the sink. */
export interface AttackStep {
  /** Where this step is, when it is a code location. */
  location?: EvidenceLocation;
  /** What happens here. */
  detail: string;
}

/**
 * How an attacker reaches and triggers the hypothesis.
 *
 * Deliberately structured rather than prose: an entrypoint and a path are what
 * let the combination pass (stage 4) notice that two findings share a reachable
 * route, and what let a reviewer check the claim without re-reading the code.
 *
 * An EMPTY vector is legal and means "how to reach this is not yet known" —
 * which is a different statement from "it is unreachable", and the renderer
 * says so.
 */
export interface AttackVector {
  /** How the attacker gets in: a route, a queue, a CLI verb, a file drop. */
  entrypoint: string;
  /** The chain from the entrypoint to the sink, in order. */
  path: AttackStep[];
  /** The technique: "alg=none JWT forgery", "path traversal via ../", … */
  technique: string;
  /** A concrete payload or reproduction sketch, when one is known. */
  payload?: string;
  /**
   * What the attacker gets out of it, if it works.
   *
   * A separate field from `technique` on purpose: "alg=none JWT forgery" is how
   * you do it, "take over any account including the admin" is why it matters,
   * and a report that only says the first one leaves the reader to guess the
   * second. It is the auditor's JUDGEMENT, so it is recorded as a claim rather
   * than derived — an impact the tool inferred would be the tool inventing
   * severity.
   *
   * Optional because a hypothesis is generated before it is verified: the chain
   * is often known first and the consequence worked out later. The report marks
   * the gap rather than filling it.
   */
  impact?: string;
  /**
   * A COPY-PASTEABLE request a human can run by hand to see it themselves.
   *
   * Not the same as `payload`. A payload is what to inject; this is the whole
   * thing you paste — a curl line or a raw HTTP request:
   *
   *   GET /dsview/servlet/AxisServlet
   *   curl -sS 'https://TARGET/api/latest/gorgone/command' -d '{"command":"id"}'
   *
   * It is what turns a report from something you believe into something you can
   * check. `entrypoint` is prose ("any route selected by the api firewall") and
   * cannot be pasted; this can.
   */
  poc?: string;
  /**
   * What to LOOK FOR once the request has been sent.
   *
   * Without it the reader runs the request and cannot tell whether it worked —
   * which is how a manual PoC becomes a manual shrug. "200 with the AxisServlet
   * banner", "a 5-second delay", "the file contents in the body".
   */
  pocExpected?: string;
  /** What must hold for the vector to work. */
  preconditions?: string[];
  /**
   * Can this be reached WITHOUT authentication?
   *
   *   true      PRE-AUTH — an unauthenticated request reaches the sink
   *   false     POST-AUTH — a session is required first
   *   undefined NOT ASSESSED — nobody determined it
   *
   * Tri-state on purpose, and this is the single property that decides whether a
   * finding is in scope for a pre-auth audit at all. "Nobody asked" and "the
   * answer is no" are different claims, and a report that collapses them either
   * inflates the finding or silently drops it.
   *
   * It also decides how a finding is USED: a post-auth RCE is a real finding and
   * not the one the operator asked for — the way to make it pre-auth is to chain
   * an authentication bypass in front of it, which is what `requires` is for.
   */
  preAuth?: boolean;
}

/** The fields a caller supplies to create a node. `id`, `depth`, timestamps
 * and `score` are derived by the store. */
export interface HypothesisInput {
  description: string;
  category: HypothesisCategory;
  /** Omit to attach to the root. */
  parentId?: string | null;
  /** Defaults to `hypothesis`. `scope` skips the assertion gate. */
  nodeKind?: NodeKind;
  status?: HypothesisStatus;
  evidence?: Evidence[];
  spawnedFrom?: string[];
  /** Gate ids. See Hypothesis.requires. */
  requires?: string[];
  roundIntroduced?: number;
  attackVector?: AttackVector;
  /** The recon segment this node came from (stage 6). */
  segmentId?: string;
  severity?: Severity;
  statusReason?: string;
}

// -----------------------------------------------------------------
// Recon segments (stage 6)
// -----------------------------------------------------------------

/**
 * One chunk of the agent's recon notes.
 *
 * The audit starts from a project nobody has read yet, so the first thing the
 * model produces is prose: what the project is, where its entrypoints are, what
 * the trust boundaries look like. That prose is then chunked MECHANICALLY into
 * segments, and each segment becomes the input for one hypothesis-generation
 * round.
 *
 * Chunking the model's own notes rather than the raw source is deliberate. A
 * file or a line range can split a function in half, so a hypothesis derived
 * from it is guessing; a paragraph boundary is where the MODEL stopped a
 * thought, so each segment is semantically whole. It also bounds the phase: a
 * 500-file repository is 500 rounds if you chunk by file, and three to eight if
 * you chunk the notes.
 */
export interface ReconSegment {
  /** `S-<index>-<hash8>` — position AND content, so an edited note re-opens
   * only the segments that actually changed. */
  id: string;
  /** 0-based position in the note. */
  index: number;
  /** How many blank-line-separated paragraphs this segment covers. */
  paragraphs: number;
  /** The segment's text, verbatim. */
  text: string;
  /** Content hash of `text` (first 8 hex chars). */
  hash: string;
}

/**
 * Coverage of the recon note.
 *
 * This is the mechanical answer to "when is hypothesis generation finished".
 * Without a denominator the generation phase could not terminate — the model
 * can always invent another hypothesis — and "the well is dry" would be
 * indistinguishable from "the model stopped trying".
 */
export interface SegmentCoverage {
  /** Total segments in the current note. */
  total: number;
  /** Segments that produced at least one hypothesis or were explicitly closed. */
  covered: number;
  /** Segment ids still waiting for a generation round. */
  open: string[];
}

/** Why a segment is considered done. */
export type SegmentOutcome =
  /** At least one hypothesis was added from it. */
  | "produced"
  /** Examined and deliberately closed with nothing (a recorded result). */
  | "nothing-found";

export interface SegmentRecord {
  segmentId: string;
  at: string;
  outcome: SegmentOutcome;
  /** Hypothesis ids produced from this segment. */
  hypothesisIds: string[];
  /** Required for `nothing-found`, so "empty" is a stated result. */
  note?: string;
}

// -----------------------------------------------------------------
// Consolidation (stage 4)
// -----------------------------------------------------------------

/**
 * The three ways confirmed findings combine into a new hypothesis.
 *
 *   chain              — A depends on B (you need B to reach A)
 *   shared-root-cause  — A and B are both consequences of one missing check
 *   lateral-extension  — A bypasses X; the same technique may bypass Y
 *
 * `chain` and `shared-root-cause` are relations BETWEEN findings (they need a
 * pair); `lateral-extension` generalizes ONE finding, which is why a
 * consolidation pass also considers singletons.
 */
export type CombinationKind = "chain" | "shared-root-cause" | "lateral-extension";

export const COMBINATION_KINDS: readonly CombinationKind[] = ["chain", "shared-root-cause", "lateral-extension"];

/**
 * Short tag for a combination kind, kept tiny so it can ride on a node line or
 * a decision line. Lives here rather than in render.ts so the scheduler can use
 * it without importing the renderer (which imports the scheduler).
 */
export function combinationTag(kind: CombinationKind): string {
  switch (kind) {
    case "chain":
      return "chain";
    case "shared-root-cause":
      return "shared";
    case "lateral-extension":
      return "ext";
  }
}

/** Why a consolidation pass ran. */
export type ConsolidationTrigger =
  /** `CONSOLIDATION.INTERVAL` rounds have passed since the last pass. */
  | "interval"
  /** A new finding was confirmed since the last pass. */
  | "new-finding"
  /** The user or the agent asked for one explicitly. */
  | "manual";

/**
 * One pair of confirmed findings, with the MECHANICAL signals that made it
 * worth considering.
 *
 * The extension does not decide whether two findings are related — that is a
 * semantic judgement, and deriving it mechanically would be guessing. What it
 * does is compute the structural facts (shared files, line proximity, tree
 * relationship, categories) so the judgement is grounded rather than made from
 * two prose summaries, and so the N² pair space is bounded and ordered.
 */
export interface ConsolidationPair {
  aId: string;
  bId: string;
  /** Stable key for "this pair has been examined". */
  key: string;
  score: number;
  /** Human-readable reasons, strongest first. */
  signals: string[];
  sharedFiles: string[];
  /** Closest distance in lines between the two findings' evidence in a shared
   * file, or null when they share no file. */
  minLineDistance: number | null;
  treeRelation: "ancestor" | "sibling" | "unrelated";
}

/** A confirmed finding that has not yet been generalized. */
export interface ConsolidationSingle {
  id: string;
  score: number;
  signals: string[];
}

/**
 * The audit trail of one consolidation pass.
 *
 * Written even when the pass produced nothing (`skipped` says why), because
 * "we looked and found no combination" is a result, and a pass that left no
 * record is indistinguishable from a pass that never ran.
 */
export interface ConsolidationRecord {
  round: number;
  at: string;
  trigger: ConsolidationTrigger;
  /** The confirmed set at the time, so the pass is reproducible. */
  confirmedIds: string[];
  /** Pair keys handed to the model; these are marked examined. */
  pairKeys: string[];
  /** Singleton ids handed to the model. */
  singleIds: string[];
  /** Non-null when the pass had nothing to hand over. */
  skipped: string | null;
}

/** The plan for one consolidation pass, before it is recorded. */
export interface ConsolidationPlan {
  round: number;
  trigger: ConsolidationTrigger;
  /** False when the trigger has not fired; `reason` says which condition is unmet. */
  due: boolean;
  reason: string;
  /**
   * The working set: bounded and ordered, the findings the pass will actually
   * pair up. NOT the whole confirmed set — see `confirmedIds`.
   */
  confirmed: Hypothesis[];
  /**
   * EVERY confirmed id, unbounded.
   *
   * This is what gets recorded, and it is deliberately different from
   * `confirmed`: the cap on `confirmed` is about how many the pass will EXAMINE,
   * not how many exist. Recording the capped list made the next pass compare
   * `confirmedAll.length` against a number that could never grow, so once an
   * audit passed the cap the "new finding since the last pass" trigger was true
   * on every single round — consolidation pre-empted verification forever, and
   * the loop then reported a plateau while unexamined hypotheses remained.
   */
  confirmedIds: string[];
  pairs: ConsolidationPair[];
  singles: ConsolidationSingle[];
  /** Non-null when a pass has nothing to examine. */
  skipped: string | null;
}

// -----------------------------------------------------------------
// The audit loop (stage 5)
// -----------------------------------------------------------------

/** `/goal` runs until a contract is met; `/loop` runs until stopped. */
export type AuditLoopKind = "goal" | "loop" | "sec";

/**
 * The COMMAND a loop kind is registered under.
 *
 * Not the same thing as the kind, and the difference is load-bearing: the kind is what
 * the log stores, and `normalizeLoopState` DROPS an unknown one — so renaming a kind
 * would make every existing run unreadable. The command name is a UI surface and can
 * change freely.
 *
 * Mapping it in one place is what stops the two from being assumed equal at twenty call
 * sites, which is how `/${kind}` produced `/sec status` in a dozen hint strings — now `/loopsec status`.
 */
export function loopCommandName(kind: AuditLoopKind): string {
  return kind === "sec" ? "loopsec" : kind;
}

export type AuditLoopStatus =
  | "running"
  | "paused"
  /** Stopped by the user, the plateau, or the round cap. */
  | "stopped"
  /** `/goal` only: the completion contract is satisfied. */
  | "complete";

/**
 * What `/goal` is waiting for.
 *
 * Every clause is MECHANICAL and evaluated against the folded tree, because a
 * completion condition the extension cannot check is a completion condition the
 * model grades itself on — which is the failure this whole project exists to
 * avoid.
 */
export interface CompletionContract {
  /** At least this many confirmed findings. */
  minConfirmed: number;
  /** At least one confirmed finding at this severity or worse. */
  minSeverity?: Severity;
  /** Restrict the count to these classes (empty/absent = any). */
  categories?: string[];
  /** Also require that no combination pass is pending. */
  requireConsolidated: boolean;
  /**
   * Only findings whose evidence includes a real artifact count.
   *
   * Default TRUE, because a verdict resting entirely on `reasoning` entries is
   * the model's opinion: letting it satisfy a completion contract is how an
   * audit reports a "confirmed high-severity vulnerability" that nobody can
   * open a file and check.
   */
  requireArtifact: boolean;
  /**
   * Only findings REPRODUCED by a command probe count.
   *
   * Default FALSE, because it needs `allowCommandProbes` — a project that has
   * not granted that consent would have an uncompletable goal. Turn it on when
   * you want proof rather than a strong static case.
   */
  requireReproduced: boolean;
  /**
   * Only findings that have SURVIVED an attempt to refute them count.
   *
   * Default TRUE, and this is the clause that fixes the false-positive problem.
   * The contract is checked BEFORE the round kind is chosen, so without it a
   * confirmation satisfies the contract immediately, the goal completes, and
   * the challenge round never runs — meaning the model's first confident
   * judgement ends the audit, right or wrong.
   */
  requireChallenged: boolean;
  /**
   * Only findings whose attack vector records an IMPACT count.
   *
   * Default FALSE, because it constrains the writing rather than the evidence:
   * a finding can be true and well-evidenced while nobody has worked out what
   * an attacker would get from it. Turn it on for a report whose findings must
   * each answer "and then what?" before the audit may stop.
   *
   * The report renders the section either way and says "not assessed" when it is
   * missing, so this clause decides whether that gap may END an audit, not
   * whether it is visible.
   */
  requireImpact: boolean;
  /**
   * Only findings whose exploitation chain is COMPLETE count.
   *
   * Default FALSE. A confirmed sink whose entry is still unverified is a real
   * finding, and refusing to let it count would make most goals uncompletable on
   * a large target — you usually find the sink before you find the way in.
   *
   * Turn it on when the deliverable must be USABLE rather than merely real: a
   * gated deserialization sink and a working pre-auth RCE look identical in a
   * list of confirmed findings, and only one of them can be used.
   */
  requireExploitable: boolean;
  /**
   * Only findings reachable WITHOUT authentication count.
   *
   * Default FALSE, because a post-auth finding is still a finding and refusing
   * to let it count would hide real work.
   *
   * Turn it on for the goal this whole thing exists for: "find a pre-auth RCE".
   * An UNASSESSED finding does NOT satisfy it — "nobody determined the
   * authentication requirement" is not "pre-auth".
   */
  requirePreAuth: boolean;
}

// Re-exported so loop.ts can name the language without importing the report
// module (which imports this one).
export type { ReportLanguage } from "./reportText.js";

/**
 * What a DEEP run was opened from.
 *
 * The parent's fields are COPIED rather than referenced: the parent run keeps running, its log can be
 * archived or wiped, and a deep report that can no longer name what it came from is a report nobody can
 * relate to its own attack surface. `parentDir` is what ties the two together after the fact.
 */
export interface SecLoopDeep {
  /** The finding's id IN THE PARENT RUN, e.g. F-0008. */
  findingId: string;
  /** Its title, verbatim. */
  title: string;
  severity?: Severity;
  category: string;
  /** The parent's state dir relative to `.pi-loopsec` — `.` for the main run. */
  parentDir: string;
}

export interface AuditLoopState {
  kind: AuditLoopKind;
  objective: string;
  /** null for `/loop` — it has no finish line. */
  contract: CompletionContract | null;
  status: AuditLoopStatus;
  startedAt: string;
  updatedAt: string;
  /** Highest round whose brief has been sent. */
  round: number;
  /**
   * The round whose turn is in flight, or null.
   *
   * This is the anti-stacking fence: the loop only sends a brief when nothing
   * is awaiting completion, so a slow or failed turn cannot pile up rounds.
   */
  awaitingRound: number | null;
  /** 0 = unbounded. */
  maxRounds: number;
  /**
   * The classes this run is FOR, if the operator narrowed it.

   * A BIAS, never a filter. Generation is told to spend the round here, and the
   * scheduler prefers these classes — but nothing is refused, because a pre-auth
   * RCE is routinely reached by chaining a finding from somewhere else, and a hard
   * filter would make exactly that chain unfindable.
   */
  focus?: string[];
  /**
   * Present only on a DEEP run: the finding this run was opened to work on.
   *
   * A deep run is not a sweep. Its work list is a set of SUB-QUESTIONS (what has to be true for this
   * finding to be exploitable, and which of those is still unknown) rather than an attack surface, its
   * recon phase is pre-seeded instead of being spent mapping the project, and its report says which
   * finding it came from. Everything else — the evidence bar, the depth playbook, the verification,
   * the plateau — is the same machinery, which is why this is a field and not a mode.
   */
  deep?: SecLoopDeep;
  /**
   * Consecutive combination passes that handed over candidates and combined nothing.
   *
   * Dampens the pass's own schedule. A pass whose trigger fires every couple of
   * rounds is a pass that eats the rounds the depth work needs, and one that got
   * nothing back has earned a longer wait rather than the same wait.
   */
  consolidationStall?: number;
  /**
   * Pause when `round` reaches this. `/loop pause 20` sets it to round + 20.
   *
   * A `/loop` has no finish line of its own, so this is the only way to say "twenty
   * more rounds and then stop" — and `maxRounds` cannot express it, because that is
   * an absolute cap counted from the start. Absolute, not relative, so that a reload
   * or a resume cannot silently reset the count.
   *
   * CLEARED when it fires, and cleared by `resumeLoop`: a spent budget that survived
   * would pause the loop again on the very next tick.
   */
  pauseAfterRound?: number | null;
  /**
   * How many COVERAGE rounds this run has spent. Bounded by COVERAGE.MAX_ROUNDS.
   *
   * A round kind that can always justify itself is the failure mode this codebase
   * has hit three times, so this one is counted rather than trusted.
   */
  coverageRounds?: number;
  /** Consecutive rounds that produced no new verdict before the loop stops. */
  plateauWindow: number;
  stallRounds: number;
  /**
   * Paused time already banked, in milliseconds.
   *
   * Folded in when the loop RESUMES rather than when it pauses, because a
   * pause that is never resumed (stopped while paused) has no resume to fold
   * into — `pausedAt` plus `endedAt` covers that case.
   */
  pausedMs: number;
  /** When the CURRENT pause began, or null when not paused. */
  pausedAt: string | null;
  /**
   * When the loop reached a terminal status, or null while it can still move.
   *
   * Recorded explicitly rather than read off `updatedAt`: the duration of a
   * finished audit must not drift if something later touches the loop record.
   */
  endedAt: string | null;
  /**
   * The operator closed the widget.
   *
   * A terminal loop's widget otherwise sits on screen forever: nothing will ever
   * update it again, and `setWidget(name, undefined)` is undone by the next
   * refresh unless the state itself says to stay hidden.
   *
   * A FLAG rather than clearing the loop record, because dismissing a panel and
   * discarding an audit are different actions. The tree, the round history, the
   * contract, the clock and the report all survive; only the widget goes.
   * Starting or resuming clears it — you are working again, so show the work.
   */
  widgetHidden?: boolean;
  stopReason?: string;
  pausedReason?: string;
}

// -----------------------------------------------------------------
// How long has this been running?
// -----------------------------------------------------------------

/**
 * A human-readable span, at the precision a person actually wants.
 *
 * Deliberately coarse: "2h 14m" is useful at a glance, "2h 14m 07s" is noise
 * that changes every time the status is reprinted and makes the line hard to
 * read. Seconds appear only when the whole span is under a minute, which is the
 * one case where they are the only interesting part.
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) return "unknown";
  const total = Math.max(0, Math.floor(ms / 1000));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  return `${seconds}s`;
}

/** Parse an ISO timestamp to epoch ms, or null when it is missing or invalid. */
function at(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export interface LoopTiming {
  /** Milliseconds since the loop started, including paused time. */
  wallMs: number;
  /** Milliseconds the loop was actually able to work. */
  activeMs: number;
  /** Milliseconds spent paused — banked plus the current pause, if any. */
  pausedMs: number;
  /** True when the span ends at `endedAt` rather than at the reference instant. */
  ended: boolean;
  /** Rounds per hour of ACTIVE time, or null when too little has happened to say. */
  roundsPerHour: number | null;
}

/**
 * The loop's clocks.
 *
 * Paused time is separated from wall time because the two answer different
 * questions, and reporting only the wall clock makes a loop that sat paused
 * overnight claim a night of work. `activeMs` is the honest "how long has this
 * been running".
 *
 * Every span is clamped at zero: a system clock that jumps backwards must show
 * "0s", never a negative duration.
 */
export function loopTiming(loop: AuditLoopState, nowMs = Date.now()): LoopTiming | null {
  const started = at(loop.startedAt);
  if (started === null) return null;
  const endedAt = at(loop.endedAt);
  const reference = endedAt ?? nowMs;
  const wallMs = Math.max(0, reference - started);
  const pausedAt = at(loop.pausedAt);
  // Coerced, not trusted: `Math.max(0, undefined)` is NaN, and a NaN here would
  // poison every duration derived from it. A loop record written before this
  // field existed has no banked pause time, which is exactly what 0 says.
  const banked = Number.isFinite(loop.pausedMs) ? Math.max(0, loop.pausedMs) : 0;
  const pausedMs = banked + (pausedAt !== null ? Math.max(0, reference - pausedAt) : 0);
  const activeMs = Math.max(0, wallMs - pausedMs);
  // Only claim a rate once there is enough active time to divide by: a loop two
  // seconds in has not established that it runs at 1800 rounds/hour.
  const roundsPerHour = activeMs >= 60_000 && loop.round > 0 ? (loop.round / activeMs) * 3_600_000 : null;
  return { wallMs, activeMs, pausedMs, ended: endedAt !== null, roundsPerHour };
}

/**
 * One line describing the clocks, for a status block.
 *
 * Paused time is only mentioned when there IS some — a "0m paused" clause on
 * every line is a clause the reader learns to skip.
 */
export function describeTiming(timing: LoopTiming | null, round: number): string {
  if (!timing) return "elapsed: unknown (the start timestamp could not be read)";
  const parts: string[] = [`elapsed ${formatDuration(timing.activeMs)}`];
  if (timing.pausedMs > 0) {
    parts.push(`(${formatDuration(timing.wallMs)} wall, ${formatDuration(timing.pausedMs)} paused)`);
  }
  if (timing.ended) parts.push("finished");
  if (timing.roundsPerHour !== null) parts.push(`${timing.roundsPerHour.toFixed(1)} rounds/h`);
  else if (round > 0) parts.push(`${round} round(s)`);
  return parts.join(" · ");
}

/**
 * One round of the loop.
 *
 * The `*AtStart` fields are the baseline that lets the NEXT tick judge the round
 * without a second event: comparing the node's status and the confirmed count
 * now against what they were when the round began is enough to say whether the
 * round produced anything. Derived beats recorded here — there is no window in
 * which the two can disagree.
 */
/**
 * What a round does.
 *
 *   recon       — read the unknown project and submit recon notes
 *   generate    — turn ONE recon segment into falsifiable hypotheses + vectors
 *   verify      — falsify one hypothesis
 *   consolidate — look for combinations among the confirmed findings
 *   challenge   — try to REFUTE a finding this audit already confirmed
 *
 * `challenge` exists because a confirmation is itself a hypothesis, and the
 * only thing that catches a false positive is an attempt to falsify it. Without
 * this round the model's first confident judgement is permanent, and a single
 * false positive ends a `/goal` (it satisfies the contract) or sits in a
 * `/loop`'s report as a finding nobody ever attacked.
 *
 * `recon` and `generate` exist because an audit of an unfamiliar project cannot
 * start with a hypothesis: there is nothing to hypothesise ABOUT until the
 * project has been read. Stages 1–5 assumed a tree already existed; these two
 * rounds are how it comes to exist.
 */
export type RoundKind =
  | "recon"
  | "generate"
  | "verify"
  | "consolidate"
  | "challenge"
  | "pursue"
  | "coverage"
  | "dig"
  /** `/loopSEC`: enumerate the attack surface into a work list. */
  | "surface"
  /** `/loopSEC`: work ONE item on that list, all the way down. */
  | "analyze";

export const ROUND_KINDS: readonly RoundKind[] = [
  "recon",
  "generate",
  "verify",
  "consolidate",
  "challenge",
  "pursue",
  "coverage",
  "dig",
  "surface",
  "analyze",
];

export interface RoundRecord {
  round: number;
  at: string;
  /** A verify round examines one node; a consolidate round runs a pass. */
  kind: RoundKind;
  /** For a `generate` round: which segment was handed over. */
  segmentId?: string | null;
  nodeId: string | null;
  nodeStatusAtStart: HypothesisStatus | null;
  nodeEvidenceAtStart: number;
  confirmedAtStart: number;
  /**
   * How many nodes the tree held when the round was prepared.
   *
   * The baseline for a PURSUE round, whose only output is new hypotheses: a
   * pursue round that added none produced nothing, and the pursuit of that
   * finding closes immediately rather than spending the rest of its budget.
   */
  nodeCountAtStart: number;
  /**
   * How many `/loopSEC` findings the run held when the round was prepared.
   *
   * PRESENT ONLY ON A SEC ROUND, and that is load-bearing: a sec recon round and a
   * hypothesis recon round share the `recon` kind and mean different things, so the
   * baseline is what tells `evaluateRound` which one it is looking at.
   */
  findingCountAtStart?: number;
  /** For a `/loopSEC` analyze round: which surface item was handed over. */
  surfaceId?: string | null;
  /**
   * For a `/loopSEC` pursue round: which FINDING's blockers were handed over.
   *
   * Separate from `surfaceId` because they are different axes: an analyze round works a PLACE
   * (which may be cleared with no finding), a pursue round works a FINDING's precondition. A
   * pursue round has no surface item — the item was already examined when the finding landed.
   */
  findingId?: string | null;
  /**
   * The finding's blocker list when this round was prepared, joined.
   *
   * THE BASELINE THAT MAKES A PURSUIT ROUND COUNT AS PROGRESS. A pursuit round has no status to
   * flip (unlike analyze, where `examined` moves): its whole output is a better understanding of
   * the gate — a refined blocker, a new enabling finding, or the conclusion that the gate cannot
   * be opened. Comparing this string is how `evaluateRound` tells that from a round that did
   * nothing, and it is bounded because a finding's pursuit budget is.
   */
  pursuitBlockersAtStart?: string;
  /**
   * Was the assigned item in the `digging` state when this round was prepared?
   *
   * THE SIGNAL THAT MAKES A DEPTH ROUND COUNT AS PROGRESS. Without it, continuing an item
   * you deliberately asked to go deeper on looks identical to a round that did nothing —
   * `examined` does not move (the item was already being examined) and no finding was
   * recorded — so it burns a plateau slot. That is the wrong incentive: it pays the model
   * to CLOSE an item hastily rather than to finish tracing it.
   *
   * Bounded by construction: `digging` can only be set `digBudget` times, and this round's
   * prepare already counted one, so the number of rounds this can mark is small.
   */
  surfaceWasDigging?: boolean;
  /** How many items the surface list held when the round was prepared. */
  surfaceCountAtStart?: number;
  /**
   * How many of them had been examined when the round was prepared.
   *
   * THE BASELINE THAT MAKES ANALYSIS COUNT AS PROGRESS. Without it a round that read
   * five files, traced a full data flow and correctly concluded "guarded" is
   * indistinguishable from a round that did nothing — so it burns a plateau slot, and
   * eight careful rounds in a row stop the run while it is working.
   */
  surfaceExaminedAtStart?: number;
  /** The human-readable round summary, persisted so the ledger can be rebuilt. */
  summary: string[];
}

// -----------------------------------------------------------------
// Scheduling (stage 2)
// -----------------------------------------------------------------

/**
 * The score breakdown for one candidate. Every term is stored, not just the
 * total, because the scheduler's whole job is to be AUDITABLE: "why was this
 * node picked" must be answerable from the record alone, without replaying
 * the formula against a snapshot that has since changed.
 */
export interface ScoreBreakdown {
  /** Bonus for never-examined nodes; decays with `timesSelected`. */
  novelty: number;
  /** Bonus for evidence already collected — a node close to a verdict is
   * cheap value to finish. */
  evidence: number;
  /** Bonus for a category that is under-represented in the recent window. */
  categoryDiversity: number;
  /** Penalty proportional to depth: a deep node is narrower and costs more
   * context to examine. */
  depthPenalty: number;
  /** Penalty for having been selected recently. */
  recencyPenalty: number;
  /** Bonus for being the GATE of a confirmed finding — see SCORE_WEIGHTS.gateBoost. */
  gateBoost: number;
  /** Bonus for being in a class the operator asked for — see SCORE_WEIGHTS.focusBoost. */
  focusBoost: number;
  /** Penalty for a node that is currently `blocked` (it was blocked for a
   * reason, so re-picking it immediately is usually waste). */
  blockedPenalty: number;
  /** Bonus for a node left mid-examination (`testing` with no verdict) —
   * finish what was started before opening a new front. */
  testingBoost: number;
  total: number;
}

/** A hard constraint that disqualified one candidate this round. */
export type ScheduleConstraint =
  | "max-same-node-rounds"
  | "max-consecutive-depth"
  | "max-category-ratio";

export interface ScheduleVeto {
  nodeId: string;
  constraint: ScheduleConstraint;
  detail: string;
}

/**
 * One recorded scheduling decision — the round's audit trail.
 *
 * Persisted so the round summary can show the ranking that was ACTUALLY used
 * rather than a recomputation, and so a human reviewing the loop can see
 * whether the anti-rabbit-hole rules fired.
 */
export interface SelectionRecord {
  round: number;
  nodeId: string;
  at: string;
  score: number;
  breakdown: ScoreBreakdown;
  /** Human-readable rationale, in the order the scheduler derived it. */
  reasons: string[];
  /** Candidates disqualified by a hard constraint. */
  vetoes: ScheduleVeto[];
  /**
   * Constraints that had to be relaxed because NO candidate satisfied them.
   *
   * This field exists because the alternative — refusing to schedule — would
   * deadlock the loop. Relaxing is sometimes correct (if every open hypothesis
   * is one category, the category cap is unsatisfiable), but it must never be
   * silent: an empty array means the rules held.
   */
  relaxations: string[];
  /** How many open hypotheses were considered. */
  candidates: number;
  /**
   * Categories whose share of the OPEN population already exceeds the cap.
   * A diagnostic about the TREE, not about this pick: the scheduler cannot
   * spread attention when one category is nearly all the remaining work.
   */
  populationSkew: string[];
}

/** A scheduling decision before it is persisted. */
export interface ScheduleDecision {
  round: number;
  /** null when there was nothing schedulable (no tree, or no open nodes). */
  selected: Hypothesis | null;
  breakdown: ScoreBreakdown | null;
  reasons: string[];
  vetoes: ScheduleVeto[];
  relaxations: string[];
  candidates: number;
  populationSkew: string[];
  /** The full ranking that was considered, highest first (bounded). */
  ranked: Array<{ nodeId: string; score: number; vetoedBy: ScheduleConstraint | null }>;
}

// -----------------------------------------------------------------
// Tree snapshot
// -----------------------------------------------------------------

/**
 * The folded state. Produced by `store.load()`, never persisted directly
 * (except inside an append-only compaction snapshot).
 */
/**
 * A finding recorded by a `/loopSEC` run.
 *
 * -----------------------------------------------------------------------
 * Why this is NOT a Hypothesis
 * -----------------------------------------------------------------------
 *
 * A hypothesis is an assertion that can be proven WRONG, and every piece of
 * verification machinery hangs off that: the store refuses a description with no
 * truth value, a verdict requires evidence, the tier says how strong that evidence
 * is, the challenge round attacks the finding, and a refuted one is removed from
 * the report.
 *
 * `/loopSEC` trades all of it for speed. The operator gives an objective, the loop
 * digs, and whatever it finds is recorded here as the auditor's own claim. There
 * is no gate on the title, no verdict, no verification tier, no falsification
 * attempt, no challenge round — none of those can exist without an assertion to
 * attack, and pretending otherwise would be a report claiming discipline it does
 * not have.
 *
 * ONE THING IS STILL REQUIRED: an artifact. A finding with neither a `location`
 * nor an `evidence` excerpt is REFUSED. That bar is cheap — the model is reading
 * the code, so it has a `file:line` — and it is the whole difference between a
 * triage report and a list of things a model said. The report states loudly what
 * else is missing.
 */
export interface SecFinding {
  id: string;
  /** ISO timestamp. */
  at: string;
  /** The round that recorded it. */
  round: number;
  /** What it is. Free-form: this mode has no assertion gate. */
  title: string;
  category: string;
  /** The auditor's judgement, or absent for "not yet judged". */
  severity?: Severity;
  /**
   * Can an UNAUTHENTICATED request reach it?
   *
   * Tri-state, and the absent case is NOT folded into either answer: "nobody
   * determined it" and "the answer is no" are different claims, and collapsing
   * them either inflates the finding or silently drops it.
   */
  preAuth?: boolean;
  /** Where it is. One of this and `evidence` is required. */
  location?: EvidenceLocation;
  /** The verbatim artifact. One of this and `location` is required. */
  evidence?: string;
  /** How it is reached and why it matters — the auditor's reasoning. */
  reasoning?: string;
  /** A copy-pasteable request, when there is one. */
  poc?: string;
  /**
   * The call chain, one step per hop.
   *
   * Optional, and a finding without one still renders — but a finding WITH one is the
   * difference between a reader reconstructing the path out of prose and reading it off
   * a numbered list.
   */
  path?: SecFindingStep[];
  /** The surface item this came out of, when the run enumerated one. */
  surfaceId?: string;
  /**
   * The findings this one COMBINES. Two or more ids.
   *
   * A CHAIN IS A FINDING. "An arbitrary file write plus a config that is exec'd reaches
   * root code execution" is the most important thing a run can report, and NEITHER PART
   * says it alone — the report would otherwise list two separate medium findings and
   * never say the word.
   *
   * This is why it belongs in this mode even though the assertion machinery does not:
   * combination is ORTHOGONAL to the assertion gate. The gate is what `/loopsec` drops;
   * chaining was never about assertions, and dropping it along with them was a design
   * mistake rather than a trade.
   *
   * A finding with `chainOf` needs no artifact OF ITS OWN — its artifact is its parts,
   * and each of those already carries one. That is the same bar the hypothesis mode's
   * `hypothesis_combine` sets by refusing a `spawnedFrom` that names anything
   * unconfirmed.
   */
  chainOf?: string[];
  /**
   * The result of ACTUALLY RUNNING something against the claim, when it was run.
   *
   * This is the one field that makes a finding's tier knowable. Without it every line of
   * the report is a static argument, and a reader cannot tell a sink they read from a
   * request that came back 200. See `SecVerification`.
   */
  verification?: SecVerification;
  /**
   * What must hold for this finding to be exploitable AS RECORDED — the gates that are not open yet.
   *
   * THIS FIELD IS WHAT MAKES A NEAR MISS WORKABLE. A real RCE that needs an authenticated session,
   * or needs one more field to be attacker-controlled, is the most valuable thing a run can hold:
   * closing the gate CONVERTS it into the objective. Without this recorded, the loop marks its
   * surface item examined and moves to the next item — the finding is filed and abandoned exactly
   * when it deserved the next two rounds. (Measured: a post-auth RCE on a pre-auth objective was
   * recorded, its item closed, and the run went on enumerating.)
   *
   * Each entry is a STATE OF THE WORLD, not a task: "needs a valid admin session", "needs base_url
   * to carry a path prefix", "needs the attacker to control X-Forwarded-Host". A gated finding with
   * a non-empty list is a PURSUIT candidate — see `nextPursuit` — and the pursuit rounds are spent
   * attacking these, not the work list.
   */
  blockers?: string[];
  /**
   * How many PURSUIT rounds this finding's blockers have cost.
   *
   * Bounded like every other depth budget here: without it one near miss sits on the run forever,
   * which is the failure the budget exists to prevent. Incremented by the loop on prepare, so a
   * crash or a stalled turn cannot hand out unlimited rounds on one finding.
   */
  pursuitSpent?: number;
  /**
   * Why the pursuit ENDED — set when the gate was opened, or when the attempts ran out.
   *
   * A closed pursuit is not scheduled again, and the reason is what tells a reader whether the
   * finding became reachable ("F-0007 provides the auth bypass") or stayed a near miss ("tried
   * a/b/c, none reachable pre-auth"). Without it, "we stopped" and "we never tried" look the
   * same in the report.
   */
  pursuitClosed?: string;
  /**
   * The model's own judgement that there is MORE HERE — a general "keep going on this".
   *
   * A gate is one reason to deepen a finding, but it is not the only one: a primitive that was proven
   * but never exercised, a root cause that probably holds in five more handlers, a piece that only
   * becomes dangerous when combined with another finding. The plugin cannot tell those from prose, so
   * it ASKS: set `deepen` when a round produced something worth turning over, and the loop spends its
   * next rounds on this finding instead of the next item on the work list.
   *
   * Deliberately separate from `blockers`: blockers say WHY it does not work yet, `deepen` says THERE
   * IS MORE TO FIND. A finding can have both, either, or neither.
   */
  deepen?: boolean;
}

/**
 * What running the claim actually produced.
 *
 * RECORDED, not inferred: the exact command, its exit code and its output, plus the
 * expectation the author stated BEFORE running it. `confirmed` is the comparison of the
 * two, not the author's reading of the output — a run that exits 0 when the author
 * predicted a refusal is a DISCONFIRMATION, and it is recorded as one.
 */
export interface SecVerification {
  /** ISO timestamp of the run. */
  at: string;
  /** The exact command line that was executed. */
  command: string;
  /** What came back, clipped to the configured output cap. */
  output: string;
  /** Process exit code, or null when the run was killed (timeout). */
  exitCode: number | null;
  /** True when the process was killed for exceeding the time budget. */
  timedOut: boolean;
  /** What the author said this run would show, stated before it ran. */
  expect: string;
  /**
   * The exit-code expectation the verdict was judged against.
   *
   * STORED, not implied. Without it the verdict is not reproducible from the record: a
   * recompute has to know what the run was being judged against, or it silently decides the
   * run passed. (Measured: omitting these two fields made a recorded `confirmed: false` read
   * back as `true` — the exact failure the recompute exists to prevent.)
   */
  expectExit: "zero" | "nonzero";
  /** The output substring the verdict was judged against, when one was given. */
  expectOutput?: string;
  /** Whether the run matched that expectation. */
  confirmed: boolean;
}

/** What a verify call states. `expect` is required — see `SecVerification.confirmed`. */
export interface SecVerifyInput {
  /** The command line to run. */
  command: string;
  /** What the author predicts, in prose, stated before the run. */
  expect: string;
  /** Optional substring the output must contain for the run to count as confirmed. */
  expectOutput?: string;
  /** Optional exit-code expectation; defaults to "zero". */
  expectExit?: "zero" | "nonzero";
}

/**
 * One step in a finding's call chain.
 *
 * THE STEP A READER SCANS FOR. A sec finding's `reasoning` is prose, and the model
 * writes its `file:line` references INSIDE that prose — measured on a real X-Road
 * report, one finding named `SecurityConfig.java:51`, `:157-166`, `:165`, `:166`,
 * `ManagementRequestServiceImpl.java:97-99` and `permissions.yml:20,27,109` in the middle
 * of Chinese sentences. The chain was there; it just could not be scanned, because
 * nothing marked where one step ended and the next began.
 *
 * So the steps are recorded structurally instead, and rendered as a fenced NUMBERED
 * list — the same shape the hypothesis report's 调用链 uses, for the same reason.
 */
export interface SecFindingStep {
  /** What happens at this step. */
  detail: string;
  /** Where it happens, when the step is a code location. */
  file?: string;
  line?: number;
}

/** The fields a finding update may change. */
export interface SecFindingPatch {
  title?: string;
  category?: string;
  severity?: Severity;
  preAuth?: boolean;
  location?: EvidenceLocation;
  evidence?: string;
  reasoning?: string;
  poc?: string;
  /** Replace the call chain. */
  path?: SecFindingStep[];
  /** Link the finding back to the surface item it came out of. */
  surfaceId?: string;
  /** The findings this one combines. See `SecFinding.chainOf`. */
  chainOf?: string[];
  /** The result of a verification run. See `SecVerification`. */
  verification?: SecVerification;
  /** Replace the blocker list. See `SecFinding.blockers`. An empty array CLEARS it (the gate opened). */
  blockers?: string[];
  /**
   * How many pursuit rounds this finding has cost. Set by the LOOP on prepare, not by the model.
   *
   * In the patch type because that is the only way it reaches the log — the same reason
   * `SecSurface.attempts` is.
   */
  pursuitSpent?: number;
  /** Close the pursuit with a reason — the gate opened, or the attempts ran out. */
  pursuitClosed?: string;
  /** Say there is MORE HERE and the loop should deepen this finding. See `SecFinding.deepen`. */
  deepen?: boolean;
}

/**
 * What KIND of thing a surface item is.
 *
 * A coordinate, not a claim — which is what makes this different from a hypothesis.
 * `POST /diag/ping` is a place; "the ping handler reaches system() without a check"
 * is an assertion about it. The point of the surface list is to be able to enumerate
 * places WITHOUT having to assert anything about them first, and then examine them
 * one at a time.
 */
export type SecSurfaceKind = "entrypoint" | "sink" | "boundary" | "file" | "other";

export const SEC_SURFACE_KINDS: readonly SecSurfaceKind[] = ["entrypoint", "sink", "boundary", "file", "other"];

/**
 * How far the run has got with one item.
 *
 * `cleared` is the state that makes this mode an ANALYSIS rather than a bug hunt.
 * "I read this and it is guarded" is a result — it is what stops the next round
 * re-reading the same file, and it is the only evidence a reader has that a part of
 * the project was looked at and found sound rather than skipped.
 */
export type SecSurfaceStatus = "open" | "examined" | "cleared" | "digging";

/**
 * One item on the attack surface a `/loopSEC` run has enumerated.
 *
 * THE WORK LIST. Without it the loop can only say "go and look", which is not an
 * analysis — there is no record of what has been looked at, no way to tell progress
 * from idleness, and no way to hand the model a specific target. With it the loop
 * assigns the next open item, and a round that examines one is progress even when it
 * finds nothing.
 */
export interface SecSurface {
  id: string;
  /** ISO timestamp. */
  at: string;
  /** The round that enumerated it. */
  round: number;
  kind: SecSurfaceKind;
  /** What it is: a route, a function, a boundary. Free-form, like a finding title. */
  title: string;
  location?: EvidenceLocation;
  /**
   * The classes worth checking here, when the enumerator has an opinion. */
  categories?: string[];
  /**
   * Higher is analysed sooner. Absent/0 = as planned.
   *
   * THE PLAN IS NOT FROZEN, which is a change from the first design. That design said the
   * enumerator's order IS the plan and nothing re-sorts it — and the reasoning was that
   * re-sorting behind the model's back would throw its judgement away. The hole in it:
   * that judgement was made in round 2, with almost nothing read. A re-prioritisation in
   * round 15 is **the model's own better-informed judgement**, not the loop second-guessing
   * it, and an audit that follows a plan written before it knew anything is following a
   * stale plan.
   *
   * The hypothesis mode already re-ranks every round — novelty, gate boost, category
   * diversity — so a frozen enumeration order was the inconsistent one.
   */
  priority?: number;
  status: SecSurfaceStatus;
  /**
   * WHY it is not exploitable. Required to clear an item.
   *
   * "Nothing found" is not a reason — it is the absence of one. A clearance that
   * cannot say what guard it found is a clearance nobody can check, and it would let
   * a whole area be marked done on the strength of a shrug.
   */
  clearedReason?: string;
  /**
   * WHERE the guard is — the line a reader opens to check the clearance.
   *
   * REQUIRED to clear an item, and it is the same bar the findings carry. A clearance is what BOUNDS
   * the attack surface ("this part was looked at and found guarded"), so on a 0day hunt it matters as
   * much as a finding does — and a reason like "the role check is enforced" names no line, so nobody
   * can verify it. Measured on a real run: clearances read well and could not be checked.
   */
  guardLocation?: EvidenceLocation;
  examinedAt?: string;
  /**
   * How many rounds of DEPTH this item has been given. See `sec_dig`.
   *
   * Counted by the loop, not by the model, so a crash or a stalled turn cannot hand out
   * unlimited depth — the same reason `pursueSpent` is spent on prepare.
   *
   * It exists to make "I am not finished with this" a bounded act. Without a bound the
   * digging state is a way for the model to sit on one item for the rest of the run, which
   * is the failure it was added to fix.
   */
  digRounds?: number;
  /**
   * How many analyze rounds this item has been ASSIGNED.
   *
   * Incremented by the loop on prepare. It exists because the report was lying: an item that
   * was handed a round and left unresolved stays `open`, and the `尚未分析` section called every
   * open item "没看过" — including ones the run had looked at. On a run with unproductive rounds
   * that is most of them.
   *
   * NOT the same as `digRounds`: that counts rounds the model ASKED for, this counts rounds it
   * was given.
   */
  attempts?: number;
  /** The finding this item produced, when it produced one. */
  findingId?: string;
}

/** The fields a surface update may change. */
export interface SecSurfacePatch {
  status?: SecSurfaceStatus;
  clearedReason?: string;
  /** Where the guard is. See `SecSurface.guardLocation`. */
  guardLocation?: EvidenceLocation;
  /** Stamped by updateSurface when the status leaves `open`. */
  examinedAt?: string;
  /** Raise to jump the queue; 0 to put it back in plan order. */
  priority?: number;
  /** Set by the loop when it prepares a depth round. See `SecSurface.digRounds`. */
  digRounds?: number;
  /** Set by the loop on prepare. See `SecSurface.attempts`. */
  attempts?: number;
  findingId?: string;
  categories?: string[];
  title?: string;
  location?: EvidenceLocation;
}

export interface TreeSnapshot {
  /** Stable tree id, assigned at creation. */
  treeId: string;
  /** The user's audit objective — the root node's `description`. */
  objective: string;
  /** Root node id. */
  rootId: string;
  /** All nodes, insertion order (root first). */
  nodes: Hypothesis[];
  byId: Map<string, Hypothesis>;
  /** Ordered ids of every node, oldest first. */
  order: string[];
  /**
   * Operator input, oldest first.
   *
   * Unlike every other history here this is NOT windowed. A selection or a
   * consolidation can be re-derived by re-reading the project; a note is the
   * only thing in the ledger that exists nowhere else.
   */
  notes: OperatorNote[];
  /**
   * Bounded history of scheduling decisions, oldest first. Bounded by
   * `HISTORY_WINDOW` so the snapshot stays small; the per-node counters that
   * need to be unbounded live on the nodes themselves.
   */
  selections: SelectionRecord[];
  /**
   * Bounded history of consolidation passes (stage 4), oldest first.
   *
   * The examined-pair set is DERIVED from these records rather than stored
   * separately, so there is one source of truth for "has this pair been looked
   * at". Bounded by `CONSOLIDATION_HISTORY_WINDOW`; a very long audit may
   * re-offer an ancient pair, which costs one extra consideration and is
   * preferable to an unbounded snapshot.
   */
  consolidations: ConsolidationRecord[];
  /** The audit loop, or null when none has been started. */
  loop: AuditLoopState | null;
  /** Bounded round history, oldest first. */
  roundRecords: RoundRecord[];
  /**
   * The recon note, chunked. Empty until a recon round has submitted notes.
   * Recomputed whenever the note changes, so an edited note re-opens only the
   * segments whose text actually differs.
   */
  segments: ReconSegment[];
  /** Per-segment outcomes, oldest first. Bounded. */
  segmentRecords: SegmentRecord[];
  /** ISO timestamp of the newest recon submission, or null. */
  reconAt: string | null;
  /**
   * `/loopSEC` findings, oldest first.
   *
   * Empty in every other mode — a hypothesis audit records nodes instead, and the
   * two never mix in one run.
   */
  findings: SecFinding[];
  /**
   * The `/loopSEC` attack surface, oldest first.
   *
   * The work list: what the run decided was worth looking at, and how far it got with
   * each item. Not windowed, like `findings` — an item dropped from the list would be
   * re-enumerated and re-examined, and the run would look busier than it is.
   */
  surfaces: SecSurface[];
  /**
   * The `/loopSEC` recon note, or null.
   *
   * Free text, NOT chunked into segments. Segments exist to bound hypothesis
   * generation — each one becomes a round — and a dig round does not generate from
   * a segment, it generates from what has not been read yet.
   */
  secNote: string | null;
  /** Highest `SEC`-style sequence number already used, so ids are never
   * reused even after a compaction. */
  maxNodeSeq: number;
  /** Rounds started so far (stage 2+; 0 until the loop runs). */
  rounds: number;
  /** Lines that failed to parse while folding (crash telemetry). A non-zero
   * value is reported, never silently swallowed. */
  tornLines: number;
  /** Number of `snapshot` records folded past — how many times the log was
   * compacted. */
  compactions: number;
  /** ISO timestamp of the newest event folded. */
  updatedAt: string;
}

// -----------------------------------------------------------------
// Validation
// -----------------------------------------------------------------

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

const NON_EMPTY = (v: unknown): boolean => typeof v === "string" && v.trim().length > 0;

/** Minimum length of a usable assertion. */
export const MIN_DESCRIPTION_CHARS = 20;

/**
 * The minimum length is counted in CHARACTERS, which is not the same yardstick
 * in every language: a Chinese assertion says in 20 characters what English
 * needs 60 for. Applying the English floor to Chinese text would reject
 * perfectly specific claims, so the floor is language-aware.
 */
const CJK = /[\u3400-\u9fff]/;

function minDescriptionCharsFor(text: string): number {
  return CJK.test(text) ? 12 : MIN_DESCRIPTION_CHARS;
}

/**
 * Task-shaped openings that make a description a TASK rather than a
 * hypothesis. Rejecting these is the single cheapest way to keep the tree
 * from degenerating into a todo list.
 *
 * The list is deliberately about the SHAPE of the sentence, not about
 * vocabulary policing: "check", "review", "look at", "audit", "scan",
 * "investigate", "find", "examine", "test whether" all ask for an action and
 * produce no knowledge when they end.
 */
const TASK_SHAPED_PREFIXES = [
  /^\s*(?:please\s+)?(?:check|verify|review|inspect|examine|look\s+(?:at|into)|audit|scan|investigate|explore|find|search|test|probe|analyze|analyse|assess|evaluate|determine|identify|locate|enumerate|list)\b/i,
  /^\s*(?:please\s+)?(?:test|check)\s+whether\b/i,
  /^\s*(?:todo|task|step)\s*[:#-]/i,
  /^\s*\d+[.)]\s+/,
  // Chinese: the same shapes. A task opens with an imperative verb; an
  // assertion opens with its SUBJECT. This half matters because the assertion
  // gate must work in the language the model is told to write in — a
  // Chinese-first audit whose gate only recognises English does not have a
  // gate, it has a wall.
  /^\s*(?:请|需要|应该|必须|尝试|记得|帮我)/,
  /^\s*(?:检查|查看|确认|验证|测试|审计|分析|排查|评估|研究|寻找|看看|梳理|枚举|列出|定位|追踪|核实|检验|判断|探究|调查)/,
];

/**
 * A description that is only a noun phrase has no truth value. "The login
 * endpoint and its middleware chain" cannot be confirmed or refuted — it is
 * a subject with no predicate.
 *
 * The third hint is a VERB-FORM check, and it is deliberately a curated list
 * rather than a generic `\w+s\b`. The generic form matched any word ending in
 * `s` — including "its" — so it accepted exactly the noun phrases this check
 * exists to refuse. The list is a superset check (any one verb is enough), so
 * a genuine assertion phrased with an unlisted verb still passes as long as it
 * has a copula or a negation; the cost of a miss is a clearer rejection
 * message, not a lost hypothesis.
 */
const ASSERTION_HINTS = [
  // copula / auxiliary
  /\b(?:is|are|was|were|does|do|did|has|have|had|can|could|will|would|must|should|may|might|isn't|aren't|doesn't|don't|didn't|can't|won't)\b/i,
  // negation / absence / weakness
  /\b(?:not|never|no|without|missing|lacks?|lacking|absent|unchecked|unsafe|unvalidated|unescaped|unbounded|unauthenticated|unauthori[sz]ed|unprotected|unsanitized|insufficient|incorrect|wrong|stale|leaks?|exposes?|bypass(?:es|ed)?|allows?|permits?|accepts?|trusts?|ignores?)\b/i,
  // a predicate verb that distinguishes "X does Y" from "X and Y"
  /\b(?:validates?|verifies?|checks?|compares?|decodes?|encodes?|parses?|escapes?|sanitizes?|sanitises?|enforces?|rejects?|returns?|writes?|reads?|executes?|deserializes?|deserialises?|handles?|uses?|calls?|passes?|stores?|loads?|resolves?|follows?|honors?|honours?|respects?|applies?|guards?|protects?|restricts?|filters?|injects?|reflects?|redirects?|fetches?|sends?|receives?|binds?|concatenates?|interpolates?|truncates?|casts?|assigns?|initializes?|initialises?|frees?|allocates?|copies?|opens?|creates?|deletes?|updates?|mutates?)\b/i,
  // Chinese. Broad on purpose, and the asymmetry is deliberate:
  //
  //   a false ACCEPT lets a vague hypothesis into the tree, where the scheduler
  //   will try to falsify it and record "blocked";
  //
  //   a false REJECT means the model cannot record what it found at all, and the
  //   audit stalls on a gate it cannot satisfy.
  //
  // The second is far worse, so these match a single character where the English
  // set matches a word. The TASK_SHAPED_PREFIXES above are what keep the gate
  // meaningful, and they stay strict.
  //
  // negation / absence / weakness / possibility
  /(?:没有|未|不|无|缺少|缺失|缺乏|忽略|绕过|暴露|泄露|泄漏|允许|可以|能够|可被|直接|任意|越权|未授权|未经|存在|导致|使得|即|就能)/,
  // predicate verbs
  /(?:校验|验证|检查|过滤|转义|鉴权|认证|授权|比较|解码|编码|解析|反序列化|序列化|执行|调用|返回|写入|读取|存储|加载|处理|使用|传递|接收|发送|拼接|截断|转换|赋值|初始化|释放|分配|复制|打开|创建|删除|更新|修改|继承|覆盖|信任|依赖|引用|转发|注入|遍历|上传|下载|回显|反射)/,
  // copula
  /(?:是|为|属于|等于|指向|落在|进入|到达|有)/,
];

/**
 * Validate that a description is a FALSIFIABLE ASSERTION.
 *
 * Three mechanical rules, in order of value:
 *   1. It must not open like a task (TASK_SHAPED_PREFIXES).
 *   2. It must be long enough to be specific.
 *   3. It must contain something with a truth value (ASSERTION_HINTS).
 *
 * This cannot judge whether an assertion is *interesting* — that is the
 * auditor's job. It only refuses the shapes that are provably not
 * hypotheses, so the failure mode is a clear rejection message rather than a
 * tree full of todos.
 */
export function validateDescription(description: string): ValidationResult {
  const errors: string[] = [];
  if (!NON_EMPTY(description)) {
    errors.push("description is required");
    return { ok: false, errors };
  }
  const text = description.trim();
  if (text.length < minDescriptionCharsFor(text)) {
    errors.push(
      `description must be a specific assertion (at least ${minDescriptionCharsFor(text)} characters); got ${text.length}`,
    );
  }
  for (const re of TASK_SHAPED_PREFIXES) {
    if (re.test(text)) {
      errors.push(
        `description reads as a TASK, not a hypothesis ("${text.slice(0, 40)}…"). State what you believe about the codebase and can be proven wrong — e.g. instead of "check the JWT validation" write "the login handler accepts a JWT without verifying its signature".`,
      );
      break;
    }
  }
  if (!ASSERTION_HINTS.some((re) => re.test(text))) {
    errors.push(
      `description has no truth value — it must be an assertion that can be confirmed or refuted (got "${text.slice(0, 60)}")`,
    );
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Validate an attack vector.
 *
 * `entrypoint` and `technique` are required when a vector is supplied at all:
 * a vector that names neither says nothing about how the hypothesis would be
 * reached, and an empty vector is expressed by OMITTING the field rather than
 * by supplying a hollow one.
 */
export function validateAttackVector(vector: Partial<AttackVector> | undefined): ValidationResult {
  const errors: string[] = [];
  if (vector === undefined) return { ok: true, errors };
  if (!vector || typeof vector !== "object") return { ok: false, errors: ["attackVector must be an object"] };
  if (!NON_EMPTY(vector.entrypoint)) {
    errors.push("attackVector.entrypoint is required — how does the attacker get in? (a route, a queue, a CLI verb, a file drop)");
  }
  if (!NON_EMPTY(vector.technique)) {
    errors.push("attackVector.technique is required — what is the attack? (e.g. \"alg=none JWT forgery\")");
  }
  if (vector.path !== undefined) {
    if (!Array.isArray(vector.path)) errors.push("attackVector.path must be an array of steps");
    else {
      vector.path.forEach((step, i) => {
        if (!step || typeof step !== "object" || !NON_EMPTY(step.detail)) {
          errors.push(`attackVector.path[${i}] needs a detail`);
        }
      });
    }
  }
  if (vector.preconditions !== undefined && !Array.isArray(vector.preconditions)) {
    errors.push("attackVector.preconditions must be an array of strings");
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Validate a caller-supplied node input, minus the derived fields.
 *
 * A `scope` node is EXEMPT from the assertion gate. That is the whole point of
 * the kind: an audit of an unfamiliar project begins with a boundary ("the
 * project rooted at cwd"), and forcing that boundary to be phrased as a claim
 * produces a root like "this project contains a vulnerability" — which no
 * evidence can refute, so the root of a falsification tree would be the one
 * node that can never be falsified.
 */
export function validateHypothesisInput(input: Partial<HypothesisInput>): ValidationResult {
  const kind: NodeKind = input.nodeKind ?? "hypothesis";
  const errors: string[] = [];

  if (!NODE_KINDS.includes(kind)) {
    errors.push(`nodeKind must be one of ${NODE_KINDS.join("|")}`);
  } else if (kind === "scope") {
    if (!NON_EMPTY(input.description)) errors.push("a scope node needs a description of the boundary it declares");
  } else {
    errors.push(...validateDescription(input.description ?? "").errors);
  }

  if (!NON_EMPTY(input.category)) {
    errors.push("category is required");
  } else if (!isKnownCategory(input.category as string)) {
    errors.push(
      `unknown category "${input.category}" — use one of the known classes so the per-category share cap cannot be evaded by inventing a spelling (see HYPOTHESIS_CATEGORIES)`,
    );
  }
  if (input.status !== undefined && !OPEN_STATUSES.includes(input.status) && !VERDICT_STATUSES.includes(input.status)) {
    errors.push(`unknown status "${input.status}"`);
  }
  if (input.status === "blocked" && !NON_EMPTY(input.statusReason)) {
    errors.push("statusReason is required when a node is blocked — an unexplained block is indistinguishable from abandonment");
  }
  if (input.evidence !== undefined) {
    if (!Array.isArray(input.evidence)) errors.push("evidence must be an array");
    else input.evidence.forEach((e, i) => errors.push(...validateEvidence(e).errors.map((m) => `evidence[${i}]: ${m}`)));
  }
  if (input.spawnedFrom !== undefined && !Array.isArray(input.spawnedFrom)) {
    errors.push("spawnedFrom must be an array of node ids");
  }
  errors.push(...validateAttackVector(input.attackVector).errors);
  if (input.segmentId !== undefined && !NON_EMPTY(input.segmentId)) {
    errors.push("segmentId must be a non-empty segment id when supplied");
  }
  return { ok: errors.length === 0, errors };
}

/** Validate one evidence entry. */
export function validateEvidence(evidence: Partial<Evidence> | undefined): ValidationResult {
  const errors: string[] = [];
  if (!evidence || typeof evidence !== "object") return { ok: false, errors: ["evidence must be an object"] };
  if (!NON_EMPTY(evidence.kind) || !EVIDENCE_KINDS.includes(evidence.kind as EvidenceKind)) {
    errors.push(`kind must be one of ${EVIDENCE_KINDS.join("|")}`);
  }
  if (!NON_EMPTY(evidence.detail)) {
    errors.push("detail is required — an evidence entry without the verbatim excerpt, request, or output proves nothing");
  }
  if (evidence.kind === "command-output" && !NON_EMPTY(evidence.command)) {
    errors.push("command is required for command-output evidence (the output is not reproducible without it)");
  }
  if (evidence.kind === "file") {
    if (!evidence.location) errors.push("location { file, line } is required for file evidence");
    else if (!NON_EMPTY(evidence.location.file) || !Number.isFinite(evidence.location.line)) {
      errors.push("location must be { file: string, line: number }");
    }
  }
  return { ok: errors.length === 0, errors };
}
