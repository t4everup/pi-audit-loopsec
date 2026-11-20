/**
 * pi-audit-loopsec — extensions/loop-sec/coverage.ts
 *
 * How much of the PROJECT has this audit actually looked at?
 *
 * -----------------------------------------------------------------------
 * Why this is not the segment coverage
 * -----------------------------------------------------------------------
 *
 * `segmentCoverage` counts SEGMENTS, and segments come from the recon note. So it
 * reports "4/4" for an audit that wrote four paragraphs about a whole application
 * — a number that reads as complete coverage and means only "I processed the four
 * windows I chose to write".
 *
 * Measured on a real Centreon audit: 16 paragraphs became 4 segments, 92% of every
 * hypothesis came from those four windows, and NOTHING came from anywhere else. A
 * report saying "4/4" hid all of that.
 *
 * -----------------------------------------------------------------------
 * What this measures instead
 * -----------------------------------------------------------------------
 *
 * The FILES a hypothesis cites, against the files the project has. Both sides are
 * derived, neither is declared:
 *
 *   cited   — the `file` of every attack-vector step and every evidence location,
 *             over every node in the tree, so it is CUMULATIVE: a second recon
 *             note adds to it rather than replacing it.
 *   project — the same bounded walk the grep probe uses, with the same skip list,
 *             so the two cannot disagree about what "the project" is.
 *
 * The gap, grouped by top-level directory, is the part of the project that no
 * hypothesis has ever touched.
 *
 * -----------------------------------------------------------------------
 * What a gap is NOT
 * -----------------------------------------------------------------------
 *
 * A directory with no hypothesis is not "clean". It is UNREAD, and those are
 * different claims — the same distinction the impact section makes between "not
 * assessed" and "no impact". Everything rendered from this module says so.
 */

import * as path from "node:path";

import type { Hypothesis, TreeSnapshot } from "./types.js";
import { walkProject } from "./executor.js";
import { loadSettings } from "./settings.js";
import { type ReportLanguage, coverageHeadlineText } from "./reportText.js";

export const COVERAGE = {
  /**
   * How many directories the report and the brief will name.
   *
   * Bounded because the list is an instruction to go and read something, and an
   * instruction with forty items is one nobody follows.
   */
  MAX_LISTED: 12,
  /**
   * A directory with fewer files than this is not worth a recon round.
   *
   * A single-file directory with no hypothesis is noise; a 400-file subsystem is
   * a hole. Without a floor the list is mostly noise and the real holes are not
   * visible in it.
   */
  MIN_FILES_FOR_GAP: 3,
  /**
   * How many coverage rounds a run may spend.
   *
   * Two: one to open the areas the first note missed, one to follow up if the
   * first coverage recon itself turned out thin. Unbounded would be a round kind
   * that can always justify itself — the failure mode this codebase has hit three
   * times.
   */
  MAX_ROUNDS: 2,
} as const;

export interface DirectoryGap {
  /** Top-level directory, project-relative, forward slashes. */
  dir: string;
  /** Files the walk found there. */
  files: number;
  /** How many of them a hypothesis cites. */
  cited: number;
}

export interface CoverageReport {
  /** Distinct project-relative files cited by any hypothesis. */
  citedFiles: number;
  /** Files the bounded walk found, or null when the walk could not run. */
  projectFiles: number | null;
  /** True when the walk hit its file budget, so `projectFiles` is a lower bound. */
  truncated: boolean;
  /** Why the walk could not run, when it could not. */
  reason: string;
  /**
   * The round this measurement belongs to, when the walk is memoised (see `secCoverage`).
   *
   * Printed with the figure: a coverage number with no timestamp reads as current, and a memoised one can be
   * a few rounds old.
   */
  measuredAtRound?: number;
  /** Directories with ZERO cited files, biggest first. */
  gaps: DirectoryGap[];
  /**
   * How many files sit inside the untouched subtrees.
   *
   * The headline number, and the one a fixed depth was hiding: a project can show
   * one tiny "gap" and still have half its files in subtrees nobody cited.
   */
  untouchedFiles: number | null;
  /** The skip-list note, so a reader knows what the walk deliberately ignored. */
  skipNote: string;
}

/**
 * Every project-relative file a hypothesis cites.
 *
 * Both sources, because they are recorded in different places: an attack vector
 * carries the chain's locations, and evidence carries the artifact's. A file that
 * appears only in evidence is still a file the audit looked at.
 */
export function citedFiles(snapshot: Pick<TreeSnapshot, "nodes">): Set<string> {
  const cited = new Set<string>();
  const add = (file: string | undefined): void => {
    if (!file) return;
    // Normalised so `./src/a.ts` and `src/a.ts` are one file.
    cited.add(path.posix.normalize(file.split("\\").join("/")).replace(/^\.\//, ""));
  };
  for (const node of snapshot.nodes as Hypothesis[]) {
    for (const step of node.attackVector?.path ?? []) add(step.location?.file);
    for (const ev of node.evidence) add(ev.location?.file);
  }
  return cited;
}

/**
 * The largest subtrees with ZERO cited files.
 *
 * ADAPTIVE, not a fixed depth, and that is the whole point of the function.
 *
 * A fixed depth fails in both directions. Grouping by ONE segment collapses
 * `src/api` and `src/admin` into `src`, so one cited file under `src/api` marks the
 * entire `src` tree covered. Grouping by TWO fails on a project where everything
 * lives under a single wrapper: measured on the Checkmk appliance, the source is one
 * tree at `source/rootfs/...`, so depth 2 produced THREE groups and the report said
 * "1 gap: source/.idea (an IDE directory)" while 40 of 898 files had been cited.
 *
 * So: descend only while a directory is TOUCHED. The moment one is untouched, report
 * it and stop — its children are inside the same hole, and listing them would turn
 * one hole into forty lines nobody reads.
 *
 * On that same Checkmk tree this reports 10 subtrees holding 407 of 898 files, which
 * is the truth the fixed depth was hiding.
 */
interface DirNode {
  files: number;
  cited: number;
  kids: Map<string, DirNode>;
}

function untouchedSubtrees(
  projectRoot: string,
  walkFiles: readonly string[],
  cited: ReadonlySet<string>,
): { gaps: DirectoryGap[]; files: number } {
  const root: DirNode = { files: 0, cited: 0, kids: new Map() };
  for (const abs of walkFiles) {
    const rel = path.relative(path.resolve(projectRoot), abs).split("\\").join("/");
    const parts = rel.split("/");
    const hit = cited.has(rel);
    let cur = root;
    cur.files++;
    if (hit) cur.cited++;
    for (let i = 0; i < parts.length - 1; i++) {
      const name = parts[i]!;
      let next = cur.kids.get(name);
      if (!next) {
        next = { files: 0, cited: 0, kids: new Map() };
        cur.kids.set(name, next);
      }
      cur = next;
      cur.files++;
      if (hit) cur.cited++;
    }
  }

  const gaps: DirectoryGap[] = [];
  let files = 0;
  const descend = (node: DirNode, prefix: string): void => {
    for (const [name, child] of node.kids) {
      const dir = prefix ? `${prefix}/${name}` : name;
      if (child.cited > 0) {
        descend(child, dir);
      } else if (child.files >= COVERAGE.MIN_FILES_FOR_GAP) {
        gaps.push({ dir, files: child.files, cited: 0 });
        files += child.files;
      }
    }
  };
  descend(root, "");
  // Biggest hole first: the largest untouched subsystem is the one most likely to
  // hold what the audit is looking for.
  gaps.sort((a, b) => b.files - a.files || a.dir.localeCompare(b.dir));
  return { gaps, files };
}

/**
 * The coverage gap.
 *
 * Never throws: a walk that cannot run reports `projectFiles: null` and an empty
 * gap list, because "I could not measure" must not be rendered as "fully covered".
 */
export function coverageGaps(
  snapshot: TreeSnapshot,
  projectRoot: string,
  /**
   * The cited set, when it does not come from the hypothesis tree.
   *
   * `/loopSEC` has no nodes to derive it from — its record is a list of findings —
   * so it computes its own set and passes it in. Without this the sec report would
   * say "0 of 898 files cited" no matter how much had been read, and the dig brief
   * could not tell the model what is still unread.
   */
  citedOverride?: ReadonlySet<string>,
): CoverageReport {
  const cited = citedOverride ?? citedFiles(snapshot);
  const settings = loadSettings(projectRoot).settings;
  const walk = walkProject(projectRoot, undefined, settings);
  const skipNote = settings.maxFilesScanned > 0 ? `${settings.maxFilesScanned}-file budget` : "no budget";

  if (walk.files.length === 0) {
    return {
      citedFiles: cited.size,
      projectFiles: null,
      truncated: walk.truncated,
      reason: walk.reason || "the project walk found no files",
      gaps: [],
      untouchedFiles: null,
      skipNote,
    };
  }

  const { gaps, files: untouchedFiles } = untouchedSubtrees(projectRoot, walk.files, cited);

  return {
    citedFiles: cited.size,
    projectFiles: walk.files.length,
    truncated: walk.truncated,
    reason: walk.reason,
    gaps: gaps.slice(0, COVERAGE.MAX_LISTED),
    untouchedFiles,
    skipNote,
  };
}


/** Is there a hole worth spending a coverage round on? */
export function hasCoverageGap(report: CoverageReport): boolean {
  return report.gaps.length > 0;
}

/** `4 of 5 directories` style summary, or a reason it could not be measured. */
export function coverageHeadline(report: CoverageReport, lang: ReportLanguage = "en"): string {
  return coverageHeadlineText(
    lang,
    report.projectFiles === null ? null : report.citedFiles,
    report.projectFiles,
    report.untouchedFiles,
    report.truncated,
    report.reason,
  );
}
