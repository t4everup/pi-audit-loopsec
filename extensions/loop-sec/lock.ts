/**
 * pi-audit-loopsec — extensions/loop-sec/lock.ts
 *
 * One round at a time, across PROCESSES.
 *
 * The turn claim in `active.json` already keeps one round in flight per process — but two pi windows
 * open on the same project both write it, and the loser's tool calls then resolve to the winner's run.
 * Nothing reports it: the finding lands in another audit's log and both windows look healthy. This is
 * the only known way to corrupt the record silently, which is why it is the one thing here that had to
 * be fixed before a run could be left unattended.
 *
 * WHY A DIRECTORY. `mkdirSync` is atomic on NTFS and on exFAT, needs no descriptor held open, and needs
 * no rename or link — the three things this project forbids because a non-journaling volume fails them.
 * Whoever creates the directory owns the round; the loser skips and tries again later.
 *
 * WHY A TTL. A process killed mid-round leaves the directory behind. A lock that cannot be released by
 * the dead outlives them and stops the run forever, so an owner older than the TTL is taken over — and
 * `owner.json` records the pid and time so the takeover is visible in the log rather than magic.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { secBaseDir } from "./store.js";

/** Where the lock lives, relative to `.pi-loopsec`. A directory, not a file — see the header. */
export const TURN_LOCK_NAME = "turn.lock";

/** How long an owner may hold the lock before another process may take it over. */
export const DEFAULT_LOCK_TTL_MS = 600_000;

export interface LockOwner {
  pid: number;
  at: string;
  run?: string;
  round?: number;
}

export type LockResult =
  | { ok: true; release: () => void; reentrant?: boolean; /** The dead owner whose lock was taken over. */ tookOver?: LockOwner }
  | { ok: false; reason: string; holder?: LockOwner };

/**
 * Remove the lock IF THIS PROCESS OWNS IT.
 *
 * Separate from the `release` closure because the lock now outlives the call that took it: `advanceRuns`
 * keeps it while a round is in flight (that is what stops a second window from settling somebody else's
 * round) and drops it when the round is over. A handle that only lives as long as one call cannot express
 * that, and a blind remove would delete another process's lock.
 */
export function releaseTurnLock(projectRoot: string): void {
  const dir = turnLockDir(projectRoot);
  const holder = readOwner(dir);
  if (!holder) {
    // Unreadable owner: only remove when the directory is ours by mtime-freshness is NOT knowable, so
    // leave it — the TTL will clear it rather than risk deleting a live lock.
    return;
  }
  if (holder.pid !== process.pid) return;
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* the TTL will clear it */
  }
}

/** Remove the lock. Shared by every acquire path so the two cannot drift. */
function makeRelease(dir: string): () => void {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* the TTL will clear it */
    }
  };
}

export function turnLockDir(projectRoot: string): string {
  return path.join(secBaseDir(projectRoot), TURN_LOCK_NAME);
}

/**
 * Is that process still there?
 *
 * process.kill(pid, 0) sends no signal; it only asks the OS whether the process exists. ESRCH means it is gone,
 * EPERM means it exists but belongs to somebody else (still alive), anything else is treated as alive —
 * refusing to take over a lock we are unsure about is the safe direction.
 */
function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readOwner(dir: string): LockOwner | null {
  try {
    const raw = fs.readFileSync(path.join(dir, "owner.json"), "utf-8");
    const o = JSON.parse(raw) as Record<string, unknown>;
    if (typeof o.pid !== "number" || typeof o.at !== "string") return null;
    return {
      pid: o.pid,
      at: o.at,
      ...(typeof o.run === "string" ? { run: o.run } : {}),
      ...(typeof o.round === "number" ? { round: o.round } : {}),
    };
  } catch {
    // An owner file that cannot be read is treated as "unknown age", which the caller handles by the
    // directory's own mtime — not as "free", because that would let two processes into one round.
    return null;
  }
}

function ageOfMs(dir: string, now: number): number {
  const owner = readOwner(dir);
  if (owner) {
    const at = Date.parse(owner.at);
    if (Number.isFinite(at)) return Math.max(0, now - at);
  }
  try {
    return Math.max(0, now - fs.statSync(dir).mtimeMs);
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/**
 * Try to take the round lock.
 *
 * On failure the caller MUST NOT work a round — the returned reason names the holder so the operator
 * can see both windows instead of guessing which one is stuck.
 */
export function acquireTurnLock(
  projectRoot: string,
  opts: { ttlMs?: number; at?: number; run?: string; round?: number; pid?: number } = {},
): LockResult {
  const dir = turnLockDir(projectRoot);
  const now = opts.at ?? Date.now();
  const ttl = opts.ttlMs ?? DEFAULT_LOCK_TTL_MS;
  // `pid` is a TEST seam: re-entrancy is decided by pid, so a test that wants to represent a SECOND
  // window has to present a different one. In production it is always this process.
  const self = opts.pid ?? process.pid;
  const me: LockOwner = {
    pid: self,
    at: new Date(now).toISOString(),
    ...(opts.run ? { run: opts.run } : {}),
    ...(typeof opts.round === "number" ? { round: opts.round } : {}),
  };

  const writeOwner = (): boolean => {
    try {
      fs.writeFileSync(path.join(dir, "owner.json"), JSON.stringify(me) + "\n", "utf-8");
      return true;
    } catch {
      return false;
    }
  };



  // The PARENT is created recursively (it is shared with every other state file and its existence is
  // not the lock), and then the lock directory is created WITHOUT `recursive` — because `recursive: true`
  // on the lock itself succeeds when it already exists, which would make the lock advisory instead of
  // exclusive. EEXIST is exactly the signal we want.
  try {
    fs.mkdirSync(secBaseDir(projectRoot), { recursive: true });
  } catch {
    return { ok: false, reason: `could not create the state directory for ${TURN_LOCK_NAME}` };
  }
  try {
    fs.mkdirSync(dir);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EEXIST") {
      return { ok: false, reason: `could not create ${TURN_LOCK_NAME}: ${(error as Error).message}` };
    }
    // Held — by ANOTHER PROCESS, or by US.
    //
    // The lock's lifetime is the ROUND, not the call: it is taken when a brief is sent and released when
    // that round is settled. So the same process must be able to re-enter it on the settle, or the settle
    // would be refused by its own lock. Re-entrancy is by pid, which is the only identity a second call
    // in this process has.
    const holder = readOwner(dir);
    if (holder && holder.pid === self) {
      // RE-ENTRANT, AND REFRESHED. The timestamp is rewritten because the lock's lifetime is the round: a run
      // that has been going for an hour is not stale, and another window must not take over a lock whose owner
      // is alive and working. Without the refresh every long run looked abandoned after `ttl` from its FIRST
      // acquisition.
      writeOwner();
      return { ok: true, release: () => {}, reentrant: true };
    }
    // A DEAD OWNER IS NOT A LOCK, and this is checked BEFORE the TTL. A real run paid for the difference: a
    // window was closed mid-round, its lock survived, and the other window reported "another process is working
    // a round (pid 29468)" on every attempt for the full 30-minute TTL while nothing was working. A pid is
    // answerable right now, so ask it instead of waiting.
    if (holder && !pidAlive(holder.pid)) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
        fs.mkdirSync(dir);
        writeOwner();
      } catch (error) {
        return { ok: false, reason: `could not take over a lock left by pid ${holder.pid}: ${(error as Error).message}` };
      }
      return { ok: true, release: makeRelease(dir), tookOver: holder };
    }
    // Held by a process that IS alive: the TTL is the only remaining reason to take it.
    const age = ageOfMs(dir, now);
    if (age <= ttl) {
      return {
        ok: false,
        reason:
          `another pi window is working a round` +
          (holder
            ? ` (pid ${holder.pid}, alive, since ${holder.at}${holder.run ? `, run ${holder.run}` : ""})`
            : "") +
          ` — this window skipped its turn so the two do not interleave. Close that window, or make it pause.`,
        ...(holder ? { holder } : {}),
      };
    }
    // STALE: the owner is gone or wedged. Removing the directory is safe because the only thing in it is
    // our own owner file — the audit records themselves are append-only elsewhere.
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.mkdirSync(dir);
    } catch (e) {
      return { ok: false, reason: `could not take over a stale ${TURN_LOCK_NAME}: ${(e as Error).message}` };
    }
  }

  if (!writeOwner()) {
    // The directory was ours but the owner file failed: give it back rather than hold a lock nobody can
    // attribute, which is what the TTL is for.
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* nothing else to do */
    }
    return { ok: false, reason: `could not write ${TURN_LOCK_NAME}/owner.json` };
  }

  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* the TTL will clear it */
    }
  };
  return { ok: true, release };
}
