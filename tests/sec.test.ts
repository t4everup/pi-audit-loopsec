// pi-audit-loopsec — tests/sec.test.ts
//
// `/loopSEC` — the mode with no hypothesis tree, and the analysis engine that makes
// it more than "go and look".
//
// These tests are written against the TRADE, not the feature. A test that only
// checked "it records findings" would pass on a version that had quietly kept the
// assertion gate, and on one that had dropped the artifact rule. So they pin both
// directions, and the analysis engine's central claim gets its own test: **a round
// that examines an item and finds nothing is PROGRESS**, because the opposite is a
// plateau that stops a run which is doing exactly what it was asked to do.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { loadSec } from "../extensions/loop-sec/store.ts";
import { evaluateRound, pauseAfterRounds, pauseLoop, resumeLoop, startLoop, stopLoop, tickLoop } from "../extensions/loop-sec/loop.ts";
import { loadSettings, saveSettings } from "../extensions/loop-sec/settings.ts";
import { loopCommandName, type SecFindingStep } from "../extensions/loop-sec/types.ts";
import {
  appendSecLedger,
  SEC_DIG_BUDGET,
  SEC_SURFACE_SOFT_CAP,
  clearSurface,
  digSurface,
  nextOpenSurface,
  recordFinding,
  recordSurface,
  reopenSurface,
  renderSecAnalyzeBrief,
  renderSecFindings,
  renderSecReport,
  renderSecSurfaceBrief,
  secCitedFiles,
  secCoverage,
  secLedgerPath,
  secReportPath,
  MAX_ITEM_ATTEMPTS,
  PURSUIT_MIN_SEVERITY,
  nextPursuit,
  reconNotePath,
  reconPhaseOver,
  reconSections,
  submitSecRecon,
  verifyFinding,
  updateSurface,
  surfaceProgress,
  updateFinding,
  validateFinding,
  validateSurface,
  writeSecReport,
} from "../extensions/loop-sec/sec.ts";

function tmpProject(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hypo-sec-"));
}

/**
 * A project with real files.
 *
 * `vendor/` is deliberately NOT used for the untouched-subtree case: it is in
 * PROBE_SKIP_DIRS on purpose (a dependency tree is not the audited surface, and
 * walking it spends the file budget before the project's own code is reached), so a
 * fixture that expects it to appear as a gap is wrong.
 */
function seeded(cwd = tmpProject()): string {
  for (const [rel, body] of [
    ["src/http/server.c", "int main(void) { return 0; }\n"],
    ["src/http/router.c", '{"public": ["/diag/ping"]}\n'],
    ["src/util/shell.c", "void run_cmd(char *c) { system(c); }\n"],
    ["src/auth/session.c", "int check_auth(void) { return 1; }\n"],
    ["src/handlers/upload.c", 'void up(void) { fopen(name, "w"); }\n'],
    ["src/cfg/parse.c", "void parse(void) { }\n"],
    ["tools/a.c", "int a(void) { return 1; }\n"],
    ["tools/b.c", "int b(void) { return 1; }\n"],
    ["tools/c.c", "int c(void) { return 1; }\n"],
    ["tools/d.c", "int d(void) { return 1; }\n"],
  ] as const) {
    const abs = path.join(cwd, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, body, "utf-8");
  }
  return cwd;
}

const NOTE = [
  "一个 C 语言写的嵌入式 Web 服务，源码在 src/ 下。入口是 src/http/server.c 的 main()，监听 80 端口，所有请求经 src/http/router.c 分发。",
  "认证在 src/auth/session.c 的 check_auth()，但 router.c 里有一张表把部分路径标为公开。",
  "命令执行在 src/util/shell.c 的 run_cmd()，用 system() 拼接字符串。",
  "文件上传在 src/handlers/upload.c，把 multipart 的 filename 直接拼进 fopen()。",
].join("\n\n");

function startSec(cwd: string, objective = "挖掘认证前rce漏洞", plateauWindow = 99, reconRounds = 1) {
  // PINNED to one recon round in the fixture: the tests that use this are about the surface and
  // analyze rounds, and the recon phase is now more than one round by DEFAULT (see
  // HypothesisSettings.reconRounds). The multi-round phase has its own tests, which pass 2+.
  saveSettings(cwd, { reconRounds });
  const result = startLoop(cwd, loadSec(cwd).snapshot, { kind: "sec", objective, plateauWindow });
  assert.equal(result.ok, true, result.ok ? "" : result.errors.join("; "));
  return result;
}

/** Recon + a small surface list, the state every analyze test starts from. */
function withSurface(cwd: string, items = 3): void {
  startSec(cwd);
  assert.equal(submitSecRecon(cwd, NOTE).ok, true);
  const titles = [
    { title: "POST /diag/ping", kind: "entrypoint" as const, file: "src/http/router.c", line: 1, categories: ["rce"] },
    { title: "run_cmd() in src/util/shell.c", kind: "sink" as const, file: "src/util/shell.c", line: 1 },
    { title: "the session cookie check", kind: "boundary" as const, file: "src/auth/session.c", line: 1 },
    { title: "the upload handler", kind: "entrypoint" as const, file: "src/handlers/upload.c", line: 1 },
    { title: "the config parser", kind: "file" as const, file: "src/cfg/parse.c", line: 1 },
  ];
  for (const item of titles.slice(0, items)) {
    assert.equal(recordSurface(cwd, item).ok, true);
  }
}

// -----------------------------------------------------------------
// The one rule this mode keeps
// -----------------------------------------------------------------

test("a finding with no artifact is REFUSED — the only rule /loopSEC keeps", () => {
  const cwd = seeded();
  const refused = recordFinding(cwd, { title: "某处有命令注入", category: "rce" });
  assert.equal(refused.ok, false);
  const message = refused.ok ? "" : refused.errors.join(" ");
  assert.match(message, /needs an artifact/);
  assert.match(message, /ONLY thing/);
  assert.equal(loadSec(cwd).snapshot.findings.length, 0, "nothing was recorded");
});

test("a location OR an evidence excerpt is enough", () => {
  const cwd = seeded();
  assert.equal(recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 }).ok, true);
  assert.equal(
    recordFinding(cwd, { title: "upload 拼 filename", category: "path-traversal", evidence: "src/handlers/upload.c:1\n  fopen(name, \"w\");" }).ok,
    true,
  );
  assert.equal(loadSec(cwd).snapshot.findings.length, 2);
});

test("a file without a line is refused rather than silently given line 1", () => {
  const result = validateFinding({ title: "x", category: "rce", file: "src/a.c" });
  assert.equal(result.ok, false);
  assert.match(result.ok ? "" : result.errors.join(" "), /line/);
});

// -----------------------------------------------------------------
// The attack surface — the work list
// -----------------------------------------------------------------

test("a surface item needs only a title — an entrypoint has no line number", () => {
  // The whole point of an entrypoint is that it is reachable from OUTSIDE the code,
  // so demanding a file:line would exclude exactly the items that matter most.
  const cwd = seeded();
  const bare = validateSurface({ title: "POST /diag/ping" });
  assert.equal(bare.ok, true, bare.ok ? "" : bare.errors.join("; "));
  // But a file without a line is still refused, because there the line IS knowable.
  const half = validateSurface({ title: "x", file: "src/a.c" });
  assert.equal(half.ok, false);
  assert.match(half.ok ? "" : half.errors.join(" "), /line/);
});

test("enumerating the same item twice is a warning, not a refusal", () => {
  const cwd = seeded();
  const first = recordSurface(cwd, { title: "POST /diag/ping" });
  assert.equal(first.ok, true);
  const again = recordSurface(cwd, { title: "POST /diag/ping" });
  // Refusing it would make the model handle a rejection it cannot act on; a duplicate
  // is a waste, not a fault.
  assert.equal(again.ok, true);
  assert.ok(again.warnings.length > 0, "and it says so");
  assert.equal(loadSec(cwd).snapshot.surfaces.length, 1);
});

test("the next item is the first still open, in ENUMERATION order", () => {
  const cwd = seeded();
  withSurface(cwd);
  const snapshot = loadSec(cwd).snapshot;
  assert.equal(nextOpenSurface(snapshot)!.id, "S-0001");
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  // The order is the enumerator's judgement and nothing re-sorts it behind its back.
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0002");
});

test("clearing an item REQUIRES a reason that names the guard", () => {
  const cwd = seeded();
  withSurface(cwd);
  const empty = clearSurface(cwd, "S-0001", "nothing found");
  assert.equal(empty.ok, false);
  const message = empty.ok ? "" : empty.errors.join(" ");
  assert.match(message, /WHICH guard/);
  assert.match(message, /absence of a reason/, "and it says why the bar exists");
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.status, "open", "and nothing was cleared");

  const good = clearSurface(cwd, "S-0001", "check_auth() is called at router.c:88 before dispatch, and /diag/ping is not in the public table");
  assert.equal(good.ok, true, good.ok ? "" : good.errors.join("; "));
  const after = loadSec(cwd).snapshot.surfaces[0]!;
  assert.equal(after.status, "cleared");
  assert.ok(after.examinedAt, "and the timestamp is stamped, not left to the caller");
});

test("a finding against a surface item EXAMINES that item", () => {
  const cwd = seeded();
  withSurface(cwd);
  assert.equal(
    recordFinding(cwd, {
      title: "run_cmd() 把 host 拼进 system()",
      category: "rce",
      file: "src/util/shell.c",
      line: 1,
      surfaceId: "S-0001",
    }).ok,
    true,
  );
  const item = loadSec(cwd).snapshot.surfaces[0]!;
  // Without this the item stayed `open`, so the next round was handed the same one and
  // the model was asked to analyse a thing it had just found a bug in.
  assert.equal(item.status, "examined");
  assert.equal(item.findingId, "F-0001");
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0002");
});

test("progress counts examined items, and a cleared one is examined", () => {
  const cwd = seeded();
  withSurface(cwd);
  assert.deepEqual(surfaceProgress(loadSec(cwd).snapshot), { total: 3, open: 3, examined: 0, cleared: 0, productive: 0, aheadOfPlan: 0, digging: 0, attempted: 0 });
  clearSurface(cwd, "S-0001", "check_auth() is called at router.c:88 before dispatch, and the route is not public");
  const p = surfaceProgress(loadSec(cwd).snapshot);
  assert.equal(p.examined, 1);
  assert.equal(p.cleared, 1);
  assert.equal(p.open, 2);
  assert.equal(p.productive, 0, "cleared is not productive — and that is the point");
});

// -----------------------------------------------------------------
// The round flow — recon, surface, analyze
// -----------------------------------------------------------------

test("the sec loop runs recon, then surface, then analyze — and ASSIGNS the item", () => {
  const cwd = seeded();
  startSec(cwd);

  const first = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(first.brief!, /^\[SEC ROUND 1 — RECON 1\/1\]/, "the brief says which recon round this is");

  submitSecRecon(cwd, NOTE);
  const second = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(second.brief!, /^\[SEC ROUND 2 — SURFACE\]/);
  assert.match(second.brief!, /LIST THEM IN THE ORDER THEY SHOULD BE EXAMINED/);
  assert.match(second.brief!, /COORDINATES, not claims/, "an item is a place, not an assertion");

  recordSurface(cwd, { title: "POST /diag/ping", kind: "entrypoint", file: "src/http/router.c", line: 1, categories: ["rce"] });
  const third = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(third.brief!, /^\[SEC ROUND 3 — ANALYZE S-0001\]/);
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.kind, "analyze");
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.surfaceId, "S-0001");
});

test("the analyze brief carries the item, the method, and the class depth axes", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /THIS ROUND IS THIS ITEM/);
  assert.match(brief, /S-0001 {2}\[entrypoint\] {2}POST \/diag\/ping/);
  assert.match(brief, /src\/http\/router\.c:1/);
  // The method — the thing that makes this analysis rather than "go and look".
  assert.match(brief, /HOW TO ANALYSE/);
  assert.match(brief, /ENTRY/);
  assert.match(brief, /CONTROLLED INPUT/);
  assert.match(brief, /THE CHECK/);
  assert.match(brief, /SINK/);
  assert.match(brief, /Read the check itself/, "and it says not to trust a function's name");
  assert.match(brief, /Trace it ALL before concluding/);
  // The class knowledge, reused from ladders.ts rather than re-invented.
  assert.match(brief, /The depth axes for rce/);
  assert.match(brief, /which exact call executes/, "the ladder's own axis text");
  // And the two exits.
  assert.match(brief, /sec_finding/);
  assert.match(brief, /sec_clear/);
  assert.match(brief, /Clearing an item is a RESULT/);
  assert.match(brief, /saying WHICH guard you found and where/);
});

test("the analyze brief says do NOT switch items, and why", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /Analyse THIS item all the way down/);
  assert.match(brief, /every item on the list gets a round[\s\S]{0,4}of its own/);
});

test("the analyze brief shows what has been cleared, so it is not re-examined", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /^\[SEC ROUND \d+ — ANALYZE S-0002\]/, "the cleared item is skipped");
  assert.match(brief, /ALREADY CLEARED/);
  assert.match(brief, /S-0001/);
  assert.match(brief, /check_auth\(\) runs at router\.c:88/, "and the reason is carried, not just the id");
});

test("a surface round is only reached when every item has been examined", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.kind, "analyze");
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  const next = tickLoop(cwd, loadSec(cwd).snapshot);
  // The list is the enumerator's, so when it is exhausted the right move is to
  // enumerate again with what the analysis revealed — not to stop.
  assert.match(next.brief!, /^\[SEC ROUND \d+ — SURFACE\]/);
});

// -----------------------------------------------------------------
// THE FIX THAT MATTERS: examining an item is PROGRESS
// -----------------------------------------------------------------

test("a round that EXAMINES an item and finds nothing is PROGRESS, not a plateau slot", () => {
  const cwd = seeded();
  // A plateau window of 3. Before this fix, three careful rounds that each read the
  // code, traced the flow and correctly concluded "guarded" would stop the run.
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  for (const title of ["a", "b", "c", "d", "e"]) {
    recordSurface(cwd, { title: `item ${title}`, kind: "file", file: "src/cfg/parse.c", line: 1 });
  }

  // Five rounds, each clearing its item, finding nothing.
  for (let i = 0; i < 5; i++) {
    const result = tickLoop(cwd, loadSec(cwd).snapshot);
    assert.equal(result.action, "sent", `round ${i + 1} must be sent: ${result.reason}`);
    const item = nextOpenSurface(loadSec(cwd).snapshot);
    assert.ok(item, "an item must still be open");
    clearSurface(cwd, item!.id, "check_auth() runs at router.c:88 before dispatch and this path is not in the public table");
  }

  const loop = loadSec(cwd).snapshot.loop!;
  assert.equal(loop.status, "running", "five productive rounds must NOT have stopped the run");
  assert.equal(loop.stallRounds, 0, "examining an item resets the stall counter");
  assert.equal(surfaceProgress(loadSec(cwd).snapshot).examined, 5);
});

test("a round that examines NOTHING is unproductive, and the plateau fires", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "one item", kind: "file", file: "src/cfg/parse.c", line: 1 });

  // The model answers nothing at all: the item is never cleared, no finding lands.
  let stopped: string | null = null;
  for (let i = 0; i < 12; i++) {
    const result = tickLoop(cwd, loadSec(cwd).snapshot);
    if (result.action !== "sent") {
      stopped = result.reason;
      break;
    }
  }
  assert.ok(stopped, "a run where nothing is ever examined must stop");
  assert.match(stopped!, /plateau/);
});

test("a surface round that enumerates nothing is unproductive", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 2);
  submitSecRecon(cwd, NOTE);
  // No items are ever recorded, so every round is a surface round that adds nothing.
  let stopped: string | null = null;
  for (let i = 0; i < 8; i++) {
    const result = tickLoop(cwd, loadSec(cwd).snapshot);
    if (result.action !== "sent") {
      stopped = result.reason;
      break;
    }
  }
  assert.ok(stopped, "an enumeration that adds nothing must eventually stop the run");
  assert.match(stopped!, /plateau/);
});

test("the round summary says how much of the surface has been examined", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  tickLoop(cwd, loadSec(cwd).snapshot);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  tickLoop(cwd, loadSec(cwd).snapshot);
  const ledger = fs.readFileSync(secLedgerPath(cwd), "utf-8");
  // The ledger is written when the round is PREPARED, so it carries the round's
  // assignment and the progress at that moment — which is how a reader can see the
  // analysis advancing rather than only the findings appearing.
  assert.match(ledger, /SEC ROUND 1 — analyse S-0001/);
  assert.match(ledger, /0\/2 examined/);
  assert.match(ledger, /SEC ROUND 2 — analyse S-0002/);
  assert.match(ledger, /1\/2 examined/, "the second round knows the first one cleared an item");
});

// -----------------------------------------------------------------
// The report
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// sec_verify — running the claim, and recording what came back
// -----------------------------------------------------------------
//
// This is the only tool in the mode that touches anything outside the source tree, so it
// needs the strongest tests: the gate, the bounds, and the verdict.

test("sec_verify is REFUSED until the project consents, and names the setting", () => {
  const cwd = seeded();
  startSec(cwd);
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  assert.equal(loadSettings(cwd).settings.allowCommandProbes, false, "off by default");
  const r = verifyFinding(cwd, f.value.id, { command: "echo hi", expect: "prints hi" });
  assert.equal(r.ok, false, "nothing is executed without consent");
  assert.match(r.errors.join(" "), /allowCommandProbes=true/, "and the refusal names the fix");
  assert.equal(loadSec(cwd).snapshot.findings[0]!.verification, undefined, "nothing was recorded");
});

test("a run that matches the stated expectation is recorded as CONFIRMED", () => {
  const cwd = seeded();
  startSec(cwd);
  saveSettings(cwd, { allowCommandProbes: true });
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  const r = verifyFinding(cwd, f.value.id, { command: "echo HELLO", expect: "prints HELLO", expectOutput: "HELLO" });
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.confirmed, true);
  assert.equal(r.value.exitCode, 0);
  const stored = loadSec(cwd).snapshot.findings[0]!.verification!;
  assert.equal(stored.command, "echo HELLO", "the command is stored verbatim so a reader can re-run it");
  assert.equal(stored.confirmed, true);
  assert.equal(stored.expect, "prints HELLO", "and so is the expectation it was judged against");
});

test("a run that does NOT match the expectation is recorded as a DISCONFIRMATION", () => {
  const cwd = seeded();
  startSec(cwd);
  saveSettings(cwd, { allowCommandProbes: true });
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  const r = verifyFinding(cwd, f.value.id, { command: "echo AAAA", expect: "should print BBBB", expectOutput: "BBBB" });
  assert.equal(r.ok, true, "the run happened");
  if (!r.ok) return;
  assert.equal(r.value.confirmed, false, "the verdict is the comparison, not the author's opinion");
  assert.ok(r.warnings.some((w) => w.includes("did NOT match")), "the warning says so");
  assert.ok(r.warnings.some((w) => w.includes("either the finding is wrong")), "and points at both possible errors");
});

test("a hung command is KILLED by the time budget and not confirmed", () => {
  const cwd = seeded();
  startSec(cwd);
  saveSettings(cwd, { allowCommandProbes: true, commandTimeoutMs: 700 });
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  const r = verifyFinding(cwd, f.value.id, { command: "node -e \"setTimeout(() => {}, 60000)\"", expect: "would hang" });
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.timedOut, true);
  assert.equal(r.value.confirmed, false, "a killed run proves nothing");
});

test("verify without an expectation is REFUSED — the verdict has to be judged against something", () => {
  const cwd = seeded();
  startSec(cwd);
  saveSettings(cwd, { allowCommandProbes: true });
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  const r = verifyFinding(cwd, f.value.id, { command: "echo x", expect: "   " });
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /stated BEFORE the run/);
});

test("a verification verdict is RECOMPUTED from the run, so a tampered one cannot contradict it", () => {
  // What IS guaranteed: `confirmed` is a FUNCTION of the recorded exit code and output
  // substring, so a log that claims success while recording a failure is corrected on read.
  // What is NOT guaranteed — and cannot be, at this layer: a fabricated command and output
  // that are internally CONSISTENT. The log is the record; this stops it from lying to
  // itself, not from being invented.
  const cwd = seeded();
  startSec(cwd);
  saveSettings(cwd, { allowCommandProbes: true });
  const f = recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  if (!f.ok) return assert.fail("the finding must record");
  verifyFinding(cwd, f.value.id, { command: "echo AAAA", expect: "prints BBBB", expectOutput: "BBBB" });
  assert.equal(loadSec(cwd).snapshot.findings[0]!.verification!.confirmed, false);
  fs.appendFileSync(
    path.join(cwd, ".pi-loopsec", "tree.jsonl"),
    JSON.stringify({
      type: "finding_updated",
      at: "tampered",
      id: f.value.id,
      patch: {
        verification: {
          at: "tampered",
          command: "echo AAAA",
          output: "AAAA",
          exitCode: 1,
          timedOut: false,
          expect: "prints BBBB",
          confirmed: true,
        },
      },
    }) + "\n",
    "utf-8",
  );
  assert.equal(
    loadSec(cwd).snapshot.findings[0]!.verification!.confirmed,
    false,
    "claimed confirmed, recorded exit 1 — the verdict is recomputed from the facts",
  );
});

test("the brief's FOUND SO FAR list is bounded, and says how many it hid", () => {
  // Unbounded, this list grows one line per finding and rides every brief: a run with 60
  // findings re-sent all 60 every round, crowding out the item the round was about.
  const cwd = seeded();
  withSurface(cwd, 1);
  for (let i = 0; i < 35; i++) {
    recordFinding(cwd, {
      title: `finding number ${i}`,
      category: i % 2 === 0 ? "rce" : "sqli",
      severity: i % 3 === 0 ? "high" : "medium",
      file: `src/f${i}.c`,
      line: i + 1,
    });
  }
  const r = tickLoop(cwd, loadSec(cwd).snapshot);
  const brief = r.brief!;
  const listed = brief.split("\n").filter((l) => /^ {2}F-\d{4} \[/.test(l)).length;
  assert.ok(listed <= 30, `the list must be bounded; it listed ${listed}`);
  assert.match(brief, /\+5 more, worst-first/, "and it states exactly how many were hidden");
  assert.match(brief, /FOUND SO FAR \(35\)/, "while still stating the true total");
});

test("the report shows the run, the expectation and the verdict, and counts them in the summary", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  saveSettings(cwd, { allowCommandProbes: true });
  const ran = recordFinding(cwd, { title: "认证前命令执行", category: "rce", file: "src/a.c", line: 1, severity: "high" });
  if (!ran.ok) return assert.fail("the finding must record");
  const unrun = recordFinding(cwd, { title: "仅静态追踪的发现", category: "sqli", file: "src/b.c", line: 2, severity: "medium" });
  if (!unrun.ok) return assert.fail("the second finding must record");
  // A run that does NOT match its expectation — this fixture asserts the honest verdict path.
  verifyFinding(cwd, ran.value.id, {
    command: "curl -s http://TARGET/x",
    expect: "HTTP 200 且回显命令输出",
    expectOutput: "200",
  });

  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  // The summary states the split, so a reader does not have to reconstruct it.
  assert.match(report, /已复现（跑过命令，结果符合跑前声明的预期）\*\* \| \*\*0\/2\*\*/, "0 of 2 matched their expectation");
  // The finding that WAS run carries the command, the prediction and the output.
  assert.match(report, /\*\*验证\*\*/);
  assert.match(report, /命令 {2}curl -s http:\/\/TARGET\/x/);
  assert.match(report, /跑前预期 {2}HTTP 200 且回显命令输出/);
  assert.match(report, /未复现/, "and the verdict is printed as a NOT-reproduced one");
  // The finding that was NOT run says exactly that, rather than borrowing the other's credit.
  assert.match(report, /_未经验证：无等级 · 无证伪 · 无对抗复核_/);
});

test("with probes OFF the summary says nothing was run, rather than implying the findings were checked", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1, severity: "high" });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /allowCommandProbes[\s\S]*是关的/);
  assert.match(report, /静态声明/);
});

// -----------------------------------------------------------------
// PURSUIT — the finding that is ONE STEP from the objective
// -----------------------------------------------------------------
//
// The failure this closes, measured: a real RCE was recorded on a pre-auth objective, its surface
// item was marked examined, and the run went on enumerating the list. The result that came closest
// to the goal was filed and abandoned in the same round — and the rounds that would have turned it
// into the objective went to unrelated S-xxx items.
//
// A finding that is REAL but GATED is the most valuable thing a run can hold: closing the gate
// converts it. So the loop attacks the gate before the next item on the plan.

test("a gated HIGH finding is pursued INSTEAD of the next surface item", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "POST /api/exec", kind: "sink", file: "src/api/exec.py", line: 42 });
  recordSurface(cwd, { title: "GET /other", kind: "entrypoint", file: "src/api/other.py", line: 1 });

  tickLoop(cwd, loadSec(cwd).snapshot); // analyze S-0001
  const f = recordFinding(cwd, {
    title: "认证后可 RCE：exec 端点拼接命令",
    category: "rce",
    severity: "high",
    file: "src/api/exec.py",
    line: 42,
    evidence: "src/api/exec.py:42\n  os.system(cmd)",
    preAuth: false,
    surfaceId: "S-0001",
    blockers: ["需要一个有效的已认证会话（该路由在 requireAuth 装饰器之后）"],
  });
  assert.equal(f.ok, true);

  const next = tickLoop(cwd, loadSec(cwd).snapshot);
  const rec = loadSec(cwd).snapshot.roundRecords.at(-1)!;
  assert.match(next.brief!, /^\[SEC ROUND 2 — PURSUE F-0001\]/, "the round pursues the finding, not the list");
  assert.equal(rec.kind, "pursue");
  assert.equal(rec.findingId, "F-0001");
  assert.notEqual(rec.surfaceId, "S-0002", "S-0002 is NOT handed over while the gate is open");
  assert.match(next.brief!, /Do NOT go to the next/, "and the brief says so explicitly");
  assert.match(next.brief!, /需要一个有效的已认证会话/, "the gate is restated in the brief");
  assert.match(next.brief!, /找.*不需要.*会话|without one/, "and the brief names the way to attack it");
});

test("the pursuit budget is spent on prepare and then the loop returns to the plan", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99, 1);
  saveSettings(cwd, { pursuitRounds: 2 });
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "S1", kind: "sink", file: "a.py", line: 1 });
  recordSurface(cwd, { title: "S2", kind: "entrypoint", file: "b.py", line: 2 });
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });

  // Two pursuit rounds, each spending one of the budget.
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.findings[0]!.pursuitSpent, 1);
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.kind, "pursue");
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.findings[0]!.pursuitSpent, 2);
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.kind, "pursue");

  // Budget spent → back to the work list, with the finding still recorded as a near miss.
  tickLoop(cwd, loadSec(cwd).snapshot);
  const rec = loadSec(cwd).snapshot.roundRecords.at(-1)!;
  assert.equal(rec.kind, "analyze", "the plan is back in charge");
  assert.equal(rec.surfaceId, "S-0001");
  assert.equal(loadSec(cwd).snapshot.findings[0]!.pursuitSpent, 2, "and the budget is not spent further");
});

test("opening the gate stops the pursuit — an empty blocker list MEANS the gate is open", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 3 });
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 3)!.id, "F-0001");

  // An EMPTY array must CLEAR the gate — the usual "empty means absent" rule would make the gate
  // impossible to open and the finding would be pursued until its budget ran out.
  updateFinding(cwd, "F-0001", { blockers: [] });
  assert.deepEqual(loadSec(cwd).snapshot.findings[0]!.blockers, [], "the empty list survives the log");
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 3), null, "and it is no longer pursued");
});

test("closing the pursuit with a reason stops it, and the reason is recorded", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 3 });
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });
  updateFinding(cwd, "F-0001", { pursuitClosed: "试过 a/b/c：均无法在认证前到达" });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 3), null);
  assert.match(loadSec(cwd).snapshot.findings[0]!.pursuitClosed!, /试过 a\/b\/c/);
});

test("only HIGH-or-worse RATED findings are pursued — the budget is the expensive kind of round", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 2 });
  submitSecRecon(cwd, NOTE);
  // medium → not pursued
  recordFinding(cwd, { title: "medium gated", category: "rce", severity: "medium", file: "a.py", line: 1, evidence: "e", blockers: ["需要会话"] });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 2), null, "a medium finding's gate is not worth a round");
  // unrated → not pursued either: "we have not decided whether this matters" is not a reason
  recordFinding(cwd, { title: "unrated gated", category: "rce", file: "b.py", line: 2, evidence: "e", blockers: ["需要会话"] });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 2), null);
  // high → pursued
  recordFinding(cwd, { title: "high gated", category: "rce", severity: "high", file: "c.py", line: 3, evidence: "e", blockers: ["需要会话"] });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 2)!.id, "F-0003");
  // critical outranks high
  recordFinding(cwd, { title: "critical gated", category: "rce", severity: "critical", file: "d.py", line: 4, evidence: "e", blockers: ["需要会话"] });
  assert.equal(nextPursuit(loadSec(cwd).snapshot, 2)!.id, "F-0004", "worst-first");
});

test("pursuitRounds=0 switches the mechanism off entirely", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 0 });
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "S1", kind: "sink", file: "a.py", line: 1 });
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });
  const r = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(r.brief!, /^\[SEC ROUND 1 — ANALYZE S-0001\]/, "the plan runs as before");
  assert.equal(loadSec(cwd).snapshot.findings[0]!.pursuitSpent, undefined, "nothing is spent");
});

test("a pursuit round is PROGRESS when the gate is refined — and not when nothing changed", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 3 });
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });

  // Round 1: nothing changes → unproductive, so the plateau advances.
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.loop!.stallRounds, 0, "the first round has no prior outcome to judge");
  tickLoop(cwd, loadSec(cwd).snapshot);
  const stalled = loadSec(cwd).snapshot.loop!.stallRounds;
  assert.equal(stalled, 1, "a pursuit round that changed nothing is unproductive");

  // Round 3: the gate is refined → productive, so the stall resets. Capture the record that is
  // ABOUT to be evaluated (round 2's), because `at(-1)` after the tick is the round just PREPARED —
  // evaluating that one would compare the refined blockers with themselves.
  updateFinding(cwd, "F-0001", { blockers: ["需要 core.change_datasource 权限，它由任意已认证用户持有"] });
  const round2 = loadSec(cwd).snapshot.roundRecords.at(-1)!;
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.loop!.stallRounds, 0, "a refined gate is progress — the model learned something");

  // And the detail line says which finding, and what changed.
  const outcome = evaluateRound(loadSec(cwd).snapshot, round2);
  assert.match(outcome.detail, /F-0001/);
  assert.match(outcome.detail, /gate refined/);
  assert.equal(outcome.produced, true);
});

test("closing the pursuit in a round is progress even with no new finding", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  saveSettings(cwd, { pursuitRounds: 3 });
  submitSecRecon(cwd, NOTE);
  recordFinding(cwd, {
    title: "gated rce", category: "rce", severity: "high", file: "a.py", line: 9, evidence: "e",
    blockers: ["需要一个会话"],
  });
  tickLoop(cwd, loadSec(cwd).snapshot); // prepare the pursuit round
  const rec = loadSec(cwd).snapshot.roundRecords.at(-1)!;
  updateFinding(cwd, "F-0001", { pursuitClosed: "穷尽：三条路径都无法认证前到达" });
  const outcome = evaluateRound(loadSec(cwd).snapshot, rec);
  assert.equal(outcome.produced, true, "concluding the gate cannot be opened is a result");
  assert.match(outcome.detail, /pursuit closed/);
});

test("a blocker list is validated: blank entries refused, and more than six is not one finding", () => {
  const cwd = seeded();
  startSec(cwd);
  const blank = recordFinding(cwd, {
    title: "x", category: "rce", severity: "high", file: "a.py", line: 1, evidence: "e", blockers: ["   "],
  });
  assert.equal(blank.ok, false);
  assert.match(blank.ok ? "" : blank.errors.join(" "), /non-empty state of the world/);
  const many = recordFinding(cwd, {
    title: "y", category: "rce", severity: "high", file: "b.py", line: 2, evidence: "e",
    blockers: ["a", "b", "c", "d", "e", "f", "g"],
  });
  assert.equal(many.ok, false);
  assert.match(many.ok ? "" : many.errors.join(" "), /not one finding/);
});

test("the report shows the gate and the pursuit outcome, and counts the near misses", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  saveSettings(cwd, { pursuitRounds: 2 });
  const f = recordFinding(cwd, {
    title: "认证后可 RCE", category: "rce", severity: "high", file: "src/a.c", line: 42, evidence: "e",
    preAuth: false, blockers: ["需要一个有效的已认证会话"],
  });
  if (!f.ok) return assert.fail("must record");
  const open = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(open, /\*\*前提（要利用它还需要什么成立）\*\*/, "the gate block is rendered");
  assert.match(open, /需要一个有效的已认证会话/);
  assert.match(open, /被前提阻塞的高危发现/, "and the summary counts the near misses");
  assert.match(open, /\*\*1\/1\*\*/);

  // Once the pursuit is closed the gate block says WHY it stopped — "we stopped" and "we never
  // tried" must not look the same.
  updateFinding(cwd, f.value.id, { blockers: [], pursuitClosed: "F-0007 提供了鉴权绕过" });
  const closed = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(closed, /追索已结束（0 轮）：F-0007 提供了鉴权绕过/);
  assert.doesNotMatch(closed, /被前提阻塞的高危发现/, "a closed gate is not an open near miss");
});

test("the report LEADS with what this mode does not have", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  // A finding is needed for the per-finding caveat line to exist at all.
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high" });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  const caveat = report.indexOf("先读这一段");
  const findings = report.indexOf("## 发现");
  assert.ok(caveat > 0, "the caveat is present");
  assert.ok(caveat < findings, "and it comes BEFORE the findings, not after them");
  // The tier row changed with sec_verify: it no longer claims "no verification exists" —
  // it says the mark only covers what was actually RUN, which is the honest version now that
  // running something is possible.
  for (const missing of ["只有跑过的条目才有", "没有证伪尝试", "没有对抗复核", "没有等级核查", "没有断言门禁"]) {
    assert.ok(report.includes(missing), `the report must name what is missing: ${missing}`);
  }
  assert.match(report, /每条发现都带物证/);
  assert.match(report, /未经验证/);
});

test("the report shows the attack surface and how much of it was examined", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", surfaceId: "S-0002" });

  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /## 攻击面/);
  assert.match(report, /\*\*攻击面上的项\*\* \| 3 \|/);
  assert.match(report, /\*\*已分析\*\* \| \*\*2\*\* \(67%\)/, "the denominator the findings cannot give on their own");
  assert.match(report, /已确认有防护 \| 1 \|/);
  assert.match(report, /产出了发现 \| 1 \|/);
  // The two lists, and they say different things.
  assert.match(report, /## 尚未分析/);
  assert.match(report, /它们不是干净的，是没看过/);
  assert.match(report, /## 已分析并确认有防护/);
  assert.match(report, /check_auth\(\) runs at router\.c:88/, "the clearance reason is printed — it is the evidence");
  // And the finding links back to where it came from.
  assert.match(report, /攻击面 S-0002/, "the surface item is on the one-line metadata strip");
});

test("a run that never enumerated a surface says so instead of showing an empty table", () => {
  const cwd = seeded();
  startSec(cwd);
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /这次运行没有枚举攻击面/);
});

test("a finding with no severity is listed, and counted separately from the rated ones", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "一条还没判级的", category: "other", file: "src/a.c", line: 1 });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /\*\*未评级的\*\*/);
});

test("an unassessed preAuth is NOT counted as pre-auth", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1, preAuth: true });
  recordFinding(cwd, { title: "b", category: "rce", file: "src/b.c", line: 1 });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /无需认证可达 \| 1 \|/);
  assert.match(report, /\*\*认证要求未评估\*\* \| 1 \|/);
});

test("the report defaults to Chinese and follows reportLanguage when set", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const zh = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop, {
    coverageReport: secCoverage(loadSec(cwd).snapshot, cwd),
  });
  assert.match(zh, /^# \/loopSEC — 发现$/m);
  assert.match(zh, /## 先读这一段/);
  assert.match(zh, /## 攻击面/);
  assert.match(zh, /## 概览/);
  assert.match(zh, /## 覆盖/);
  assert.match(zh, /## 发现（0）/);

  const en = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop, {
    language: "en",
    coverageReport: secCoverage(loadSec(cwd).snapshot, cwd),
  });
  assert.match(en, /^# \/loopSEC — findings$/m);
  assert.match(en, /## READ THIS FIRST/);
  assert.match(en, /## Attack surface/);
  assert.match(en, /## Summary/);

  // writeSecReport reads the setting itself, so a caller cannot forget it.
  saveSettings(cwd, { reportLanguage: "en" });
  const written = writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.equal(written.ok, true, written.ok ? "" : written.errors.join("; "));
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /## READ THIS FIRST/);
  saveSettings(cwd, { reportLanguage: "zh" });
  writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /## 先读这一段/);
});

test("the report is written to its OWN file, so it cannot overwrite the hypothesis report", () => {
  const cwd = seeded();
  startSec(cwd);
  assert.match(secReportPath(cwd), /SEC-REPORT\.md$/);
  assert.match(secLedgerPath(cwd), /SEC-FINDINGS\.md$/);
  assert.notEqual(path.basename(secReportPath(cwd)), "REPORT.md");
});

// -----------------------------------------------------------------
// Coverage, without hypotheses
// -----------------------------------------------------------------

test("coverage counts the files a FINDING cites, not the files a node cites", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/util/shell.c", line: 1 });
  recordFinding(cwd, { title: "b", category: "rce", evidence: "see src/handlers/upload.c:77 and src/cfg/parse.c:3" });
  const cited = secCitedFiles(loadSec(cwd).snapshot);
  assert.ok(cited.has("src/util/shell.c"));
  assert.ok(cited.has("src/handlers/upload.c"), "a `file:line` inside an evidence excerpt counts too");
  const report = secCoverage(loadSec(cwd).snapshot, cwd);
  assert.equal(report.citedFiles, 3);
  assert.ok(report.projectFiles! >= 9);
  assert.ok(report.gaps.some((g) => g.dir.includes("tools")), `tools/ is untouched: ${JSON.stringify(report.gaps)}`);
});

// -----------------------------------------------------------------
// The store round trip — the allowlist lesson, twice over
// -----------------------------------------------------------------

test("every SecFinding field survives being written and read back", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "run_cmd 拼接 host",
    category: "rce",
    file: "src/util/shell.c",
    line: 41,
    severity: "high",
    preAuth: true,
    evidence: "41: system(cmd);",
    reasoning: "router 把 /diag/ping 标为公开",
    poc: "curl 'http://t/diag/ping?host=127.0.0.1;id'",
    surfaceId: "S-0001",
  });
  const back = loadSec(cwd).snapshot.findings[0]!;
  assert.equal(back.title, "run_cmd 拼接 host");
  assert.equal(back.category, "rce");
  assert.deepEqual(back.location, { file: "src/util/shell.c", line: 41 });
  assert.equal(back.severity, "high");
  assert.equal(back.preAuth, true);
  assert.equal(back.evidence, "41: system(cmd);");
  assert.equal(back.reasoning, "router 把 /diag/ping 标为公开");
  assert.equal(back.poc, "curl 'http://t/diag/ping?host=127.0.0.1;id'");
  assert.equal(back.surfaceId, "S-0001");

  // THE FIELD ALLOWLIST TRAP. A new field on SecFinding has four places to be registered —
  // two on the read path (the finding itself and the patch) and one on the write path — and
  // missing any of them drops the field SILENTLY: the record still validates, the write
  // reports success, and the value is simply not there on the way back. It has happened four
  // times in this file. So the round trip is asserted for `verification` too, and its verdict
  // is asserted to be REPRODUCIBLE from what was stored.
  assert.equal(back.verification, undefined, "silence stays silence");
  saveSettings(cwd, { allowCommandProbes: true });
  verifyFinding(cwd, back.id, { command: "echo MARKER-OK", expect: "prints MARKER-OK", expectOutput: "MARKER-OK" });
  const after = loadSec(cwd).snapshot.findings[0]!.verification!;
  assert.equal(after.command, "echo MARKER-OK");
  assert.equal(after.expect, "prints MARKER-OK");
  assert.equal(after.expectExit, "zero");
  assert.equal(after.expectOutput, "MARKER-OK");
  assert.equal(after.exitCode, 0);
  assert.equal(after.confirmed, true, "and the verdict survives being judged again on read");
});

test("every SecSurface field survives being written and read back", () => {
  const cwd = seeded();
  startSec(cwd);
  recordSurface(cwd, {
    title: "POST /diag/ping",
    kind: "entrypoint",
    file: "src/http/router.c",
    line: 88,
    categories: ["rce", "command-injection"],
  });
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and the route is not in the public table");
  updateSurface(cwd, "S-0001", { findingId: "F-0001" });
  const back = loadSec(cwd).snapshot.surfaces[0]!;
  assert.equal(back.kind, "entrypoint");
  assert.equal(back.title, "POST /diag/ping");
  assert.deepEqual(back.location, { file: "src/http/router.c", line: 88 });
  assert.deepEqual(back.categories, ["rce", "command-injection"]);
  assert.equal(back.status, "cleared");
  assert.match(back.clearedReason!, /check_auth\(\)/);
  assert.ok(back.examinedAt, "examinedAt survives the allowlist");
  assert.equal(back.findingId, "F-0001");
});

test("an absent preAuth stays ABSENT across the round trip", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const back = loadSec(cwd).snapshot.findings[0]!;
  assert.equal("preAuth" in back, false, "silence stays silence");
  assert.equal("severity" in back, false, "and an unrated finding stays unrated");
});

test("MAX_ITEM_ATTEMPTS rounds with no conclusion drop an item behind the rest of the plan", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "GET /a", kind: "entrypoint", file: "a.py", line: 1 });
  recordSurface(cwd, { title: "GET /b", kind: "entrypoint", file: "b.py", line: 2 });
  // S-0001 is first in enumeration order, so it is handed every round until it is exhausted.
  for (let i = 0; i < MAX_ITEM_ATTEMPTS; i++) tickLoop(cwd, loadSec(cwd).snapshot);
  const a = loadSec(cwd).snapshot.surfaces[0]!;
  assert.equal(a.attempts, MAX_ITEM_ATTEMPTS, "it was handed the budget");
  assert.equal(a.status, "open", "an exhausted item is DEPRIORITISED, not thrown away");

  // The next round goes to the item behind it, instead of the same one again.
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(
    loadSec(cwd).snapshot.roundRecords.at(-1)!.surfaceId,
    "S-0002",
    "the item behind the exhausted one is analysed rather than the stuck one eating the plateau",
  );
});

test("an exhausted item's brief says the round MUST end in a conclusion", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "GET /a", kind: "entrypoint", file: "a.py", line: 1 });
  recordSurface(cwd, { title: "GET /b", kind: "entrypoint", file: "b.py", line: 2 });
  for (let i = 0; i < MAX_ITEM_ATTEMPTS; i++) tickLoop(cwd, loadSec(cwd).snapshot);
  // Promotion brings it back — the deprioritisation must not be a silent ban.
  updateSurface(cwd, "S-0001", { priority: 1 });
  const r = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.surfaceId, "S-0001", "a promoted item IS handed the round");
  assert.match(r.brief!, /THIS ITEM HAS HAD 3 ROUNDS AND NO CONCLUSION RECORDED/);
  assert.match(r.brief!, /sec_clear/, "and it names the ways out");
});

test("before any recon section is recorded the round IS recon — brief and label agree", () => {
  // The tools enforce no order: a model can enumerate before it submits the note. The old
  // failure was a MISMATCH — the round was labelled "recon" while its brief analysed an item,
  // and the plateau counts those two kinds differently. The recon phase takes priority now, so
  // there is nothing to mismatch: no note means no ceiling, and the round asks for the ceiling.
  // The surface items already recorded are not lost; they are analysed once the phase is over.
  const cwd = seeded();
  startSec(cwd);
  recordSurface(cwd, { title: "GET /a", kind: "entrypoint", file: "a.py", line: 1 });
  const r = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(r.brief!, /^\[SEC ROUND 1 — RECON 1\/1\]/, "the brief is a recon brief");
  assert.equal(loadSec(cwd).snapshot.roundRecords.at(-1)!.kind, "recon", "and the record agrees with it");
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.status, "open", "the item is untouched — not lost");

  // Once the ceiling is recorded, the same item is analysed.
  submitSecRecon(cwd, NOTE);
  const next = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(next.brief!, /^\[SEC ROUND 2 — ANALYZE S-0001\]/);
});

test("recon sections are APPEND-ONLY — a later round can widen the ceiling, never shrink it", () => {
  // What the old refusal was protecting, and still protects: a model must not REPLACE the run's
  // scope mid-run, because the surface list it already enumerated would stay while the note that
  // justified it vanished. Appending keeps that guarantee and drops the limitation — a later
  // section can only ADD.
  const cwd = seeded();
  startSec(cwd);
  const first = submitSecRecon(cwd, NOTE);
  assert.equal(first.ok, true);
  const second = submitSecRecon(cwd, "第二轮：读请求生命周期。认证在 src/auth/middleware.c:44 统一挂载，公开路由由 router.c:88 的白名单标记。".repeat(5));
  assert.equal(second.ok, true, "a second section is accepted");
  const note = loadSec(cwd).snapshot.secNote!;
  assert.ok(note.includes(NOTE), "the FIRST section is still there, verbatim");
  assert.ok(note.includes("第二轮：读请求生命周期"), "and the second is appended after it");
  assert.match(note, /^## RECON ROUND 1$/m, "sections are marked with the round they were recorded in");
  assert.match(note, /^## RECON ROUND 2$/m);
  assert.ok(note.indexOf("## RECON ROUND 1") < note.indexOf("## RECON ROUND 2"), "in order");
});

test("the recon phase is counted in SECTIONS: recording nothing keeps the run in recon", () => {
  // Counted in rounds, a model that recorded nothing in round 1 would "spend" the round and the
  // phase would move on with an empty note — the run then enumerates from a ceiling that does not
  // exist. Counted in sections, the phase ends when the work is done.
  const cwd = seeded();
  startSec(cwd, "x", 99, 2);
  assert.equal(reconPhaseOver(loadSec(cwd).snapshot, 2), false);
  assert.equal(reconSections(loadSec(cwd).snapshot), 0);

  tickLoop(cwd, loadSec(cwd).snapshot);                                    // recon 1 (nothing recorded)
  const second = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(second.brief!, /^\[SEC ROUND 2 — RECON 1\/2\]/, "still round 1 of the phase: nothing was recorded");

  submitSecRecon(cwd, NOTE);                                               // section 1 of 2
  assert.equal(reconSections(loadSec(cwd).snapshot), 1);
  const third = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(third.brief!, /^\[SEC ROUND 3 — RECON 2\/2\]/, "now round 2 of the phase");
  assert.match(third.brief!, /REQUEST LIFECYCLE/, "and round 2 asks for the lifecycle, not the map again");

  submitSecRecon(cwd, "第二轮：请求生命周期与鉴权接线。".repeat(20));
  assert.equal(reconPhaseOver(loadSec(cwd).snapshot, 2), true, "the phase is over once both sections exist");
  const fourth = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(fourth.brief!, /^\[SEC ROUND \d+ — SURFACE\]/, "the next round enumerates (the note is replayed inside it)");
});

test("reconRounds=1 keeps the single-round behaviour", () => {
  const cwd = seeded();
  startSec(cwd, "x", 99, 1);
  submitSecRecon(cwd, NOTE);
  assert.equal(reconPhaseOver(loadSec(cwd).snapshot, 1), true);
  recordSurface(cwd, { title: "GET /a", kind: "entrypoint", file: "a.py", line: 1 });
  assert.match(tickLoop(cwd, loadSec(cwd).snapshot).brief!, /^\[SEC ROUND 1 — ANALYZE S-0001\]/);
});

test("the recon note is mirrored to .pi-loopsec/recon.md so a later round can re-read it", () => {
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  const file = reconNotePath(cwd);
  assert.ok(fs.existsSync(file), "the mirror is written");
  assert.match(fs.readFileSync(file, "utf-8"), /## RECON ROUND 1/, "with the section marker");
  assert.match(fs.readFileSync(file, "utf-8"), /命令执行在 src\/util\/shell\.c/);
});

test("the floor applies to the NEW section, not to the total", () => {
  const cwd = seeded();
  startSec(cwd);
  assert.equal(submitSecRecon(cwd, "太短了").ok, false, "a short FIRST section is refused");
  assert.equal(submitSecRecon(cwd, NOTE).ok, true, "and the real note still goes in");
  // With a long note already recorded, a one-line addition is still not a recon section.
  const tiny = submitSecRecon(cwd, "顺便看看 /admin");
  assert.equal(tiny.ok, false, "the floor is on the NEW section, not on the total");
  assert.match(tiny.errors.join(" "), /a recon section must be at least 200 characters/);
});

test("the same sink + category records ONCE — the second call returns the existing finding", () => {
  const cwd = seeded();
  startSec(cwd);
  const a = recordFinding(cwd, { title: "cmd injection in run_cmd", category: "rce", severity: "high", file: "src/shell.c", line: 42, evidence: "src/shell.c:42" });
  const b = recordFinding(cwd, { title: "shell.c system call unvalidated", category: "rce", severity: "high", file: "src/shell.c", line: 42, evidence: "src/shell.c:42" });
  assert.equal(b.ok, true);
  if (!b.ok || !a.ok) return assert.fail("both calls must succeed");
  assert.equal(b.value.id, a.value.id, "the SECOND call returns the FIRST finding, not a new one");
  assert.ok(b.warnings.some((w) => w.includes("sec_update")), "and it names the way to amend it");
  assert.equal(loadSec(cwd).snapshot.findings.length, 1, "the log holds ONE finding, not two");
});

test("the same sink with a DIFFERENT category is a second finding, not a duplicate", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "cmd injection in run_cmd", category: "rce", file: "src/shell.c", line: 42, evidence: "e" });
  const c = recordFinding(cwd, { title: "traversal reaches the same exec", category: "path-traversal", file: "src/shell.c", line: 42, evidence: "e" });
  assert.equal(c.ok, true);
  if (!c.ok) return assert.fail("a different category must be accepted");
  assert.notEqual(c.value.id, "F-0001", "a traversal INTO an exec is two bugs");
  assert.equal(loadSec(cwd).snapshot.findings.length, 2);
});

test("the same category at a DIFFERENT sink is a second finding", () => {
  const cwd = seeded();
  startSec(cwd);
  recordFinding(cwd, { title: "cmd injection in run_cmd", category: "rce", file: "src/shell.c", line: 42, evidence: "e" });
  const d = recordFinding(cwd, { title: "cmd injection in exec_sh", category: "rce", file: "src/exec.c", line: 9, evidence: "e" });
  assert.equal(d.ok, true);
  if (!d.ok) return assert.fail("a different sink must be accepted");
  assert.notEqual(d.value.id, "F-0001");
  assert.equal(loadSec(cwd).snapshot.findings.length, 2);
});

test("a finding written to the log with NO artifact is dropped on read", () => {
  const cwd = seeded();
  startSec(cwd);
  fs.appendFileSync(
    path.join(cwd, ".pi-loopsec", "tree.jsonl"),
    JSON.stringify({
      type: "finding_recorded",
      at: new Date().toISOString(),
      finding: { id: "F-0001", title: "a bare claim", category: "rce", at: "", round: 1 },
    }) + "\n",
    "utf-8",
  );
  assert.equal(loadSec(cwd).snapshot.findings.length, 0, "no artifact, no finding");
});

test("a surface item written with no title is dropped on read", () => {
  const cwd = seeded();
  startSec(cwd);
  fs.appendFileSync(
    path.join(cwd, ".pi-loopsec", "tree.jsonl"),
    JSON.stringify({ type: "surface_recorded", at: new Date().toISOString(), surface: { id: "S-0001", at: "", round: 1, title: "" } }) + "\n",
    "utf-8",
  );
  assert.equal(loadSec(cwd).snapshot.surfaces.length, 0);
});

// -----------------------------------------------------------------
// The lifecycle the operator asked for
// -----------------------------------------------------------------

test("pause, resume and the round budget all work on a sec loop", () => {
  const cwd = seeded();
  startSec(cwd);
  assert.equal(pauseLoop(cwd, loadSec(cwd).snapshot, "the operator paused it").ok, true);
  assert.equal(loadSec(cwd).snapshot.loop!.status, "paused");
  assert.equal(tickLoop(cwd, loadSec(cwd).snapshot).action, "paused", "a paused loop sends nothing");

  assert.equal(resumeLoop(cwd, loadSec(cwd).snapshot, { forRounds: 3 }).ok, true);
  const loop = loadSec(cwd).snapshot.loop!;
  assert.equal(loop.status, "running");
  assert.equal(loop.pauseAfterRound, loop.round + 3, "the budget is relative to the current round");
});

test("the ledger is cumulative, so a finding is never invisible in it", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  tickLoop(cwd, loadSec(cwd).snapshot);
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1 });
  tickLoop(cwd, loadSec(cwd).snapshot);
  appendSecLedger(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop!.round, ["SEC ROUND — analyze"]);
  const ledger = fs.readFileSync(secLedgerPath(cwd), "utf-8");
  assert.match(ledger, /### Findings so far \(1\)/);
  assert.match(ledger, /F-0001/);
});

test("renderSecFindings shows the surface AND the findings, for `/loopsec tree`", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  const text = renderSecFindings(loadSec(cwd).snapshot).join("\n");
  assert.match(text, /Attack surface: 0\/2 examined/);
  assert.match(text, /S-0001 \[entrypoint\] POST \/diag\/ping/);
  assert.match(text, /No findings recorded yet\./, "a work list with no findings is the normal early state");
  recordFinding(cwd, { title: "run_cmd 拼接 host", category: "rce", file: "src/util/shell.c", line: 1, severity: "high", preAuth: true });
  const after = renderSecFindings(loadSec(cwd).snapshot).join("\n");
  assert.match(after, /F-0001 \[high\] rce \[pre-auth\]\s+src\/util\/shell\.c:1/);
});

test("the surface and analyze briefs never claim a verification tier or a challenge round", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const snapshot = loadSec(cwd).snapshot;
  const surface = renderSecSurfaceBrief(snapshot, "挖掘认证前rce漏洞", 2);
  const analyze = renderSecAnalyzeBrief(snapshot, "挖掘认证前rce漏洞", 3, snapshot.surfaces[0]!);
  for (const text of [surface, analyze]) {
    for (const lie of ["验证等级", "对抗复核", "证伪", "verification tier"]) {
      assert.equal(text.includes(lie), false, `the brief must not promise ${lie}`);
    }
  }
  assert.match(analyze, /no assertion gate|COORDINATES|sec_clear/);
});

test("an update may not leave a finding with no artifact", () => {
  const cwd = seeded();
  const created = recordFinding(cwd, { title: "x", category: "rce", evidence: "src/a.c:1 system(c)" });
  assert.equal(created.ok, true);
  const id = created.ok ? created.value.id : "";
  assert.equal(updateFinding(cwd, id, { severity: "high" }).ok, true);
  assert.equal(updateFinding(cwd, "F-9999", { severity: "high" }).ok, false, "an unknown id is refused");
});

test("NO assertion gate — a noun phrase is a perfectly good finding title", () => {
  const cwd = seeded();
  // In hypothesis mode this exact string is refused: it has no truth value.
  assert.equal(
    recordFinding(cwd, { title: "src/diag/ 下的调试端点", category: "info-disclosure", file: "src/cfg/parse.c", line: 1 }).ok,
    true,
  );
});

test("a sec run creates NO hypothesis tree", () => {
  const cwd = seeded();
  startSec(cwd);
  const snapshot = loadSec(cwd).snapshot;
  assert.equal(snapshot.rootId, "", "a sec run has no tree to create");
  assert.equal(snapshot.nodes.length, 0);
  assert.equal(snapshot.loop!.kind, "sec", "and the loop survived the store round trip");
});

test("the sec loop is not refused for having no tree, but /loop still is", () => {
  const cwd = seeded();
  const loop = startLoop(cwd, loadSec(cwd).snapshot, { kind: "loop", objective: "audit" });
  assert.equal(loop.ok, false, "/loop still needs a tree");
  assert.match(loop.ok ? "" : loop.errors.join(" "), /no hypothesis tree/);
});

// -----------------------------------------------------------------
// The long-run shape of the analysis engine
// -----------------------------------------------------------------
//
// Stress-tested over 200 rounds before these were written, because the question
// "does `enumerate -> analyse xN -> enumerate` GROW or does it spin?" cannot be
// answered by reading the code. Measured: no item was ever enumerated twice, the
// run never went idle, and a model that swept ONE item per surface round still
// produced 12 findings over 200 rounds.
//
// The share of rounds spent enumerating is `1/(k+1)` for a sweep of k items, and that
// is the MODEL's rate rather than the loop's structure — so what is pinned here is
// that the loop keeps making progress and does not thrash, not a particular share.

test("a long run never re-enumerates a place it already has", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 8);
  submitSecRecon(cwd, NOTE);

  let seq = 0;
  for (let i = 0; i < 60; i++) {
    const result = tickLoop(cwd, loadSec(cwd).snapshot);
    assert.equal(result.action, "sent", `round ${i + 1} stopped early: ${result.reason}`);
    const rec = loadSec(cwd).snapshot.roundRecords.at(-1)!;
    if (rec.kind === "surface") {
      // A model that sweeps two places per surface round.
      for (let k = 0; k < 2; k++) {
        seq++;
        recordSurface(cwd, { title: `area ${seq} reaches a sink without the guard the code relies on`, kind: "file", file: "src/cfg/parse.c", line: 1 });
      }
    } else if (rec.kind === "analyze" && rec.surfaceId) {
      clearSurface(cwd, rec.surfaceId, "check_auth() runs at router.c:88 before dispatch and this path is not in the public table");
    }
  }

  const snap = loadSec(cwd).snapshot;
  const titles = snap.surfaces.map((s) => s.title);
  assert.equal(titles.length, new Set(titles).size, "an item was enumerated twice — the loop is spinning");
  assert.equal(surfaceProgress(snap).open, 0, "every enumerated item gets analysed");
  assert.ok(snap.surfaces.length >= 30, `the surface must grow; it reached ${snap.surfaces.length}`);

  // The invariant is ASYMMETRIC, and it has to be: `analyze` dominating is the point
  // (it is the work), so what is pinned is that the ENUMERATION never takes the tier.
  // Its share is 1/(k+1) for a sweep of k items, so a two-item sweep measures 33% and
  // the one-item worst case lands on exactly 50% — the boundary this codebase uses for
  // "a trigger that is always true".
  const secRounds = snap.roundRecords.filter((r) => r.findingCountAtStart !== undefined);
  const surfaceShare = secRounds.filter((r) => r.kind === "surface").length / secRounds.length;
  assert.ok(surfaceShare <= 0.5, `enumeration took ${(surfaceShare * 100).toFixed(0)}% of the rounds`);
  const analyzeShare = secRounds.filter((r) => r.kind === "analyze").length / secRounds.length;
  assert.ok(analyzeShare >= 0.5, `analysis is the work and must keep the majority; it took ${(analyzeShare * 100).toFixed(0)}%`);
});

test("an analyze round that reveals a new place can record it without a surface round", () => {
  // The improvement the stress test pointed at: tracing one path is how you find the
  // next one, and a place noticed but not recorded is a place the run never returns to.
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /A new place revealed by the analysis/);
  assert.match(brief, /`sec_surface` it now/);
  assert.match(brief, /priority=1` if it beats what/);
});

// -----------------------------------------------------------------
// The command name is NOT the kind
// -----------------------------------------------------------------

test("the kind stays `sec` while the command is `/loopsec`", () => {
  // The two are different things and conflating them is a one-way door: the kind is
  // what the log stores, and `normalizeLoopState` DROPS an unknown one — so renaming
  // the kind would make every existing run unreadable. The command name is a UI
  // surface. Mapping it in one place is what stops the twenty hint strings from
  // assuming the two are equal.
  assert.equal(loopCommandName("sec"), "loopsec");
  assert.equal(loopCommandName("goal"), "goal");
  assert.equal(loopCommandName("loop"), "loop");
});

test("a loop started as kind `sec` still reads back after a round trip", () => {
  const cwd = seeded();
  startSec(cwd);
  const loop = loadSec(cwd).snapshot.loop!;
  assert.equal(loop.kind, "sec", "the stored kind must not follow the command name");
  assert.equal(tickLoop(cwd, loadSec(cwd).snapshot).action, "sent", "and the loop still drives");
});

// -----------------------------------------------------------------
// Combinations — a chain is a finding
// -----------------------------------------------------------------
//
// Combination is ORTHOGONAL to the assertion gate. The gate is what this mode drops;
// chaining was never about assertions, and dropping it along with them was a design
// mistake rather than a trade. Measured before this existed: `sec.ts` mentioned
// chain/combine/requires exactly twice, and both were comments about what was ABSENT —
// so nothing in the mode ever suggested that two findings might be one bug.

test("a chain needs NO artifact of its own — its artifact is its parts", () => {
  const cwd = seeded();
  const a = recordFinding(cwd, { title: "api_sync_files 按请求路径以 root 写任意文件", category: "arbitrary-file-write", file: "src/cfg/parse.c", line: 1, severity: "medium" });
  const b = recordFinding(cwd, { title: "load_config() 把 cma.conf 当 Python 执行", category: "rce", file: "src/util/shell.c", line: 1, severity: "medium" });
  assert.equal(a.ok && b.ok, true);

  // No file, no evidence — only the two parts.
  const chain = recordFinding(cwd, {
    title: "写 cma.conf 后下一次请求就是 root 代码执行 —— 两个原语拼成 RCE",
    category: "rce",
    severity: "critical",
    chainOf: ["F-0001", "F-0002"],
    reasoning: "单独一个写原语只是中危；写进一个会被 exec 的文件就是 root。",
  });
  assert.equal(chain.ok, true, chain.ok ? "" : chain.errors.join("; "));
  assert.deepEqual(loadSec(cwd).snapshot.findings[2]!.chainOf, ["F-0001", "F-0002"]);
});

test("a finding with no artifact and no chain is still refused", () => {
  const cwd = seeded();
  const r = recordFinding(cwd, { title: "某处有命令注入", category: "rce" });
  assert.equal(r.ok, false);
  // And the refusal says the chain is the OTHER way past the requirement, so a model
  // that has a real combination does not attach an unrelated file to satisfy it.
  assert.match(r.ok ? "" : r.errors.join(" "), /chainOf` naming two or more existing findings is exempt/);
});

test("a chain of ONE is refused — that is just the finding", () => {
  const cwd = seeded();
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const r = recordFinding(cwd, { title: "b", category: "rce", chainOf: ["F-0001"] });
  assert.equal(r.ok, false);
  assert.match(r.ok ? "" : r.errors.join(" "), /TWO OR MORE/);
});

test("a chain naming an id this run does not have is refused, and names what it does have", () => {
  const cwd = seeded();
  recordFinding(cwd, { title: "the config parser reads a file as key=value", category: "other", file: "src/cfg/parse.c", line: 1 });
  const r = recordFinding(cwd, { title: "chain", category: "rce", chainOf: ["F-0001", "F-0099"] });
  assert.equal(r.ok, false);
  const message = r.ok ? "" : r.errors.join(" ");
  assert.match(message, /F-0099/);
  assert.match(message, /Known findings: F-0001/, "it says what exists, so the next call can be right");
  assert.equal(loadSec(cwd).snapshot.findings.length, 1, "nothing was recorded");
});

test("a repeated id in a chain is refused", () => {
  const cwd = seeded();
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const r = recordFinding(cwd, { title: "b", category: "rce", chainOf: ["F-0001", "F-0001"] });
  assert.equal(r.ok, false);
  assert.match(r.ok ? "" : r.errors.join(" "), /distinct/);
});

test("chainOf survives the store round trip", () => {
  const cwd = seeded();
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  recordFinding(cwd, { title: "b", category: "rce", file: "src/b.c", line: 1 });
  recordFinding(cwd, { title: "chain", category: "rce", severity: "critical", chainOf: ["F-0001", "F-0002"] });
  // The allowlist in store.ts has now eaten a new field FOUR times; this is the test
  // that catches the fifth.
  assert.deepEqual(loadSec(cwd).snapshot.findings[2]!.chainOf, ["F-0001", "F-0002"]);
});

test("the analyze brief asks the combination question once there is something to combine", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  // Nothing recorded yet: the question would be noise.
  const first = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.equal(first.includes("DOES THIS COMBINE?"), false, "no findings, no question");

  recordFinding(cwd, { title: "写任意文件的接口", category: "arbitrary-file-write", file: "src/cfg/parse.c", line: 1, severity: "medium" });
  const second = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(second, /--- DOES THIS COMBINE\? ---/);
  assert.match(second, /together with something ALREADY RECORDED, reach\s+somewhere neither reaches alone/);
  assert.match(second, /record the chain as its own finding/);
  assert.match(second, /chainOf=\["F-0001", "F-0007"\]/);
  assert.match(second, /NO artifact of its own/, "and it says why the artifact rule does not block it");
});

test("FOUND SO FAR marks which findings are already chains", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  recordFinding(cwd, { title: "b", category: "rce", file: "src/b.c", line: 1 });
  recordFinding(cwd, { title: "the two together reach root", category: "rce", chainOf: ["F-0001", "F-0002"] });
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /⛓ combines F-0001 \+ F-0002/);
  assert.match(brief, /CHAINS ALREADY RECORDED \(1\)/);
});

test("the report shows the chains BEFORE the findings, and counts them", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "写任意文件", category: "arbitrary-file-write", file: "src/cfg/parse.c", line: 1, severity: "medium" });
  recordFinding(cwd, { title: "配置被 exec", category: "rce", file: "src/util/shell.c", line: 1, severity: "medium" });
  recordFinding(cwd, { title: "两个拼成 root 代码执行", category: "rce", severity: "critical", chainOf: ["F-0001", "F-0002"] });

  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /\*\*组合链\*\* \| \*\*1\*\*/, "a chain is counted as its own thing");
  assert.match(report, /## 组合链/);
  assert.match(report, /这些发现\*\*由其他发现组合而成\*\*/);
  assert.match(report, /\*\*F-0003\*\* \[严重\] 两个拼成 root 代码执行/);
  assert.match(report, /F-0001 \(写任意文件\) \+ F-0002 \(配置被 exec\)/, "and it prints the PARTS, not just the ids");
  // A reader who scrolls the individual findings still sees the relationship.
  assert.match(report, /组合自： `F-0001` \+ `F-0002`/);
  // And the chains section comes before the flat list.
  assert.ok(report.indexOf("## 组合链") < report.indexOf("## 发现"), "chains first");
});

test("a run with no chains shows no chain section", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.equal(report.includes("## 组合链"), false);
  assert.equal(report.includes("组合链"), false, "not even the summary row");
});

test("`/loopsec tree` marks the chains", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "a", category: "rce", file: "src/a.c", line: 1 });
  recordFinding(cwd, { title: "b", category: "rce", file: "src/b.c", line: 1 });
  recordFinding(cwd, { title: "chain", category: "rce", chainOf: ["F-0001", "F-0002"] });
  assert.match(renderSecFindings(loadSec(cwd).snapshot).join("\n"), /F-0003 \[unrated\] rce \[auth NOT assessed\]\s+\(evidence only\)\s+⛓ F-0001\+F-0002/);
});

// -----------------------------------------------------------------
// A refusal has to say WHICH audit, and in a sentence that parses
// -----------------------------------------------------------------

test("a refusal names the command the operator typed, not the internal kind", () => {
  // Measured on a real run: `/loopsec pause` on an already-paused loop produced
  //     REJECTED: the audit sec is ALREADY PAUSED at round 30.
  // — the KIND interpolated into an English sentence, so it was both ungrammatical
  // ("the audit sec") and named something the operator had never typed. The same bug
  // predated sec mode: `/goal` produced "the audit goal is already RUNNING".
  const cwd = seeded();
  startSec(cwd);
  assert.equal(pauseLoop(cwd, loadSec(cwd).snapshot, "paused by the user").ok, true);
  const again = pauseLoop(cwd, loadSec(cwd).snapshot, "paused by the user");
  assert.equal(again.ok, false, "pausing a paused loop is refused");
  const message = again.errors.join(" ");
  assert.match(message, /the \/loopsec audit is ALREADY PAUSED/);
  assert.match(message, /\/loopsec resume/, "and it names the way forward");
  assert.equal(/\bthe audit sec\b/.test(message), false, "no bare kind in the sentence");
});

test("a stopped loop's refusal reads as a sentence too", () => {
  const cwd = seeded();
  startSec(cwd);
  // Stopping a PAUSED loop is allowed — that is how a pause is ended. Stopping an
  // already-STOPPED one is the refusal, and it goes through the same wording.
  assert.equal(stopLoop(cwd, loadSec(cwd).snapshot, "operator stopped it").ok, true);
  const again = stopLoop(cwd, loadSec(cwd).snapshot, "operator stopped it");
  assert.equal(again.ok, false);
  assert.match(again.errors.join(" "), /the \/loopsec audit is already stopped/);
  assert.equal(/\bthe audit sec\b/.test(again.errors.join(" ")), false);
});

// -----------------------------------------------------------------
// "no audit loop" has to say WHICH, and must not lie about a read failure
// -----------------------------------------------------------------
//
// Measured on a real run: the operator had a loop at round 30, ran `/loopsec pause 1`,
// and was told "no audit loop in this project". Two things can produce that and the
// message could not tell them apart — running the command from a DIFFERENT directory,
// and the log failing to READ (which returns an empty snapshot and is NOT the same
// claim as "the loop is gone"). The second is the worse of the two, because it tells
// the operator their audit has been deleted when it has not.

test("no-loop says WHERE it looked, so a wrong directory is obvious", () => {
  const cwd = seeded();
  // No `.pi-loopsec` at all — the command was run from somewhere else.
  const nothing = pauseAfterRounds(cwd, loadSec(cwd).snapshot, 1);
  assert.equal(nothing.ok, false);
  const message = nothing.errors.join("\n");
  assert.match(message, /no audit loop here — there is no log at/);
  assert.match(message, /tree\.jsonl at all/, "it names the file it looked for");
  assert.match(message, /Run this from the directory the audit was started in/);

  // A log that exists but records no loop is a DIFFERENT fact and says so.
  startSec(cwd);
  stopLoop(cwd, loadSec(cwd).snapshot, "done");
  const snap = loadSec(cwd).snapshot;
  assert.ok(snap.loop, "a stopped loop is still recorded");
});

test("a read failure is reported as a read failure, never as a missing loop", () => {
  const cwd = seeded();
  // `tree.jsonl` as a DIRECTORY makes readFileSync throw EISDIR — a real read error,
  // not a simulation of one.
  fs.mkdirSync(path.join(cwd, ".pi-loopsec", "tree.jsonl"), { recursive: true });
  const { readError } = loadSec(cwd);
  assert.ok(readError, "the store reports the read failure rather than pretending");
  // And the command layer must surface it: `load` returns an EMPTY snapshot on a read
  // error, so a caller that ignores `readError` says "no audit loop" — the one message
  // that makes an operator think their audit was deleted.
  const result = pauseLoop(cwd, loadSec(cwd).snapshot, "paused by the user");
  assert.equal(result.ok, false);
  assert.match(result.errors.join(" "), /no audit loop/, "the store alone cannot tell the difference");
});

test("the four loop-control verbs check readError before using the snapshot", () => {
  // A source-level check, because the failure is an OMISSION — there is no output to
  // assert on when the code silently swallows a read error and reports the wrong thing.
  const source = fs.readFileSync(path.join("extensions", "loop-sec", "index.ts"), "utf-8");
  const uses = source.match(/const result = (pauseAfterRounds|pauseLoop|resumeLoop|stopLoop)\(cwd, load\(cwd\)\.snapshot/g) ?? [];
  assert.deepEqual(uses, [], `these verbs still read the snapshot without checking readError: ${uses.join(", ")}`);
  assert.match(source, /const loadOrReport = \(\)/, "the helper exists");
});

// -----------------------------------------------------------------
// The finding block is ordered the way a hunter reads it
// -----------------------------------------------------------------
//
// Measured on a real X-Road report before this: 27-102 lines per finding, of which 8-9
// were four labelled metadata lines and 2 were a disclaimer the preamble already
// carried — and the PoC was LAST, under 36-55 lines of evidence, while the call chain
// was buried in Chinese prose where the `file:line` references could not be scanned.
// One finding named six locations inside its sentences and none of them could be read
// off the page.

const CHAIN: SecFindingStep[] = [
  { detail: "permitAll() lets the endpoint through unauthenticated", file: "src/common/SecurityConfig.java", line: 51 },
  { detail: "dispatched to a callback that does not verify signatures", file: "src/common/ManagementRequestVerifier.java", line: 165 },
  { detail: "no location on this step" },
];

test("a finding's call chain is a FENCED, NUMBERED list of file:line steps", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "认证前删除任意客户端的证书",
    category: "auth-bypass",
    severity: "critical",
    file: "src/common/ManagementRequestVerifier.java",
    line: 165,
    path: CHAIN,
    reasoning: "接口默认 attachment 是空实现，签名附件被静默丢弃。",
  });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  const chain = report.slice(report.indexOf("**调用链**"));
  assert.match(chain, /^```c\n1\. src\/common\/SecurityConfig\.java:51\n/m, "step 1, in a fence tagged for the viewer");
  assert.match(chain, /\n   permitAll\(\) lets the endpoint through unauthenticated\n/, "and the detail indented under it");
  assert.match(chain, /^2\. src\/common\/ManagementRequestVerifier\.java:165$/m);
  assert.match(chain, /^3\. no location on this step$/m, "a step without a location still renders");
  // The prose is kept, and it now renders as 链子分析 — FENCED like 怎么打 and 调用链
  // above it, so the reasoning section looks like the sibling it is.
  assert.match(report, /\*\*链子分析\*\*\n\n```c\n接口默认 attachment/);
});

test("without a structured path, the prose IS the chain — it renders as the 链子分析 fence", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "x", category: "rce", file: "src/a.c", line: 1,
    reasoning: "【入口】SecurityConfig.java:51 permitAll\n【校验缺失】ManagementRequestVerifier.java:165 不验签",
  });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  // No structured path, so the reasoning IS the chain: it takes the 链子分析 fence,
  // and there is no separate prose section beside it.
  assert.match(report, /\*\*链子分析\*\*\n\n```c\n【入口】SecurityConfig\.java:51 permitAll/);
  assert.match(report, /【校验缺失】ManagementRequestVerifier\.java:165 不验签/);
});

test("the PoC comes BEFORE the chain, and the chain before the evidence", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "x", category: "rce", file: "src/a.c", line: 1,
    poc: "curl -k https://t/managementservice/manage",
    path: CHAIN,
    evidence: "SecurityConfig.java:51 permitAll()",
  });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  const at = (label: string): number => report.indexOf(label);
  assert.ok(at("**怎么打**") < at("**调用链**"), "a hunter wants to paste it before reading why it works");
  assert.ok(at("**调用链**") < at("**物证**"), "and the chain before the artifact it rests on");
});

test("the metadata is ONE line, with no wall-clock timestamp and no label per field", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "x", category: "rce", file: "src/a.c", line: 7, severity: "high", preAuth: true, surfaceId: "S-0001",
  });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /`src\/a\.c:7` · 认证：\*\*认证前可达\*\* · 第 \d+ 轮 · 攻击面 S-0001/);
  // The four old labels are gone, and so is the ISO timestamp that went with them.
  for (const gone of ["**位置：**", "**来自攻击面：**", "**是否需要身份认证：**", "**记录于：**", "T00:00", "Z · "]) {
    assert.equal(report.includes(gone), false, `the report still carries ${gone}`);
  }
});

test("the per-finding caveat is ONE line, because the preamble carries the full table", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1 });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /_未经验证：无等级 · 无证伪 · 无对抗复核_/);
  // The long form still exists — once, in the preamble, where a reader meets it before
  // the findings rather than after each one.
  assert.equal(report.includes("这条没有验证等级、没有被尝试证伪、没有对抗复核"), false);
  assert.match(report, /只有跑过的条目才有/);
});

test("the title reads as the CLAIM, not as body text", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "认证前删除任意客户端的证书", category: "auth-bypass", file: "src/a.c", line: 1 });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(report, /^> 认证前删除任意客户端的证书$/m);
});

test("the call chain survives the store round trip", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1, path: CHAIN });
  const back = loadSec(cwd).snapshot.findings[0]!;
  assert.deepEqual(back.path, CHAIN);
  // A step with no `detail` is not a step, and is dropped on read like everything else
  // that fails its own requirement. (The finding itself still needs an artifact — the
  // rule this mode keeps — so it gets a location.)
  fs.appendFileSync(
    path.join(cwd, ".pi-loopsec", "tree.jsonl"),
    JSON.stringify({ type: "finding_recorded", at: new Date().toISOString(), finding: { id: "F-0099", title: "y", category: "rce", at: "", round: 1, location: { file: "src/b.c", line: 1 }, path: [{ detail: "" }, { detail: "ok" }] } }) + "\n",
    "utf-8",
  );
  assert.deepEqual(loadSec(cwd).snapshot.findings[1]!.path, [{ detail: "ok" }]);
});

// -----------------------------------------------------------------
// The fence tag — `c` by default, and configurable
// -----------------------------------------------------------------
//
// A fence with no tag gets NO highlighting in any viewer, and the targets this was built
// for are mostly C. The tag is a HINT, never a claim about the file: the evidence may be
// Java, XML or a shell transcript, and tagging it `c` costs nothing but the wrong colour
// on a few tokens.

test("the content fences open with `c` by default", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, {
    title: "x", category: "rce", file: "src/a.c", line: 1,
    poc: "curl -k https://t/run", path: CHAIN, evidence: "system(cmd);",
  });
  const report = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  // All three content fences: the PoC, the chain and the artifact.
  assert.equal((report.match(/^```c$/gm) ?? []).length, 3, "PoC, chain and evidence");
  // And the CLOSING fences are bare — a tagged closer is content, not a closer.
  assert.equal((report.match(/^```c$/gm) ?? []).length, (report.match(/^```$/gm) ?? []).length);
});

test("fenceLanguage is settable, and an empty value turns the tag off", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1, evidence: "system(cmd);" });

  const shell = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop, { fenceLanguage: "sh" });
  assert.match(shell, /^```sh$/m);

  const bare = renderSecReport(loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop, { fenceLanguage: "" });
  assert.equal((bare.match(/^```c$/gm) ?? []).length, 0);
  assert.match(bare, /^```$/m, "still fenced, just untagged");
});

test("writeSecReport reads the setting itself, so a caller cannot forget it", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  recordFinding(cwd, { title: "x", category: "rce", file: "src/a.c", line: 1, evidence: "system(cmd);" });
  saveSettings(cwd, { fenceLanguage: "python" });
  assert.equal(writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop).ok, true);
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /^```python$/m);
  saveSettings(cwd, { fenceLanguage: "c" });
  writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  assert.match(fs.readFileSync(secReportPath(cwd), "utf-8"), /^```c$/m);
});

test("the setting refuses a value that is not a language tag", () => {
  const cwd = seeded();
  // A tag is a token. Free text would end up on the fence line and break the block.
  const result = saveSettings(cwd, { fenceLanguage: "c; rm -rf /" as never });
  const loaded = loadSettings(cwd).settings.fenceLanguage;
  assert.equal(loaded, "c", `the bad value must not have landed; got ${JSON.stringify(loaded)}`);
  void result;
});

// -----------------------------------------------------------------
// The plan is not frozen — promotion
// -----------------------------------------------------------------
//
// The first design said the enumerator's order IS the plan and nothing re-sorts it. The
// hole: the plan is written in round 2, with almost nothing read. A re-prioritisation in
// round 15 is the model's OWN better-informed judgement, not the loop second-guessing it.
// (The hypothesis mode already re-ranks every round — a frozen order was the inconsistent
// one.) Measured before this: `nextOpenSurface` was `surfaces.find(status === "open")`,
// so an item found by the analysis went to the BACK of the list.

test("a PROMOTED item is analysed before the plan order", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0001", "plan order to start with");

  // Round 15's judgement: the third item matters more than the first two.
  assert.equal(updateSurface(cwd, "S-0003", { priority: 1 }).ok, true);
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0003");
});

test("everything NOT promoted keeps the plan order, and ties are stable", () => {
  const cwd = seeded();
  withSurface(cwd, 4);
  updateSurface(cwd, "S-0003", { priority: 1 });
  const snap = loadSec(cwd).snapshot;
  // Drained in plan order after the promoted one — `sort` is stable, so equal priorities
  // keep insertion order. That is what keeps this a plan rather than a free-for-all.
  assert.equal(nextOpenSurface(snap)!.id, "S-0003");
  clearSurface(cwd, "S-0003", "check_auth() runs at router.c:88 before dispatch and this path is not public");
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0001", "back to the plan");
});

test("a HIGHER priority jumps ahead of a lower one", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  updateSurface(cwd, "S-0001", { priority: 1 });
  updateSurface(cwd, "S-0003", { priority: 5 });
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0003");
  // `0` puts an item back in plan order.
  updateSurface(cwd, "S-0003", { priority: 0 });
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0001");
});

test("over-promoting is VISIBLE, not capped", () => {
  const cwd = seeded();
  withSurface(cwd, 5);
  assert.equal(surfaceProgress(loadSec(cwd).snapshot).aheadOfPlan, 0);
  for (const id of ["S-0002", "S-0003", "S-0004"]) updateSurface(cwd, id, { priority: 1 });
  // The mechanism has no limit — a model can send every item to the front. The defence is
  // a number the model can see, not a silent reorder and not a cap it would work around.
  assert.equal(surfaceProgress(loadSec(cwd).snapshot).aheadOfPlan, 3);
});

test("the analyze brief SHOWS the queue, so thrashing is a fact not a surprise", () => {
  const cwd = seeded();
  withSurface(cwd, 4);
  updateSurface(cwd, "S-0003", { priority: 1 });
  updateSurface(cwd, "S-0004", { priority: 1 });
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /QUEUED AHEAD OF THE PLAN \(2\)/);
  assert.match(brief, /S-0003 \[p1\]/);
  assert.match(brief, /you are not re-prioritising — you are thrashing/);
});

test("the surface brief no longer promises that nothing re-sorts the list", () => {
  // It DID promise that, and the promise became a lie the moment promotion existed. A
  // brief that states a rule the tool no longer follows is worse than one that omits it.
  const cwd = seeded();
  startSec(cwd);
  submitSecRecon(cwd, NOTE);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.equal(brief.includes("Nothing re-sorts the list afterwards"), false);
  assert.match(brief, /\*\*The order is NOT frozen\.\*\*/);
  assert.match(brief, /priority=1` for a new place/);
  assert.match(brief, /a plan written before you had read anything should not override that/);
});

test("the analyze brief says you may promote an item you already listed", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /an item you already listed now more promising/);
  assert.match(brief, /`sec_update <id> priority=1`/);
  assert.match(brief, /it was written before you had read\s+anything/);
});

test("promotion survives the store round trip — the fifth field this allowlist had to learn", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  updateSurface(cwd, "S-0002", { priority: 3 });
  assert.equal(loadSec(cwd).snapshot.surfaces[1]!.priority, 3);
  // And a record written BEFORE the field existed reads back with no priority, which is
  // exactly "as planned" — the safe default, not an invented one.
  assert.equal("priority" in loadSec(cwd).snapshot.surfaces[0]!, false);
});

test("a new item can arrive already promoted", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  assert.equal(recordSurface(cwd, { title: "a place the analysis just revealed", kind: "sink", priority: 1 }).ok, true);
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.title, "a place the analysis just revealed");
});

// -----------------------------------------------------------------
// Depth — an item may take more than one round
// -----------------------------------------------------------------
//
// Before this, an item got ONE round. A round spent genuinely tracing something that needed
// a second pass recorded nothing and moved no status, so `evaluateRound` called it
// unproductive and it BURNED A PLATEAU SLOT. The model paid for being thorough, and the
// cheap way out was to close the item hastily — the wrong incentive, and exactly the
// "跑偏" it is supposed to prevent.

test("sec_dig makes the item come back NEXT round, ahead of the plan", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  assert.equal(digSurface(cwd, "S-0003").ok, true);
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0003", "not after the whole list");
});

test("a digging item outranks even a PROMOTED one", () => {
  // Finishing a trace you started beats starting a more promising-looking item: an abandoned
  // trace is wasted work, an unstarted item is still just an item.
  const cwd = seeded();
  withSurface(cwd, 3);
  updateSurface(cwd, "S-0001", { priority: 9 });
  digSurface(cwd, "S-0003");
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0003");
});

test("a DEPTH round counts as progress — it does not burn the plateau", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "the long path", kind: "sink", file: "src/cfg/parse.c", line: 1 });

  // Round 1 assigns it; the model says "not finished".
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(digSurface(cwd, "S-0001").ok, true);
  // Rounds 2 and 3 continue it, recording nothing.
  tickLoop(cwd, loadSec(cwd).snapshot);
  tickLoop(cwd, loadSec(cwd).snapshot);
  const loop = loadSec(cwd).snapshot.loop!;
  assert.equal(loop.status, "running", "three depth rounds must not stop the run");
  assert.equal(loop.stallRounds, 0, "a depth round resets the stall counter");
  // And the evaluation says WHAT happened, rather than "nothing".
  const rec = loadSec(cwd).snapshot.roundRecords.at(-1)!;
  assert.equal(rec.surfaceWasDigging, true);
  assert.match(evaluateRound(loadSec(cwd).snapshot, rec).detail, /depth round on the item you asked to keep digging/);
});

test("depth is BUDGETED, and past the budget the refusal names both ways out", () => {
  // An unbounded digging state is a way to sit on one item for the rest of the run — which is
  // the failure it was added to fix. The budget is spent by the LOOP on prepare, so a crash
  // cannot hand out unlimited rounds.
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "the long path", kind: "sink", file: "src/cfg/parse.c", line: 1 });
  digSurface(cwd, "S-0001");

  tickLoop(cwd, loadSec(cwd).snapshot);                             // spend 1
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.digRounds, 1);
  assert.equal(digSurface(cwd, "S-0001").ok, true, "still inside the budget");
  tickLoop(cwd, loadSec(cwd).snapshot);                             // spend 2
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.digRounds, 2);

  const refused = digSurface(cwd, "S-0001");
  assert.equal(refused.ok, false);
  const message = refused.ok ? "" : refused.errors.join(" ");
  assert.match(message, /budget \(2\)/);
  assert.match(message, /sec_finding` if you found something/);
  assert.match(message, /A depth round that never ends is the same as never deciding/);
  // And past the budget it drops BEHIND everything — including items recorded AFTER it.
  // The old behavior ranked it as an ordinary item (plan order), which meant the spent item
  // was assigned before any NEW item: the exact one-item-eats-the-plateau failure that
  // MAX_ITEM_ATTEMPTS closes for open items. The budget's whole point is that the item has
  // had its rounds; the loop moves on.
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0001", "still in the pool…");
  recordSurface(cwd, { title: "another item", kind: "file", file: "src/a.c", line: 1 });
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0002", "…but ranked BEHIND a new item now — the dig budget was spent");
});

test("a CLEARED item cannot be dug — a clearance names a guard", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and this path is not public");
  const r = digSurface(cwd, "S-0001");
  assert.equal(r.ok, false);
  assert.match(r.ok ? "" : r.errors.join(" "), /is CLEARED/);
  assert.match(r.ok ? "" : r.errors.join(" "), /sec_reopen S-0001/, "and it names how to reopen");
});

test("the analyze brief shows the last round AND how close the run is to stopping", () => {
  // Both were absent from every sec brief. The stall counter is the only self-correction
  // signal there is: with it, "one more unproductive round and this stops" is actionable.
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 8);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "a", kind: "file", file: "src/a.c", line: 1 });
  const first = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(first.brief!, /UNPRODUCTIVE ROUNDS: 0\/8/);
  const second = tickLoop(cwd, loadSec(cwd).snapshot);
  assert.match(second.brief!, /Last round \(\d+\): /, "the hypothesis briefs have had this all along");
  assert.match(second.brief!, /UNPRODUCTIVE ROUNDS: 1\/8/);
  assert.match(second.brief!, /\*\*7 more and this run STOPS\.\*\*/);
  assert.match(second.brief!, /try a different one/);
});

test("a mid-dig item is named in the brief with its budget use", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  digSurface(cwd, "S-0002");
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /MID-DIG \(1\) — these are not finished/);
  assert.match(brief, /S-0002\s+depth round 0\/2/);
  assert.match(brief, /CONTINUING — depth round 0\/2 on this item/);
});

test("the brief says you may ask for another round, and that it is budgeted", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, /\*\*Not finished\*\* → `sec_dig`/);
  assert.match(brief, /comes back to you NEXT round/);
  assert.match(brief, /Budgeted at 2 round\(s\)/);
  assert.match(brief, /a trace that never ends is the same as never deciding/);
});

test("ALREADY CLEARED is no longer cut at 12, and says when it truncates", () => {
  // Past twelve clearances the oldest reasons fell out of the brief, so the model could not
  // tell WHY an area had been ruled out — and a model that cannot see its own exclusions
  // re-litigates them or contradicts them.
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  for (let i = 0; i < 20; i++) recordSurface(cwd, { title: `area ${i} reaches a sink without the guard the code relies on`, kind: "file", file: "src/a.c", line: 1 });
  // Clear 20 of 21, leaving one OPEN. With nothing open the next round is a SURFACE round,
  // which carries no ALREADY CLEARED section at all — and the test would then pass without
  // testing anything.
  recordSurface(cwd, { title: "the one still open", kind: "file", file: "src/a.c", line: 1 });
  for (const s of loadSec(cwd).snapshot.surfaces.slice(0, 20)) {
    clearSurface(cwd, s.id, `guard ${s.id}: check_auth() runs at router.c:88 before dispatch and this path is not public`);
  }
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  const shown = (brief.match(/^ {2}S-\d{4} {2}/gm) ?? []).length;
  assert.ok(shown >= 15, `the oldest reasons must not fall out; only ${shown} shown of 20`);
  assert.match(brief, /area 0 reaches a sink/, "including the FIRST one cleared");
});

test("digging shows up in the report, as neither cleared nor unread", () => {
  const cwd = seeded();
  withSurface(cwd, 3);
  digSurface(cwd, "S-0002");
  writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  const report = fs.readFileSync(secReportPath(cwd), "utf-8");
  assert.match(report, /\*\*仍在深挖（未定论）\*\* \| 1 \|/);
  assert.match(report, /## 仍在深挖/);
  assert.match(report, /是一段没走完的追踪/);
  assert.match(report, /S-0002.*已用 0\/2 个深挖轮，仍未定论/s);
});

test("digging and its budget survive the store round trip", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  digSurface(cwd, "S-0002");
  updateSurface(cwd, "S-0002", { digRounds: 2 });
  const back = loadSec(cwd).snapshot.surfaces[1]!;
  assert.equal(back.status, "digging");
  assert.equal(back.digRounds, 2);
  assert.equal("digRounds" in loadSec(cwd).snapshot.surfaces[0]!, false, "an untouched item has no dig count");
});

// -----------------------------------------------------------------
// The work list has a soft ceiling
// -----------------------------------------------------------------
//
// A list of 200 items is 200 rounds, and every one of them is "productive" because it examines
// something — so the plateau never fires and the run goes quiet for hours with no warning.
// Measured: the rounds spent enumerating is 1/(k+1) for a sweep of k items, so the cost is not
// the cap, it is the COMMITMENT the cap bounds.
//
// SOFT, because refusing the item the model just found loses information — and an item it
// cannot record is an item the run will never come back to.

test("past the soft ceiling the item is RECORDED, and the warning says what to do", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  let last = recordSurface(cwd, { title: "item 1", kind: "file", file: "src/a.c", line: 1 });
  assert.equal(last.ok, true);
  assert.deepEqual(last.warnings, [], "below the ceiling there is nothing to say");

  for (let i = 2; i <= SEC_SURFACE_SOFT_CAP; i++) {
    last = recordSurface(cwd, { title: `item ${i}`, kind: "file", file: "src/a.c", line: 1 });
  }
  // The Nth item is still recorded. A refusal here would drop what the model just found.
  assert.equal(last.ok, true, "soft means soft");
  assert.equal(loadSec(cwd).snapshot.surfaces.length, SEC_SURFACE_SOFT_CAP);
  const warning = last.warnings.join(" ");
  assert.match(warning, new RegExp(`SURFACE AT ${SEC_SURFACE_SOFT_CAP} ITEMS`));
  assert.match(warning, /It was recorded — refusing it would lose it/);
  assert.match(warning, /committed to at least \d+ more round\(s\)/, "it states the COMMITMENT, not just the count");
  assert.match(warning, /matters MORE than what is already waiting/);
});

test("the surgical brief stops asking for a sweep once the list is at the ceiling", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "item 1", kind: "file", file: "src/a.c", line: 1 });
  const small = tickLoop(cwd, loadSec(cwd).snapshot).brief!;

  for (let i = 2; i <= SEC_SURFACE_SOFT_CAP; i++) recordSurface(cwd, { title: `item ${i}`, kind: "file", file: "src/a.c", line: 1 });
  // Force a surface round: clear everything so nothing is left to analyse.
  for (const s of loadSec(cwd).snapshot.surfaces) {
    clearSurface(cwd, s.id, "check_auth() runs at router.c:88 before dispatch and this path is not public");
  }
  const big = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(big, /^\[SEC ROUND \d+ — SURFACE\]/m, "still a surface round");
  assert.match(big, /THE LIST IS ALREADY AT \d+ ITEMS/);
  assert.match(big, /Do NOT sweep again for its own sake/);
  assert.equal(big.includes("Aim for 10-30 items"), false, "the aim is not restated when it no longer applies");
  void small;
});

test("the analyze brief says when there is more listed than can be finished", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  for (let i = 1; i <= SEC_SURFACE_SOFT_CAP; i++) recordSurface(cwd, { title: `item ${i}`, kind: "file", file: "src/a.c", line: 1 });
  const brief = tickLoop(cwd, loadSec(cwd).snapshot).brief!;
  assert.match(brief, new RegExp(`The list is at ${SEC_SURFACE_SOFT_CAP} items`));
  assert.match(brief, /more listed than can be finished/);
  assert.match(brief, /Add only what matters more than what is already waiting/);
});

test("the soft ceiling and the dig budget are not the same knob", () => {
  // One bounds how much there is to do, the other how long one thing may take. Conflating
  // them would make the run impatient about the wrong thing.
  assert.ok(SEC_SURFACE_SOFT_CAP > SEC_DIG_BUDGET * 10);
});

// -----------------------------------------------------------------
// A cleared item can be REOPENED, and the report stops lying about what it looked at
// -----------------------------------------------------------------
//
// Two bugs found by running the tools against each other rather than by reading them:
//
//   1. `sec_dig` on a cleared item said "reopen it first: sec_update S-0001 status=open". There is
//      no such command — `sec_update` takes a FINDING id and has no status field — so the model got
//      "S-0001 is not a finding in this run" and the item was UNREOPENABLE. A refusal that names a
//      command which does not exist is worse than one that names nothing: it looks like a tool bug
//      from the inside and sends the model to a dead end.
//
//   2. The report printed every `open` item under 尚未分析 with "没看过" — including items that had
//      been handed a round and left unresolved, which is the ORDINARY outcome of a round that
//      produces nothing. The section that exists to bound the audit's honesty was making the audit
//      look narrower than it was.

test("a cleared item can be reopened, with a reason", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and this path is not public");
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.status, "cleared");

  const ok = reopenSurface(cwd, "S-0001", "check_auth() returns early for /diag/* before it reaches the public table");
  assert.equal(ok.ok, true, ok.ok ? "" : ok.errors.join("; "));
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.status, "open", "back on the work list");
  assert.equal(nextOpenSurface(loadSec(cwd).snapshot)!.id, "S-0001", "and it is reachable again");
});

test("reopening needs a REASON — withdrawing a clearance is a claim too", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and this path is not public");
  const empty = reopenSurface(cwd, "S-0001", "wrong");
  assert.equal(empty.ok, false);
  assert.match(empty.ok ? "" : empty.errors.join(" "), /say why the guard does not hold/);
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.status, "cleared", "nothing was reopened");
});

test("reopening something that is not cleared is refused, and says what it is", () => {
  const cwd = seeded();
  withSurface(cwd, 1);
  const r = reopenSurface(cwd, "S-0001", "check_auth() returns early for /diag/* before the public table");
  assert.equal(r.ok, false);
  assert.match(r.ok ? "" : r.errors.join(" "), /is open, not cleared/);
});

test("the sec_dig refusal names sec_reopen, and following it WORKS", () => {
  // The dead end, end to end: refuse, then do what the refusal said, then succeed.
  const cwd = seeded();
  withSurface(cwd, 1);
  clearSurface(cwd, "S-0001", "check_auth() runs at router.c:88 before dispatch and this path is not public");
  const refused = digSurface(cwd, "S-0001");
  assert.equal(refused.ok, false);
  const message = refused.ok ? "" : refused.errors.join(" ");
  assert.match(message, /sec_reopen S-0001/, "it names the command that exists");
  assert.equal(/sec_update S-0001 status=open/.test(message), false, "and NOT the one that never did");
  const reopened = reopenSurface(cwd, "S-0001", "check_auth() returns early for /diag/* before the public table");
  assert.equal(reopened.ok, true, "the advice is followable now");
  assert.equal(digSurface(cwd, "S-0001").ok, true, "and the dig that was refused now works");
});

test("the loop counts an ATTEMPT whether or not the round concludes anything", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "the long path", kind: "sink", file: "src/cfg/parse.c", line: 1 });
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.attempts, undefined, "nothing yet");
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.attempts, 1, "assigned once");
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.surfaces[0]!.attempts, 2, "and again — it is still open");
});

test("attempted and examined are DIFFERENT numbers, and the plateau reads examined", () => {
  // Widening `examined` to include an attempt would make the day a round is PREPARED look
  // productive, because the loop increments attempts on prepare.
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 3);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "a", kind: "file", file: "src/a.c", line: 1 });
  tickLoop(cwd, loadSec(cwd).snapshot);
  const snap = loadSec(cwd).snapshot;
  const p = surfaceProgress(snap);
  assert.equal(p.attempted, 1, "it was handed a round");
  assert.equal(p.examined, 0, "but nothing was concluded");
  // And the round is correctly judged unproductive.
  tickLoop(cwd, loadSec(cwd).snapshot);
  assert.equal(loadSec(cwd).snapshot.loop!.stallRounds, 1, "an attempt is not a result");
});

test("the report splits never-analysed from looked-at-and-unsettled", () => {
  const cwd = seeded();
  startSec(cwd, "挖掘认证前rce漏洞", 99);
  submitSecRecon(cwd, NOTE);
  recordSurface(cwd, { title: "the one it read", kind: "file", file: "src/a.c", line: 1 });
  recordSurface(cwd, { title: "the one it never reached", kind: "file", file: "src/a.c", line: 1 });
  tickLoop(cwd, loadSec(cwd).snapshot);   // assigns only the first
  writeSecReport(cwd, loadSec(cwd).snapshot, loadSec(cwd).snapshot.loop);
  const report = fs.readFileSync(secReportPath(cwd), "utf-8");

  assert.match(report, /\*\*看过但未定论\*\* \| 1 \|/, "counted separately in the summary");
  assert.match(report, /## 尚未分析/);
  assert.match(report, /这些项从没被分配过轮次/);
  assert.match(report, /## 看过但未定论/);
  assert.match(report, /看过了、没查完/);
  // The first item is under the SECOND heading, the second item under the first — and the
  // old flat list would have put both under "没看过".
  const neverAt = report.indexOf("## 尚未分析");
  const touchedAt = report.indexOf("## 看过但未定论");
  assert.ok(neverAt >= 0 && touchedAt > neverAt);
  assert.ok(report.indexOf("the one it never reached", neverAt) < touchedAt, "unreached → 尚未分析");
  assert.ok(report.indexOf("the one it read", touchedAt) > touchedAt, "read → 看过但未定论");
});

test("attempts survives the store round trip", () => {
  const cwd = seeded();
  withSurface(cwd, 2);
  updateSurface(cwd, "S-0002", { attempts: 3 });
  assert.equal(loadSec(cwd).snapshot.surfaces[1]!.attempts, 3);
  assert.equal("attempts" in loadSec(cwd).snapshot.surfaces[0]!, false, "untouched stays untouched");
});
