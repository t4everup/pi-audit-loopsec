/**
 * pi-audit-loopsec — extensions/loop-sec/index.ts
 *
 * The extension entry: ONE command, ONE tool surface, ONE round driver.
 *
 * `/loopsec` — the triage mode. State lives in `.pi-loopsec/`; the record is a
 * list of findings, not a tree of assertions. The hypothesis modes (/goal,
 * /loop, /hypothesis) and their tools were removed together: an extension whose
 * surface lists modes it no longer drives is how a model starts a run that
 * nothing will evaluate.
 *
 * What survived from the hypothesis engine is exactly what a sec run needs:
 * the append-only event log and its fold (store.ts), the loop state machine
 * (loop.ts), operator notes, settings, coverage walking, the fence-tagged
 * report text, and the brief assembly. Everything that spoke about hypotheses
 * — scheduler, tree, combination, render, the .md report — was deleted with
 * the modes that read it.
 */
import * as fs from "node:fs";
import * as path from "node:path";

import { type ExtensionAPI, type ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import { HYPOTHESIS_CATEGORIES, clip, loopCommandName, type AuditLoopKind, type TreeSnapshot } from "./types.js";
import { load } from "./store.js";
import {
  RUNS_DIR_NAME,
  SEC_STATE_DIR_NAME,
  type LoadResult,
  findRun,
  listRuns,
  loadSec,
  nextRunName,
  readActiveRun,
  readTurnClaim,
  secBaseDir,
  secTreeLogPath,
  loadSecIn,
  setActiveRun,
} from "./store.js";
import {
  loopLogPath,
  parkOnSendFailure,
  pauseLoop,
  pauseAfterRounds,
  dismissLoop,
  showLoop,
  renderLoopStatus,
  renderWidget,
  resumeLoop,
  advanceRuns,
  startDeepRun,
  endDeepRun,
  startLoop,
  stopLoop,
  tickLoop,
  type TickResult,
  reportLanguageOf,
} from "./loop.js";
import {
  renderSecFindings,
  secCoverage,
  secLedgerPath,
  writeSecReport,
} from "./sec.js";
import { coverageHeadline } from "./coverage.js";
import { appendNote, operatorNotePath, renderOperatorSummary, writeOperatorMirror } from "./notes.js";
import { registerSecTools } from "./tools.js";
import { loadSettings, saveSettings, settingsPath, DEFAULT_SETTINGS } from "./settings.js";
// Re-exported so the command surface (and anything that imported it from here) keeps working; the
// implementation lives in `args.ts` because that module has no host dependency and is therefore
// testable in an installed checkout.
export { parseArgs, tailAfterVerb } from "./args.js";
import { LOOP_VERBS, parseArgs, tailAfterVerb } from "./args.js";

;

// -----------------------------------------------------------------
// Command surface
// -----------------------------------------------------------------

  /** Load the state of whichever log holds a running loop — the sec log first.
   *  A project that ran the old modes may have its loop in `.pi-hypothesis`; it
   *  still renders, it just cannot be driven any more. */
  const loadAuditState = (cwd: string): TreeSnapshot => {
    const sec = loadSec(cwd).snapshot;
    if (sec.loop) return sec;
    // A PRE-MIGRATION sec run kept its log in .pi-hypothesis. It still renders —
    // the widget and status must not say "no loop" while a run is mid-flight —
    // but the driver REFUSES to tick it: the run's writes would scatter across
    // two directories. The migration is renaming the directory; tell the operator.
    const hyp = load(cwd).snapshot;
    if (hyp.loop?.kind === "sec") return hyp;
    return hyp;
  };

  /** Refresh the TUI widget from the current state. Silent when there is no UI. */
  const refreshWidget = (ctx: ExtensionCommandContext): void => {
    try {
      if (!ctx.hasUI) return;
      const lines = renderWidget(loadAuditState(ctx.cwd));
      ctx.ui.setWidget("hypothesis-loop", lines ?? undefined, { placement: "belowEditor" });
    } catch {
      // A widget is a convenience; never let it break a command.
    }
  };

export default function loopsecExtension(pi: ExtensionAPI): void {
  registerSecTools(pi);

  // The ONLY audit command. Contract flags died with /goal; focus survives as a
  // PREFERENCE — generation and the work list favour those classes, and a finding
  // found outside them is still recorded.
  const verbs = LOOP_VERBS;
  const kind: AuditLoopKind = "sec";
    pi.registerCommand(loopCommandName(kind), {
      description:
        'Dig for bugs in a codebase: /loopsec "<objective>" [maxRounds=0] [plateau=8]. Round 1 reads the project; round 2 enumerates the attack surface; every later round digs ONE item from that list and records findings with sec_finding — each one carrying an artifact (a file:line or an evidence excerpt). With allowCommandProbes on, findings can be VERIFIED by running their PoC. The report is a triage list and says so. State lives in .pi-loopsec/. Subcommands: status | pause | resume | stop | next | tree | log | report | note | context | notes | config | dismiss | show | help.',
      getArgumentCompletions: (prefix: string) =>
        verbs
          .filter((v) => v.startsWith((prefix ?? "").trim()))
          .map((v) => ({
            value: v + " ",
            label: v,
            description:
              v === "status"
                ? "the run, the surface progress, and the findings"
                : v === "next"
                  ? "run one round now instead of waiting for the turn to end"
                  : v === "log"
                    ? "the per-round journal"
                    : v === "report"
                      ? "regenerate and print the SEC report (the deliverable)"
                      : v === "note"
                        ? "give the running audit information it should use in the NEXT round only"
                        : v === "context"
                          ? "give the running audit a standing fact it should use in EVERY round"
                          : v === "notes"
                            ? "show what operator input has been recorded and what has been delivered"
                      : v === "tree"
                      ? "list the findings (this mode has no tree)"
                      : v === "config"
                      ? "show or set project settings (allowCommandProbes, reportLanguage, …)"
                      : v === "deep"
                        ? "deep <F-id> [maxRounds] [说明] | deep end — work ONE finding in its own folder under .pi-loopsec/runs/"
                      : v === "start"
                        ? "start an audit, or resume the paused one if there is one"
                        : v === "dismiss"
                          ? "close the widget panel (the audit and its report are kept)"
                          : v === "hide" || v === "close"
                            ? "same as dismiss"
                            : v === "show"
                              ? "bring a closed widget back"
                              : `the ${loopCommandName(kind)} ${v}`,
          })),
      handler: async (args: string, ctx: ExtensionCommandContext) => {
        const parsed = parseArgs(args ?? "");
        const { positional, flags } = parsed;
        const first = (positional[0] ?? "").toLowerCase();
        const verb = verbs.includes(first) ? first : null;
        const rest = verb ? positional.slice(1).join(" ").trim() : positional.join(" ").trim();
        const cwd = ctx.cwd;
        const notify = (m: string, t: "info" | "warning" | "error" = "info"): void => ctx.ui.notify(m, t);

        /**
         * Load the state, or report WHY it could not be read.
         *
         * The loop-control verbs used `loadAudit().snapshot` directly, and `load` returns
         * an EMPTY snapshot when the read throws — so a transient read failure came out
         * as "no audit loop in this project". Measured on a real run: the operator had a
         * loop at round 30, ran `/loopsec pause 1`, and was told there was no loop. The
         * loop was not gone; the log could not be read, and the command said the one
         * thing that made the operator think their audit had been deleted.
         *
         * The tree/log/report/status verbs all checked `readError`. These four did not.
         * Nothing is changed on this path — the caller returns without writing.
         */
                /** Load THIS command's state: the sec log. */
        const loadAudit = (): ReturnType<typeof load> => loadSec(cwd);

        const loadOrReport = (): ReturnType<typeof load>['snapshot'] | null => {
          const { snapshot, readError } = loadAudit();
          if (readError) {
            notify(
              `Could not read the audit log: ${readError}\n` +
                `  The loop is NOT gone — the log could not be READ. Nothing was changed.\n` +
                `  The file is ${loopLogPath(cwd, kind)}`,
              "error",
            );
            return null;
          }
          return snapshot;
        };

        /** Prepare a round and hand the brief to the model. */
        const runRound = (): void => {
          const snapshot = loadAudit().snapshot;
          // Same pre-migration guard for the command-driven path: /loopsec next
          // or a fresh start must not scatter a legacy run's writes.
          const legacyLog = snapshot.loop?.awaitingRound != null && !fs.existsSync(secTreeLogPath(cwd));
          if (legacyLog) {
            notify(
              `This /loopsec run's log is still in .pi-hypothesis/ (pre-migration).` +
                `\n  Rename .pi-hypothesis to .pi-loopsec in this project, then retry — the run was NOT ticked.`,
              "error",
            );
            return;
          }
          // THROUGH THE SCHEDULER, like a settle. `tickLoop` here bypassed the turn claim, so the tool
          // calls in the turn this brief starts resolved to whatever the operator's commands pointed at —
          // which in a several-run project is a different log. It also skipped the rotation, so `next`
          // and the automatic first round after `start`/`deep` always fed the run that answered.
          const advanced = advanceRuns(cwd);
          refreshWidget(ctx);
          if (advanced.settled?.summary) notify(advanced.settled.summary.join("\n"), "info");
          if (advanced.sent) notify(`${advanced.sent.run} · round ${advanced.sent.round}`, "info");
          const result: TickResult = {
            action: advanced.sent ? "sent" : "idle",
            reason: advanced.idleReason ?? "settled",
            ...(advanced.sent ? { round: advanced.sent.round, brief: advanced.sent.brief } : {}),
            ...(advanced.sent?.summary ? { summary: advanced.sent.summary } : {}),
          };
          if (result.summary) notify(result.summary.join("\n"), "info");
          if (result.brief) {
            try {
              pi.sendUserMessage(result.brief);
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              parkOnSendFailure(cwd, `round ${result.round} was recorded but its brief could not be delivered: ${message}`);
              refreshWidget(ctx);
              notify(
                `Round ${result.round} was recorded but the brief could NOT be sent: ${message}\n` +
                  `The loop is PAUSED. Run /${loopCommandName(kind)} resume to re-offer the same work — the round number advances, the segment does not.`,
                "error",
              );
              return;
            }
          } else if (result.action !== "sent") {
            notify(`${result.action}: ${result.reason}`, result.action === "stopped" || result.action === "complete" ? "info" : "warning");
          }
        };

        switch (verb) {
          case "config": {
            // Settings live with the run's state (.pi-loopsec/settings.json, or the legacy
            // .pi-hypothesis one for a pre-migration project). Before this verb existed the
            // only way to turn allowCommandProbes on was to hand-edit that file — and the
            // sec_verify refusal NAMED a command (/hypothesis config) that had been removed with the hypothesis modes,
            // which is a refusal that sends the operator to a dead end.
            // SPLIT ON WHITESPACE, NOT ON THE LETTER "s". This was written `/s+/` — a missing
            // backslash — so EVERY key containing an "s" was torn in half: `allowCommandProbes=true`
            // arrived as ["=true"], the key became the empty string, and the refusal said "unknown
            // setting" while naming nothing. That verb is the only documented way to turn
            // `allowCommandProbes` on, which is the consent gate for `sec_verify` itself.
            //
            // Commas are accepted too, because `a=1, b=2` is how a person writes two settings.
            const pairs =
              rest === "" ? [] : rest.split(/[\s,]+/).filter((p) => p.includes("="));
            if (pairs.length === 0) {
              const { settings, source } = loadSettings(cwd);
              const live = Object.entries(DEFAULT_SETTINGS)
                .map(([k, v]) => `  ${k} = ${JSON.stringify(settings[k as keyof typeof settings] ?? v)}${source === "defaults" ? "  (default)" : ""}`)
                .join("\n");
              notify(
                `Settings (source: ${source}) — set with /loopsec config key=value\n\n${live}\n\nThe one that matters for sec_verify: allowCommandProbes (default false — nothing is executed without it).`,
                "info",
              );
              return;
            }
            const patch: Record<string, unknown> = {};
            for (const pair of pairs) {
              const eq = pair.indexOf("=");
              const key = pair.slice(0, eq).trim();
              if (key === "") {
                notify(`REJECTED: "${pair}" has no setting name before the "=" — write key=value.`, "warning");
                return;
              }
              let value: unknown = pair.slice(eq + 1);
              if (value === "true") value = true;
              else if (value === "false") value = false;
              else if (typeof value === "string" && value !== "" && !Number.isNaN(Number(value))) value = Number(value);
              patch[key] = value;
            }
            const saved = saveSettings(cwd, patch as never);
            if (!saved.ok) {
              notify(`REJECTED: ${saved.errors.join("; ")}`, "warning");
              return;
            }
            notify(
              [
                `Settings saved to ${settingsPath(cwd)}:`,
                ...Object.entries(patch).map(([k, v]) => `  ${k} = ${JSON.stringify(v)}`),
                "",
                "They take effect on the NEXT round (the report's language and fence tag, sec_verify's consent and bounds).",
              ].join("\n"),
              "info",
            );
            return;
          }

          case "help": {
            notify(
              [
                "/loopsec — the audit round engine (triage mode, state in .pi-loopsec/)",
                "",
                '  /loopsec "<objective>" [maxRounds=0] [plateau=8] [focus=a,b]   STARTS A NEW RUN',
                '  /loopsec                       continues the run your commands point at',
                `  /${loopCommandName(kind)} status              the run, the surface progress, the findings`,
                `  /${loopCommandName(kind)} pause               pause NOW`,
                `  /${loopCommandName(kind)} pause <n>           run n MORE rounds, then pause`,
                `  /${loopCommandName(kind)} resume [<n>]        resume, optionally for n rounds`,
                `  /${loopCommandName(kind)} resume maxRounds=<n>  raise a reached round cap and continue in place`,
                `  /${loopCommandName(kind)} start               start an audit, or RESUME the paused one`,
                `  /${loopCommandName(kind)} next                run one round now`,
                `  /${loopCommandName(kind)} dismiss             close the widget panel (the audit is kept)`,
                `  /${loopCommandName(kind)} show                bring a closed widget back`,
                `  /${loopCommandName(kind)} tree                render the findings (this mode has no tree)`,
                `  /${loopCommandName(kind)} log                 the per-round journal`,
                `  /${loopCommandName(kind)} report              regenerate + print the SEC report`,
                `  /${loopCommandName(kind)} ls                  every run in this project, and how far each got`,
                `  /${loopCommandName(kind)} use <name>          point your next command at one run`,
                "",
                "Steering a run that is already going:",
                `  /${loopCommandName(kind)} note <text>         info for the NEXT round only (an instruction)`,
                `  /${loopCommandName(kind)} context <text>      a standing fact, carried by EVERY round`,
                `  /${loopCommandName(kind)} notes               what has been recorded and what has landed`,
                `  /${loopCommandName(kind)} config [k=v]        show or set settings — allowCommandProbes gates sec_verify`,
                `  /${loopCommandName(kind)} deep <F-id> [max] [说明]  work ONE finding in its own folder`,
                `  /${loopCommandName(kind)} deep status         the deep run, its sub-questions, its budget`,
                `  /${loopCommandName(kind)} deep end            stop the deep run (the others keep running)`,
                "",
                "The REPORT is the deliverable: findings grouped by severity, each with its",
                "怎么打 / 调用链 / 链子分析 / 物证 — plus the surface list and what was never read.",
                "It is REGENERATED EVERY ROUND while the loop runs, so you can watch it fill in.",
                "Its language follows .pi-loopsec/settings.json reportLanguage (zh by default).",
                "",
                "A round: the recon phase reads the project (sec_recon); then the surface round enumerates",
                "the attack surface (sec_surface); then each round works ONE item from that list — a",
                "finding (sec_finding), a clearance (sec_clear), or a depth round (sec_dig).",
                "The item is assigned by the loop, not chosen by the model.",
                "",
                "A BREAKTHROUGH OUTRANKS THE LIST. When a finding is real but gated (post-auth, or you",
                "passed blockers), when you set deepen=true because there is more there, or when a HIGH",
                "finding has never been run, the loop spends its next rounds DEEPENING that finding —",
                "with a playbook (verify it, complete the path, follow the root cause, chain it) — and",
                "only returns to the work list when its depth budget is spent or you close it with",
                "`sec_update <id> pursuitClosed=\"<why>\"`.",
                "",
                "SEVERAL RUNS AT ONCE. Every objective gets its own directory — .pi-loopsec/runs/secNNN-<目标>/",
                "with its own log, findings and report — and the loop advances whichever run is due, one round",
                "at a time, least-recently-advanced first. So a sweep can keep running while a second audit",
                "chases what the first one surfaced. `ls` shows them, `use` points your commands at one;",
                "rounds pick their own run, so `use` only changes what YOU mean when you type a command.",
                "",
                "A DEEP RUN is for when that is not enough. A sweep gives a finding three rounds",
                "(pursuitRounds) and then never returns it; `/loopsec deep F-0008` opens a run whose",
                "whole job is that finding, in `.pi-loopsec/runs/secNNN-deep-F0008-<标题>/` with its own log and report.",
                "Its work list is SUB-QUESTIONS — if one action can answer it, list it — so each round",
                "narrows the next instead of repeating the same four moves. The sweep is paused while",
                "it runs and its log is never touched.",
              ].join("\n"),
              "info",
            );
            return;
          }

          case "status": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the sec log: ${readError}`, "error");
              return;
            }
            notify([...renderLoopStatus(snapshot), "", ...renderSecFindings(snapshot)].join("\n"), "info");
            return;
          }

          case "pause": {
            // `pause` stops now. `pause <n>` runs n MORE rounds first — the only way to
            // bound a run that has no finish line of its own, since `maxRounds` counts
            // from the start rather than from here.
            const budget = rest.trim();
            const budgetSnapshot = loadOrReport();
            if (!budgetSnapshot) return;
            if (budget !== "" && /^\d+$/.test(budget)) {
              const result = pauseAfterRounds(cwd, budgetSnapshot, Number(budget), undefined, kind);
              notify(result.ok ? result.message! : `REJECTED: ${result.errors.join("\n")}`, result.ok ? "info" : "warning");
              refreshWidget(ctx);
              return;
            }
            if (budget !== "") {
              notify(
                `REJECTED: "${budget}" is not a round count.\n\n` +
                  `  /${loopCommandName(kind)} pause          pause now\n` +
                  `  /${loopCommandName(kind)} pause <n>      run n MORE rounds, then pause\n` +
                  `  /${loopCommandName(kind)} pause <reason> pause now, recording why`,
                "warning",
              );
              return;
            }
            const pauseSnapshot = loadOrReport();
            if (!pauseSnapshot) return;
            const result = pauseLoop(cwd, pauseSnapshot, "paused by the user", undefined, kind);
            notify(result.ok ? result.message! : `REJECTED: ${result.errors.join("; ")}`, result.ok ? "info" : "warning");
            refreshWidget(ctx);
            return;
          }

          case "resume": {
            const raise = flags.maxRounds !== undefined && Number.isInteger(Number(flags.maxRounds)) ? Number(flags.maxRounds) : undefined;
            // `resume <n>` resumes AND pauses after n rounds — the same budget as
            // `pause <n>`, for the case where the clock is already stopped.
            const forText = rest.trim();
            if (forText !== "" && !/^\d+$/.test(forText)) {
              notify(`REJECTED: "${forText}" is not a round count. /${loopCommandName(kind)} resume <n> runs n more rounds.`, "warning");
              return;
            }
            const forRounds = forText === "" ? undefined : Number(forText);
            const resumeSnapshot = loadOrReport();
            if (!resumeSnapshot) return;
            const result = resumeLoop(
              cwd,
              resumeSnapshot,
              {
                ...(raise !== undefined ? { maxRounds: raise } : {}),
                ...(forRounds !== undefined ? { forRounds } : {}),
              },
              undefined,
              kind,
            );
            if (!result.ok) {
              notify(`REJECTED: ${result.errors.join("\n")}`, "warning");
              return;
            }
            notify(result.message!, "info");
            runRound();
            return;
          }

          case "stop":
          case "cancel": {
            const stopSnapshot = loadOrReport();
            if (!stopSnapshot) return;
            const result = stopLoop(cwd, stopSnapshot, rest || "stopped by the user", undefined, kind);
            notify(result.ok ? result.message! : `REJECTED: ${result.errors.join("; ")}`, result.ok ? "info" : "warning");
            refreshWidget(ctx);
            return;
          }

          case "next": {
            const snapshot = loadAudit().snapshot;
            if (!snapshot.loop) {
              notify(`No audit ${loopCommandName(kind)} is running. Start one with /${loopCommandName(kind)} "<objective>".`, "warning");
              return;
            }
            runRound();
            return;
          }

          case "tree": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the sec log: ${readError}`, "error");
              return;
            }
            // A sec run has no tree, so `/loopsec tree` shows what it DOES have:
            // the findings. Rendering an empty tree would read as "the audit found nothing".
            notify(renderSecFindings(snapshot).join("\n"), "info");
            return;
          }

          case "report": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            {
              const coverageReport = secCoverage(snapshot, cwd);
              const written = writeSecReport(cwd, snapshot, snapshot.loop, { coverageReport });
              if (!written.ok) {
                notify(`The report could not be written: ${written.errors.join("; ")}`, "error");
                return;
              }
              notify(
                [
                  `Report written to ${written.value}`,
                  "",
                  `${snapshot.findings.length} finding(s) · ${coverageHeadline(coverageReport)}`,
                  "Findings that were RUN carry the 已复现 mark; the rest are static claims — the summary gives both counts.",
                  "Every finding carries an artifact you can open; nothing else about them is checked.",
                ].join("\n"),
                "info",
              );
              return;
            }
          }

          // -------------------------------------------------------------
          // Operator input into a running loop.
          // -------------------------------------------------------------
          //
          // `note` is consumed by the NEXT brief; `context` is carried by EVERY
          // brief. The distinction matters: a one-shot note that stayed forever
          // would keep pulling the audit back to a stale instruction, and a
          // durable fact that was consumed once would be forgotten.
          case "note":
          case "context": {
            const pinned = verb === "context";
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            // The note is FREE TEXT, so it is taken from the raw argument string
            // rather than from the parsed positionals: a note containing an `=`
            // ("the token endpoint is at /oauth2/token?grant=x") would otherwise
            // be split off as a flag and silently dropped.
            const text = (args ?? "").trim().replace(/^\S+\s*/, "").trim();
            if (!text) {
              // No text: show what is recorded rather than an error. That is the
              // question the operator actually has at this point.
              notify(renderOperatorSummary(snapshot), "info");
              return;
            }
            const result = appendNote(cwd, snapshot, text, { pinned, kind });
            if (!result.ok || !result.note) {
              notify(result.errors.join("; "), "error");
              return;
            }
            writeOperatorMirror(cwd, loadAudit().snapshot, kind);
            const where = pinned ? "in every round from now on" : "in the next round only";
            const running = snapshot.loop?.status === "running";
            notify(
              `${result.note.id} recorded — it will reach the model ${where}${
                running ? "." : ", once a loop is running."
              }`,
              "info",
            );
            refreshWidget(ctx);
            return;
          }

          case "notes": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            writeOperatorMirror(cwd, snapshot);
            notify(`${renderOperatorSummary(snapshot)}\n\nMirror: ${operatorNotePath(cwd, kind)}`, "info");
            return;
          }

          case "log": {
            const { snapshot: logSnap } = loadAudit();
            const file = secLedgerPath(cwd);
            try {
              const text = fs.readFileSync(file, "utf-8");
              const tail = text.split("\n").slice(-60).join("\n");
              notify(`Findings ledger (tail of ${file}):\n${tail}`, "info");
            } catch {
              notify(`No findings ledger yet at ${file} — it is written at the end of each round.`, "info");
            }
            return;
          }

          // `start` is an explicit case so that `/loopsec start` is INTENTIONAL
          // rather than an accident of the switch having no matching case and
          // falling through to the start path below.
          case "start":
            break;

          // Close the widget panel without discarding the audit.
          //
          // Three spellings, because the word a person reaches for is not
          // predictable and none of them is ambiguous here.
          case "dismiss":
          case "hide":
          case "close": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            const result = dismissLoop(cwd, snapshot);
            if (!result.ok) {
              notify(result.errors.join("; "), "warning");
              return;
            }
            // Remove it NOW rather than waiting for the next refresh: the
            // refresh only happens on a settle or another command, and a
            // command that appears to do nothing is worse than none.
            if (ctx.hasUI) ctx.ui.setWidget("hypothesis-loop", undefined, { placement: "belowEditor" });
            notify(result.message!, "info");
            return;
          }

          // ---- DEEP: one finding, its own folder, its own report -------------------------------
          //
          // `/loopsec deep F-0008` opens a run whose whole job is that finding. It is a VERB rather
          // than a second command because the eight tools resolve the ACTIVE run through
          // `.pi-loopsec/active.json` — so a separate command name would buy no isolation, only a
          // second set of `pause`/`status`/`report` verbs to explain. There is exactly one active
          // run, and `deep` swaps which one that is.
          // ---- LS / USE: several runs, and pointing commands at one of them --------------------
          //
          // Runs no longer share one directory, so "which run does `report` mean" has to be answerable
          // and changeable. `ls` shows them in creation order with how far each got; `use` points the
          // operator's next command at one.
          //
          // BOTH MUST BE IN `verbs`. A verb that is not registered falls through to the START path with
          // its own name as the objective — `/loopsec ls` was silently creating a run whose objective was
          // the word "ls", which is the worst kind of wrong: it looks like it worked.
          case "ls":
          case "runs": {
            const runs = listRuns(cwd);
            if (runs.length === 0) {
              notify(
                [
                  "No runs in this project yet.",
                  "",
                  '  /loopsec "挖掘认证前漏洞"     starts one in .pi-loopsec/runs/sec001-挖掘认证前漏洞/',
                  "  /loopsec deep F-0008        starts one that works a single finding",
                ].join("\n"),
                "info",
              );
              return;
            }
            const activeNow = readActiveRun(cwd);
            const lines = [`${runs.length} run(s) under ${SEC_STATE_DIR_NAME}/${RUNS_DIR_NAME}/ (creation order):`];
            for (const r of runs) {
              const current = activeNow?.dir === r.dir ? "▶" : " ";
              const state = r.status ?? "no state";
              const round = typeof r.round === "number" ? `r${r.round}${r.maxRounds ? `/${r.maxRounds}` : ""}` : "r-";
              const deep = r.deepOf ? `  [deep ${r.deepOf}]` : "";
              lines.push(
                `${current} ${r.run.padEnd(30)} ${state.padEnd(8)} ${round.padEnd(8)} ${r.findings ?? 0}F ${r.surfaces ?? 0}Q${deep}`,
              );
              if (r.objective) lines.push(`    ${clip(r.objective, 100)}`);
            }
            lines.push("");
            lines.push("`use <name>` points your next command at one. Rounds pick their own run, so this");
            lines.push("only changes what /loopsec status|report|note mean when you type them.");
            notify(lines.join("\n"), "info");
            return;
          }

          case "use": {
            const needle = positional[1];
            if (!needle) {
              const runs = listRuns(cwd);
              notify(
                [
                  "Usage: `/loopsec use <name>` — point your next command at one run.",
                  "",
                  runs.length > 0 ? runs.map((r) => `  ${r.run}`).join("\n") : "  (no runs yet)",
                ].join("\n"),
                runs.length > 0 ? "info" : "warning",
              );
              return;
            }
            const found = findRun(cwd, needle);
            if (!found) {
              // An ambiguous prefix is the case worth naming: silently picking one would send the next
              // `report` to a run the operator did not mean.
              const all = listRuns(cwd).filter((r) => r.run.toLowerCase().startsWith(needle.toLowerCase()));
              notify(
                [
                  all.length > 1
                    ? `"${needle}" matches ${all.length} runs — say which:`
                    : `no run matches "${needle}".`,
                  "",
                  (all.length > 1 ? all : listRuns(cwd)).map((r) => `  ${r.run}`).join("\n"),
                ].join("\n"),
                "warning",
              );
              return;
            }
            if (readTurnClaim(cwd)) {
              notify(
                "A round is in flight. Its tools resolve the run when they are CALLED, so switching now would\n" +
                  "send that round's findings to the wrong log. Wait for it to settle, or `/loopsec cancel` first.",
                "warning",
              );
              return;
            }
            const claimedSwitch = setActiveRun(cwd, { dir: found.dir, run: found.run });
            if (!claimedSwitch.ok) {
              notify(claimedSwitch.errors.join("; "), "warning");
              return;
            }
            refreshWidget(ctx);
            notify(
              [
                `Now pointing at ${found.run}${found.status ? ` (${found.status}, round ${found.round ?? 0})` : ""}.`,
                `  ${found.objective ? clip(found.objective, 100) : "(no objective recorded)"}`,
                `  ${found.findings ?? 0} finding(s), ${found.surfaces ?? 0} sub-question(s)/surface item(s)`,
                "",
                "`status`, `report`, `note`, `pause`, `resume`, `log` now mean this run.",
              ].join("\n"),
              "info",
            );
            return;
          }

          case "deep": {
            const snapshot = loadSec(cwd).snapshot;
            const sub = (positional[1] ?? "").toLowerCase();
            if (sub === "end" || sub === "back") {
              const ended = endDeepRun(cwd);
              if (!ended.ok) {
                notify(ended.errors.join("\n"), "warning");
                return;
              }
              refreshWidget(ctx);
              notify(
                ended.released === "pointer"
                  ? [
                      `Released a HALF-BUILT deep run${ended.dir ? ` (${ended.dir})` : ""} — the pointer was set but that directory holds no run state.`,
                      "",
                      "Nothing was in it to lose, and the sweep is reachable again. A crash between creating the",
                      `directory and writing the run's first event leaves exactly this: check \`.pi-loopsec/${ended.dir ?? "deep/*"}/\` and remove it if it is empty.`,
                      "",
                      "The sweep is still PAUSED. `/loopsec resume` to continue it.",
                    ].join("\n")
                  : [
                      "Left the deep run — the project is back on the sweep.",
                      "",
                      "The sweep is still PAUSED where `deep` left it. `/loopsec resume` to continue it,",
                      "or `/loopsec status` to see both. The deep run's log and report are kept; rerunning",
                      "`deep` on the same finding REOPENS it at the round it stopped on.",
                    ].join("\n"),
                "info",
              );
              return;
            }
            if (sub === "status") {
              const deep = snapshot.loop?.deep;
              notify(
                deep
                  ? [
                      `Deep run active: ${deep.findingId} · ${deep.title}`,
                      `from ${deep.parentDir === "." ? "the main run" : deep.parentDir}`,
                      ...(deep.directive ? [`重点（操作者）：${deep.directive}`] : []),
                      `${snapshot.surfaces.length} sub-question(s) · ${snapshot.findings.length} new finding(s) · round ${snapshot.loop?.round ?? 0}/${snapshot.loop?.maxRounds || "∞"}`,
                      `folder: \`.pi-loopsec/deep/${deep.findingId}/\``,
                    ].join("\n")
                  : "No deep run is active. `/loopsec deep F-0001` starts one from a finding of the sweep.",
                "info",
              );
              return;
            }
            const findingId = positional[1];
            if (!findingId) {
              const available = snapshot.findings
                .filter((f) => !!f.severity)
                .slice(0, 20)
                .map((f) => `  ${f.id}  [${f.severity}]  ${f.category}  ${clip(f.title, 70)}`)
                .join("\n");
              notify(
                [
                  "Usage: `/loopsec deep <F-id> [maxRounds] [说明…]` — work ONE finding in its own folder.",
                  "",
                  "  /loopsec deep F-0008                  work it, open-ended",
                  "  /loopsec deep F-0008 30               30 rounds max",
                  "  /loopsec deep F-0008 重点关注绕过       steer it; maxRounds must come FIRST",
                  "  /loopsec deep F-0008 30 重点关注绕过    both",
                  "",
                  snapshot.findings.length > 0
                    ? `Findings of this sweep:\n${available}`
                    : "This sweep has no findings yet. A deep run starts FROM a finding: run `/loopsec` until there is one.",
                  "",
                  "`/loopsec deep end` stops the deep run. The other runs — including the sweep it came from — keep going.",
                ].join("\n"),
                snapshot.findings.length > 0 ? "info" : "warning",
              );
              return;
            }
            // THE TAIL IS THE OPERATOR'S STEER, and it has to be separable from the round cap without
            // guessing. The rule is positional and stated in the usage: if the FIRST word after the id
            // is a non-negative integer it is `maxRounds`, and everything after it is the directive;
            // otherwise the whole tail is the directive. No token-sniffing for numbers later in the
            // sentence — "重点关注绕过 30" would otherwise silently lose its words.
            //
            // Taken from `tokens` (raw text), NOT from `positional`: `parseArgs` moves `word=value` into
            // `flags`, so "用 focus=rce 这类思路" used to arrive here as "用 这类思路" — the words the
            // operator typed were gone, silently, and the run was steered by a sentence they did not
            // write.
            const tail = tailAfterVerb(parsed.tokens, "deep", 1)
              .map((t) => t.replace(/^["']|["']$/g, ""))
              .filter((p) => p !== "");
            const looksNumeric = tail.length > 0 && /^\d+$/.test(tail[0]!);
            const maxRounds = looksNumeric ? Number(tail[0]) : 0;
            const directive = (looksNumeric ? tail.slice(1) : tail).join(" ").trim();
            const started = startDeepRun(cwd, findingId.toUpperCase(), {
              ...(maxRounds > 0 ? { maxRounds: Math.floor(maxRounds) } : {}),
              ...(directive ? { directive } : {}),
              plateauWindow: flags.plateau ? Number(flags.plateau) || undefined : undefined,
            });
            if (!started.ok) {
              notify(started.errors.join("\n"), "warning");
              return;
            }
            refreshWidget(ctx);
            // A REOPENED RUN IS A DIFFERENT EVENT FROM A NEW ONE, and must not report "opened" — the
            // operator would think their earlier rounds were discarded. Same rule as `start`, which
            // separates "started" from "resumed" for the same reason.
            if (started.resumed) {
              notify(
                [
                  `Reopened the deep run on ${findingId.toUpperCase()} at round ${started.round ?? 0} — nothing reset.`,
                  `  folder: \`.pi-loopsec/${started.dir}/\``,
                  `  ${loadSec(cwd).snapshot.surfaces.length} sub-question(s) and ${loadSec(cwd).snapshot.findings.length} finding(s) carried over.`,
                  "",
                  "The sweep is paused again. To change direction: `/loopsec context <新方向>`.",
                ].join("\n"),
                "info",
              );
              runRound();
              return;
            }
            notify(
              [
                `Deep run opened: ${findingId.toUpperCase()} → \`.pi-loopsec/${started.dir}/\``,
                ...(directive ? ["", `重点：${directive}`, "（已写入种子笔记，每一轮都会读到；想改就用 `/loopsec context <新方向>`。）"] : []),
                "",
                "The sweep is paused and its log is untouched. Everything from here — findings,",
                "sub-questions, the report — lands in the new folder.",
                "",
                "Report: `/loopsec report` · back: `/loopsec deep end`",
              ].join("\n"),
              "info",
            );
            // OPENING A RUN IS NOT THE SAME AS DRIVING IT. `start` ends with `runRound()`, and without
            // it here the deep run would sit there — created, announced, and doing nothing until the
            // operator happened to type something that makes the agent settle. A command that looks
            // like it worked and then does nothing is the failure this whole file keeps fixing.
            runRound();
            return;
          }

          case "show": {
            const { snapshot, readError } = loadAudit();
            if (readError) {
              notify(`Could not read the hypothesis log: ${readError}`, "error");
              return;
            }
            const result = showLoop(cwd, snapshot);
            if (!result.ok) {
              notify(result.errors.join("; "), "warning");
              return;
            }
            notify(result.message!, "info");
            refreshWidget(ctx);
            return;
          }
        }

        // No verb: this is a START.
        //
        // With no tree, an audit of an unread project starts from a SCOPE, not a
        // hypothesis: there is nothing to hypothesise about until the project
        // has been read, and forcing the user to phrase a boundary as a claim
        // produces a root like "this project contains a vulnerability", which
        // no evidence can refute. The scope node is exempt from the assertion
        // gate and is never scheduled; the hypotheses arrive from the recon
        // segments on the following rounds.
        const snapshot = loadAudit().snapshot;
        // No objective given means "the one already in play". The fallback is the
        // LOOP's objective, not the TREE's: the tree objective is whatever
        // created the root (often the scope line), while the loop carries the
        // audit the user actually asked for. Falling back to the tree's made
        // `/loop start` on a paused loop look like a request for a DIFFERENT
        // audit, and it was refused.
        const objective = rest || snapshot.loop?.objective || snapshot.objective;

        const focus = (flags.focus ?? "")
          .split(",")
          .map((f) => f.trim())
          .filter(Boolean);
        const unknownFocus = focus.filter((f) => !HYPOTHESIS_CATEGORIES.includes(f as never));
        if (unknownFocus.length > 0) {
          notify(`Unknown focus class(es): ${unknownFocus.join(", ")}.\nKnown: ${HYPOTHESIS_CATEGORIES.join(", ")}`, "warning");
          return;
        }

        // A NEW OBJECTIVE STARTS A NEW RUN.
        //
        // This is the change that makes several audits possible: typing `/loopsec "<objective>"` used to
        // resume-or-refuse against the single run, so a second audit could not exist without stopping
        // the first. Now a GIVEN objective creates `runs/secNNN-<objective>/` and points your commands at
        // it; the other runs keep going, because the scheduler advances whichever run is due and each
        // round claims its own run for the duration of its turn.
        //
        // A bare `/loopsec` / `/loopsec start` still means "the run my commands point at" — the resume
        // path — so the old behaviour survives exactly where it was useful.
        let started: ReturnType<typeof startLoop>;
        if (rest.trim()) {
          const runName = nextRunName(cwd, rest.trim());
          const dir = `${RUNS_DIR_NAME}/${runName}`;
          try {
            fs.mkdirSync(path.join(secBaseDir(cwd), dir), { recursive: true });
          } catch (error) {
            notify(`could not create ${SEC_STATE_DIR_NAME}/${dir}: ${(error as Error).message}`, "error");
            return;
          }
          const claimedNew = setActiveRun(cwd, { dir, run: runName, label: clip(rest.trim(), 60) });
          if (!claimedNew.ok) {
            notify(claimedNew.errors.join("; "), "warning");
            return;
          }
          // Re-read through the new claim, so the loop state and the first round land in the NEW run
          // rather than in whichever run answered a moment ago.
          started = startLoop(cwd, loadSec(cwd).snapshot, {
            kind,
            objective: rest.trim(),
            ...(flags.maxRounds !== undefined && Number.isInteger(Number(flags.maxRounds)) ? { maxRounds: Number(flags.maxRounds) } : {}),
            ...(flags.plateau !== undefined && Number.isInteger(Number(flags.plateau)) ? { plateauWindow: Number(flags.plateau) } : {}),
            ...(focus.length > 0 ? { focus } : {}),
          });
          if (started.ok) {
            notify(
              [
                `New run: ${runName}`,
                `  ${clip(rest.trim(), 120)}`,
                `  folder: ${SEC_STATE_DIR_NAME}/${dir}/`,
                `  /loopsec ls to see them all · /loopsec use <name> to point your commands at one`,
              ].join("\n"),
              "info",
            );
          }
        } else {
          started = startLoop(cwd, snapshot, {
            kind,
            objective,
          ...(flags.maxRounds !== undefined && Number.isInteger(Number(flags.maxRounds)) ? { maxRounds: Number(flags.maxRounds) } : {}),
          ...(flags.plateau !== undefined && Number.isInteger(Number(flags.plateau)) ? { plateauWindow: Number(flags.plateau) } : {}),
            ...(focus.length > 0 ? { focus } : {}),
          });
        }
        if (!started.ok) {
          notify(`REJECTED: ${started.errors.join("; ")}`, "warning");
          return;
        }
        // A RESUMED loop is a different event from a fresh start: the round
        // number, the findings and the surface list all carry over, and reporting
        // "started" would make the user think their earlier work was discarded.
        if (started.resumed) {
          notify(
            [
              `Resumed the paused ${started.loop!.kind} at round ${started.loop!.round}: ${clip(started.loop!.objective, 120)}`,
              `  nothing was reset — the findings, the surface list and the round number are unchanged.`,
              `  the stall counter was reset, so the plateau starts fresh.`,
              `  to start a DIFFERENT audit: /${started.loop!.kind} stop first.`,
            ].join("\n"),
            "info",
          );
          runRound();
          return;
        }
        notify(
          [
            `SEC loop started: ${clip(objective, 120)}`,
            `  drive it with /${loopCommandName(kind)} — status, pause, report, help`,
            `  unbounded; plateau after ${started.loop!.plateauWindow} unproductive rounds`,
            `  findings ledger: ${secLedgerPath(cwd)}`,
          ].join("\n"),
          "info",
        );
        runRound();
      },
    });


  // ---------------------------------------------------------------
  // The round driver: a SETTLED turn advances the loop.
  // ---------------------------------------------------------------
  //
  // `agent_settled`, NOT `agent_end`.
  //
  // Pi's own docs draw the distinction: `agent_end` fires "when an agent run
  // ends", while `agent_settled` fires "after an agent run has fully settled and
  // no automatic retry, compaction, or queued continuation will run". Sending a
  // new user message on `agent_end` therefore fails with "Agent is already
  // processing" — the run has ended but the agent is not yet idle — and the loop
  // stops dead after round 1 with its fence set and no turn in flight.
  //
  // `awaitingRound` is the anti-stacking fence: the loop only advances when a
  // round it started is actually in flight, so a slow or failed turn cannot
  // pile rounds on top of each other. `ticking` guards re-entrancy within one
  // event.
  let ticking = false;
  pi.on("agent_settled", async (_event, ctx) => {
    if (ticking) return;
    // SEVERAL RUNS, ONE CONVERSATION. A settle no longer means "advance the loop"; it means "settle
    // whatever round was in flight, then give the next one to the run that most deserves it". Reading a
    // single snapshot here was the shape of the one-run design and would have pinned every settle to
    // whichever run answered.
    const pending = readTurnClaim(ctx.cwd);
    const anyRunning = listRuns(ctx.cwd).some((r) => r.status === "running");
    if (!pending && !anyRunning) return;
    // A PRE-MIGRATION sec loop lives in .pi-hypothesis but the driver writes to
    // .pi-loopsec — ticking it would scatter one run across two directories.
    // Park the run and name the one-line migration instead.
    if (pending && !fs.existsSync(secTreeLogPath(ctx.cwd))) {
      const message = `This /loopsec run was started before the state directory moved to .pi-loopsec/ — its log is still in .pi-hypothesis/.` +
        `\n  To migrate: rename .pi-hypothesis to .pi-loopsec in this project, then /loopsec resume.` +
        `\n  The loop was NOT ticked; nothing was written to either directory.`;
      ctx.ui.notify(message, "error");
      return;
    }
    ticking = true;
    try {
      const advanced = advanceRuns(ctx.cwd);
      if (advanced.settled?.summary) ctx.ui.notify(advanced.settled.summary.join("\n"), "info");
      // One shape for the rest of this handler: what it used to do with a single tick's result.
      const result: TickResult = {
        action: advanced.sent ? "sent" : "idle",
        reason: advanced.idleReason ?? "settled",
        ...(advanced.sent ? { round: advanced.sent.round, brief: advanced.sent.brief } : {}),
        ...(advanced.sent?.summary ? { summary: advanced.sent.summary } : {}),
      };
      if (advanced.sent) {
        ctx.ui.notify(`${advanced.sent.run} · round ${advanced.sent.round}`, "info");
      }
      if (result.summary) ctx.ui.notify(result.summary.join("\n"), "info");
      if (result.brief) {
        try {
          pi.sendUserMessage(result.brief);
        } catch (error) {
          // No automatic retry exists: the agent is idle, so no further event
          // will arrive to try again. Park the loop and hand the decision back.
          const message = error instanceof Error ? error.message : String(error);
          parkOnSendFailure(ctx.cwd, `round ${result.round} was recorded but its brief could not be delivered: ${message}`);
          ctx.ui.notify(
            `Round ${result.round} was recorded but its brief could NOT be delivered: ${message}\n` +
              `The audit loop is PAUSED. Run /loopsec resume to re-offer the same work — the round number advances, the segment does not.`,
            "error",
          );
          return;
        }
      } else if (result.action !== "sent") {
        // A terminal tick produces neither a summary nor a brief, so without
        // this branch the goal ends SILENTLY: the only signal is the widget
        // glyph changing. Say what happened and why, and what is still open.
        // The run that was settled, NOT whichever run the operator's commands point at now: the turn
        // claim is released by the settle, so re-reading through it would describe a different run.
        const settledDir = advanced.settled?.dir ?? null;
        const after = settledDir
          ? (loadSecIn(ctx.cwd, settledDir)?.snapshot ?? loadAuditState(ctx.cwd))
          : loadAuditState(ctx.cwd);
        // The REPORT is the deliverable, so it is written the moment the run
        // ends — not left for the user to remember to ask for.
        const written = writeSecReport(ctx.cwd, after, after.loop, {
          language: reportLanguageOf(ctx.cwd),
          // The run that just ended, NOT the one the operator's commands point at.
          ...(settledDir ? { runDir: settledDir } : {}),
        });
        const reportNote = written.ok ? `\n\nReport: ${written.value}` : `\n\n(The report could not be written: ${written.errors.join("; ")})`;
        const examined = after.surfaces.filter((s) => s.status === "examined" || s.status === "cleared").length;
        const tail =
          result.action === "complete"
            ? `\n\n${examined}/${after.surfaces.length} surface item(s) examined, ${after.findings.length} finding(s) recorded — the round CAP was the finish line. /loopsec resume maxRounds=<n> keeps digging.`
            : "";
        ctx.ui.notify(
          `Audit ${result.action.toUpperCase()}: ${result.reason}${tail}${reportNote}`,
          result.action === "complete" ? "info" : "warning",
        );
      }
      try {
        if (ctx.hasUI) {
          ctx.ui.setWidget("hypothesis-loop", renderWidget(loadAuditState(ctx.cwd)) ?? undefined, { placement: "belowEditor" });
        }
      } catch {
        /* a widget must never break the loop */
      }
    } catch (error) {
      // A driver failure must PARK the loop rather than spin: an exception here
      // would otherwise repeat on every subsequent turn.
      const message = error instanceof Error ? error.message : String(error);
      stopLoop(ctx.cwd, loadAuditState(ctx.cwd), `driver error: ${message}`);
      ctx.ui.notify(`Audit loop stopped — the round driver threw: ${message}`, "error");
    } finally {
      ticking = false;
    }
  });
}

/** Re-exported for tests and for anyone embedding the store primitives. */
export { loadSec, secTreeLogPath } from "./store.js";
export * from "./types.js";
export * from "./loop.js";
export * from "./sec.js";
export { registerSecTools, SEC_TOOL_NAMES } from "./tools.js";
export { loadSettings, saveSettings, settingsPath, DEFAULT_SETTINGS } from "./settings.js";
