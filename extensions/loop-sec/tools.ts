/**
 * pi-audit-loopsec — extensions/loop-sec/tools.ts
 *
 * The /loopSEC tool surface. One file used to carry the hypothesis-tree tools as
 * well; they went with /goal, /loop and /hypothesis. A tool surface that lists
 * commands that no longer exist is how a model starts driving a mode that is not
 * there.
 *
 * The seven tools below are the whole sec round loop: recon → surface → analyze.
 * The ONE hard rule lives in validateFinding (sec.ts): a finding carries an
 * artifact, or it is not recorded.
 */

import { defineTool, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import { SEVERITIES, SEC_SURFACE_KINDS, type SecFindingPatch, type SecSurfaceKind, type Severity } from "./types.js";
import { clearSurface, digSurface, recordFinding, recordSurface, reopenSurface, submitSecRecon, surfaceProgress, updateFinding, updateSurface, verifyFinding } from "./sec.js";
import { loadSec } from "./store.js";

function text(value: string, details: Record<string, unknown> = {}): { content: Array<{ type: "text"; text: string }>; details: Record<string, unknown> } {
  return { content: [{ type: "text", text: value }], details };
}

function projectRootOf(ctx: ExtensionContext): string {
  return ctx.cwd;
}

export function registerSecTools(pi: ExtensionAPI): void {
  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_recon",
      label: "Submit the /loopSEC recon note",
      description:
        "Record the reconnaissance note for a /loopSEC run: what the project is, its entrypoints, its trust boundaries, and where the class of bug the objective names would live. Unlike hypothesis_recon this note is NOT chunked into segments — a dig round works from the note plus what has not been read yet. Write it AS PARAGRAPHS.",
      promptSnippet: "sec_recon — write the one recon note a /loopSEC run works from",
      promptGuidelines: [
        "Call sec_recon once, at the start, after actually reading the project — not before.",
        "This is the ONLY recon pass and it sets the ceiling: a part of the project absent from the note is a part nothing will look at.",
        "Name the files and directories you looked at, and state what you could NOT work out.",
      ],
      parameters: Type.Object({
        notes: Type.String({
          description: "The recon note. Markdown paragraphs separated by blank lines. At least 200 characters.",
        }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const submitted = submitSecRecon(root, params.notes ?? "");
        if (!submitted.ok) {
          return text(`Recon REJECTED — nothing was recorded:\n${submitted.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        return text(
          [
            `Recon note recorded: ${submitted.value.length} chars.`,
            "",
            "The next round is a DIG round: it hands you this note, the findings so far, and the",
            "directories nothing has been recorded from yet. Record findings with sec_finding.",
          ].join("\n"),
          { chars: submitted.value.length },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_finding",
      label: "Record a /loopSEC finding",
      description:
        "Record a finding in a /loopSEC run. There is no assertion gate here — write it however is clearest — but a finding MUST carry an artifact: a `file` with `line`, or an `evidence` excerpt, or both. Without one it is refused, because the artifact is the only thing a reader of the report can check.",
      promptSnippet: "sec_finding — record what you found (an artifact is required)",
      promptGuidelines: [
        "ALWAYS pass `file` + `line` or `evidence`. A finding with neither is refused, and that refusal is the point of this mode's only rule.",
        "`severity` is your own judgement and nothing checks it here — record what you actually believe, and omit it if you cannot judge.",
        "`preAuth` is tri-state: true (reachable without authentication), false (needs one), or omitted. Omitting it means NOT ASSESSED, which the report prints as such and does NOT count as pre-auth.",
        "Recording nothing for a round is legitimate. Inventing findings to look productive is worse than coming back empty.",
        "Use sec_update to correct a finding you already recorded rather than recording a second one.",
        "Give the CALL CHAIN as `path` — one step per hop with a file:line on each. Do NOT bury the file:line references inside `reasoning`: a reader can scan a numbered list and cannot scan Chinese prose for a path.",
        "ASK THE COMBINATION QUESTION EVERY TIME: does what you just found, together with something ALREADY recorded, reach somewhere neither reaches alone? If so, record the chain as its own finding with chainOf=[...] — it is usually the heaviest finding the run produces, and the report cannot state it unless you record it.",
      ],
      parameters: Type.Object({
        title: Type.String({ description: "What the finding is. Free-form: there is no assertion gate in this mode." }),
        category: Type.String({ description: "Vulnerability class, e.g. rce, sqli, ssrf, path-traversal, auth-bypass." }),
        file: Type.Optional(Type.String({ description: "Project-relative path. Give this or `evidence`." })),
        line: Type.Optional(Type.Number({ description: "1-based line, with `file`." })),
        evidence: Type.Optional(Type.String({ description: "The verbatim artifact. Give this or `file`." })),
        severity: Type.Optional(
          Type.Union(SEVERITIES.map((s) => Type.Literal(s)), {
            description: "Your judgement, unchecked by anything in this mode. Omit if you cannot judge.",
          }),
        ),
        preAuth: Type.Optional(
          Type.Boolean({
            description:
              "Can an UNAUTHENTICATED request reach it? Omit when you have not determined it — the report prints that as 'not assessed' and does NOT count it as pre-auth.",
          }),
        ),
        reasoning: Type.Optional(Type.String({ description: "How it is reached and why it matters." })),
        poc: Type.Optional(Type.String({ description: "A copy-pasteable request, when there is one." })),
        surfaceId: Type.Optional(
          Type.String({
            description: "The surface item this came out of, e.g. S-0003. Links the finding back to the work list so the report can show which item produced it.",
          }),
        ),
        path: Type.Optional(
          Type.Array(
            Type.Object({
              detail: Type.String({ description: "What happens at this step." }),
              file: Type.Optional(Type.String({ description: "Project-relative path, when the step is a code location." })),
              line: Type.Optional(Type.Number({ description: "1-based line, with `file`." })),
            }),
            {
              description:
                "The CALL CHAIN, one step per hop, from the entrypoint to the sink. Use it instead of burying `file:line` references inside `reasoning` — a reader scans a numbered list and has to reconstruct prose. Example: [{detail: \"permitAll() lets the route through unauthenticated\", file: \"SecurityConfig.java\", line: 51}, {detail: \"dispatched to the deletion callback, which does not verify signatures\", file: \"ManagementRequestVerifier.java\", line: 165}]",
            },
          ),
        ),
        chainOf: Type.Optional(
          Type.Array(Type.String(), {
            description:
              "TWO OR MORE existing finding ids this one COMBINES, e.g. [\"F-0001\", \"F-0007\"]. Use it when what you found, together with something already recorded, reaches somewhere neither reaches alone — an arbitrary file write alone is medium, and the same write into a file that gets executed is root RCE. A chain needs NO artifact of its own: its artifact IS its parts. Every id must already exist.",
          }),
        ),
        blockers: Type.Optional(
          Type.Array(Type.String(), {
            description:
              "WHAT MUST HOLD for this to be exploitable as recorded — the gates that are not open yet: \"需要一个有效的管理员会话\", \"需要 attacker 控制 X-Forwarded-Host\", \"需要 base_url 带路径前缀\". Record these whenever what you found is REAL but GATED: a high finding with blockers is pursued by the loop — it spends its next rounds attacking that gate INSTEAD of the next item on the work list, because closing the gate converts the finding into the objective. Filing a gated finding with no blockers is what makes the run walk away from its best result.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = recordFinding(root, {
          title: params.title,
          category: params.category,
          ...(params.file ? { file: params.file } : {}),
          ...(typeof params.line === "number" ? { line: params.line } : {}),
          ...(params.evidence ? { evidence: params.evidence } : {}),
          ...(params.severity ? { severity: params.severity as Severity } : {}),
          ...(typeof params.preAuth === "boolean" ? { preAuth: params.preAuth } : {}),
          ...(params.reasoning ? { reasoning: params.reasoning } : {}),
          ...(params.poc ? { poc: params.poc } : {}),
          ...(params.surfaceId ? { surfaceId: params.surfaceId } : {}),
          ...(params.path && params.path.length > 0 ? { path: params.path } : {}),
          ...(params.chainOf && params.chainOf.length > 0 ? { chainOf: params.chainOf } : {}),
          ...(params.blockers && params.blockers.length > 0 ? { blockers: params.blockers } : {}),
        });
        if (!result.ok) {
          return text(`Finding REJECTED — nothing was recorded:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const f = result.value;
        const where = f.location ? ` ${f.location.file}:${f.location.line}` : "";
        return text(
          [
            `Recorded ${f.id}: [${f.severity ?? "unrated"}] ${f.category} — ${f.title}${where}`,
            "",
            "NOTE: this mode has no verification tier, no falsification attempt and no challenge round.",
            "The finding is recorded as your claim plus the artifact you attached, and nothing more.",
            "If it matters, re-run the objective under /loop, where it gets all three.",
          ].join("\n"),
          { findingId: f.id, total: loadSec(root).snapshot.findings.length },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_surface",
      label: "Enumerate the attack surface",
      description:
        "Add one item to the /loopSEC attack surface — the WORK LIST the run then works through one item per round. An item is a COORDINATE, not a claim: `POST /diag/ping`, `run_cmd() in src/util/shell.c`, `the session cookie check`. You do NOT have to say what is wrong with it yet. Aim for 10-30 items, and list them IN THE ORDER THEY SHOULD BE EXAMINED — the loop takes the first open item each round, so that order is the plan.",
      promptSnippet: "sec_surface — add one place worth analysing to the work list",
      promptGuidelines: [
        "These are places, not assertions. Do NOT phrase an item as a claim about behaviour — that is what the analyze rounds are for.",
        "List them in the order worth checking. Nothing re-sorts the list.",
        "Include the entrypoints, the sinks, the trust boundaries, and any file you cannot yet explain but that looks load-bearing.",
        "An item you end up clearing is not wasted: it is a part of the project somebody looked at and found sound.",
        "Pass `categories` when the class is already obvious — the analyze round then hands over that class's depth axes.",
      ],
      parameters: Type.Object({
        title: Type.String({ description: "What it is: a route, a function, a boundary, a file. Free-form." }),
        kind: Type.Optional(
          Type.Union(SEC_SURFACE_KINDS.map((k) => Type.Literal(k)), {
            description: "entrypoint | sink | boundary | file | other. Defaults to other.",
          }),
        ),
        file: Type.Optional(Type.String({ description: "Project-relative path, when you know where it is." })),
        line: Type.Optional(Type.Number({ description: "1-based line, with `file`." })),
        categories: Type.Optional(
          Type.Array(Type.String(), { description: "Classes worth checking here, e.g. [\"rce\", \"path-traversal\"]." }),
        ),
        priority: Type.Optional(
          Type.Number({
            description:
              "Raise to look at this SOONER than the plan. 1 means 'next'; higher jumps ahead of that. Leave it unset for anything found while reading the project, and use it when the ANALYSIS revealed something more promising than what is left on the list — you know things in round 15 you did not know in round 2, and a plan written before you knew anything should not override that. Do NOT promote everything: the brief reports how many items are queued ahead of the plan.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = recordSurface(root, {
          title: params.title,
          ...(params.kind ? { kind: params.kind as SecSurfaceKind } : {}),
          ...(params.file ? { file: params.file } : {}),
          ...(typeof params.line === "number" ? { line: params.line } : {}),
          ...(params.categories && params.categories.length > 0 ? { categories: params.categories } : {}),
          ...(typeof params.priority === "number" ? { priority: params.priority } : {}),
        });
        if (!result.ok) {
          return text(`Surface item REJECTED:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const s = result.value;
        const p = surfaceProgress(loadSec(root).snapshot);
        const where = s.location ? ` ${s.location.file}:${s.location.line}` : "";
        return text(
          [
            `Added ${s.id} [${s.kind}] ${s.title}${where}`,
            ...(result.warnings.length > 0 ? result.warnings : []),
            "",
            `Surface: ${p.total} item(s), ${p.open} open.`,
            p.total < 10
              ? "Keep enumerating — 10-30 items is the range that covers a project without making any one item too big for its round."
              : "Enough to work with. The loop now takes the first open item each round.",
          ].join("\n"),
          { surfaceId: s.id, total: p.total },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_clear",
      label: "Clear a surface item",
      description:
        "Mark a surface item examined and NOT exploitable. The reason is required and must NAME THE GUARD you found and where it is — 'nothing found' is refused, because it is the absence of a reason rather than one. Clearing an item is a RESULT: it is the only evidence a reader has that a part of the project was looked at and found sound, and it is what stops the next round re-reading the same file.",
      promptSnippet: "sec_clear — I read this item and it is guarded",
      promptGuidelines: [
        "The reason must name the guard and where it is. \"I looked and found nothing\" is refused.",
        "Clearing an item is a result, not a failure — it is what makes this an analysis rather than a bug hunt.",
        "Clear only what you actually traced. A clearance on an unread item marks an area done on the strength of a shrug.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The surface item id, e.g. S-0003." }),
        reason: Type.String({
          description: "WHICH guard you found and where: \"check_auth() is called at router.c:88 before dispatch, and the route is not in the public table\".",
        }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = clearSurface(root, params.id, params.reason);
        if (!result.ok) {
          return text(`Clear REJECTED:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const s = result.value;
        const p = surfaceProgress(loadSec(root).snapshot);
        return text(
          [
            `${s.id} cleared — ${s.title}`,
            `  guard: ${s.clearedReason}`,
            "",
            `Surface: ${p.examined}/${p.total} examined · ${p.cleared} cleared · ${p.productive} produced a finding · ${p.open} open`,
            p.open === 0
              ? "Every item on the list has been examined. The next round enumerates again, with what the analysis revealed."
              : "The next round takes the next open item.",
          ].join("\n"),
          { surfaceId: s.id, status: s.status, open: p.open },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_dig",
      label: "Keep digging on a surface item",
      description:
        "Tell the loop you are NOT finished with a surface item: it comes back to you next round. Tracing a path takes more than one round when the path is long, and a depth round counts as PROGRESS — so asking for it costs you nothing. It IS budgeted, because a trace that never ends is the same as never deciding.",
      promptSnippet: "sec_dig — I need another round on this item",
      promptGuidelines: [
        "Use it when you genuinely started tracing something and the next hop needs the next round. Do NOT use it to avoid deciding.",
        "A depth round is product, so it does not burn the plateau — but it is budgeted, and past the budget you must either `sec_finding` or `sec_clear`.",
        "It outranks both the plan and a promoted item: finishing a trace you started beats starting a more promising-looking one.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The surface item id, e.g. S-0003." }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = digSurface(root, params.id);
        if (!result.ok) {
          return text(`Dig REJECTED:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const s = result.value;
        const p = surfaceProgress(loadSec(root).snapshot);
        return text(
          [
            `${s.id} will come back NEXT round — depth round ${s.digRounds ?? 0} of the budget.`,
            `  ${s.title}`,
            "",
            `Surface: ${p.examined}/${p.total} examined · ${p.digging} mid-dig · ${p.open} open`,
          ].join("\n"),
          { surfaceId: s.id, status: s.status },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_reopen",
      label: "Reopen a cleared surface item",
      description:
        "Withdraw a clearance: the guard you named does not actually hold, so the item goes back on the work list. The reason is required, because a clearance asserts that something protects this code and withdrawing that assertion is a claim too.",
      promptSnippet: "sec_reopen — the guard does not hold, put this item back",
      promptGuidelines: [
        "Use it when a guard you recorded turns out not to cover the path you thought it did. Say WHICH part of it fails.",
        "It puts the item back in PLAN order; add `priority=1` as well if it should be looked at next.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The surface item id, e.g. S-0003." }),
        reason: Type.String({
          description: "Why the recorded guard does NOT hold: what it actually checks, and what it misses.",
        }),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = reopenSurface(root, params.id, params.reason);
        if (!result.ok) {
          return text(`Reopen REJECTED:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const s = result.value;
        const p = surfaceProgress(loadSec(root).snapshot);
        return text(
          [
            `${s.id} is back on the work list — ${s.title}`,
            `  withdrawn clearance: ${params.reason}`,
            "",
            `Surface: ${p.examined}/${p.total} examined · ${p.attempted} attempted · ${p.open} open`,
          ].join("\n"),
          { surfaceId: s.id, status: s.status },
        );
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_update",
      label: "Correct a /loopSEC finding",
      description:
        "Change a field of a finding you already recorded — a severity you can now judge, a preAuth you have determined, a poc, or a better title. A field you omit is KEPT, not cleared. Also the two ways a PURSUIT ends: pass `blockers=[]` when the gate opened, or `pursuitClosed` with the reason when it cannot be opened. The artifact requirement holds: a finding may not be left with neither a location nor an evidence excerpt.",
      promptSnippet: "sec_update — correct a finding, or close the pursuit of its gate",
      parameters: Type.Object({
        id: Type.String({ description: "The finding id, e.g. F-0003." }),
        title: Type.Optional(Type.String()),
        category: Type.Optional(Type.String()),
        severity: Type.Optional(Type.Union(SEVERITIES.map((s) => Type.Literal(s)))),
        preAuth: Type.Optional(
          Type.Boolean({
            description: "Omit to keep what is there. Tri-state, so 'not assessed' stays 'not assessed'.",
          }),
        ),
        file: Type.Optional(Type.String()),
        line: Type.Optional(Type.Number()),
        evidence: Type.Optional(Type.String()),
        reasoning: Type.Optional(Type.String()),
        poc: Type.Optional(Type.String()),
        blockers: Type.Optional(
          Type.Array(Type.String(), {
            description:
              "REPLACE the blocker list. Pass `[]` when the gate OPENED (the precondition now holds — the loop stops pursuing it); pass refined text when your pursuit round established something better than what was recorded (\"需要 admin 会话\" → \"需要 core.change_datasource 权限，它由任意已认证用户持有\"). A refined blocker is PROGRESS — the same text is not.",
          }),
        ),
        pursuitClosed: Type.Optional(
          Type.String({
            description:
              "Close the pursuit of this finding's gate, with the reason. Use it when you attacked the blockers and none can be opened (\"试过 a/b/c：均无法在认证前到达\"). Without it, \"we stopped\" and \"we never tried\" look the same in the report.",
          }),
        ),
        priority: Type.Optional(
          Type.Number({
            description:
              "Raise to analyse this item SOONER than the plan says; 0 puts it back in plan order. Use it when what you have read since made an item you already listed more promising than you thought.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const patch: SecFindingPatch = {};
        if (params.title) patch.title = params.title;
        if (params.category) patch.category = params.category;
        if (params.severity) patch.severity = params.severity as Severity;
        if (typeof params.preAuth === "boolean") patch.preAuth = params.preAuth;
        if (params.file) patch.location = { file: params.file, line: typeof params.line === "number" ? params.line : 1 };
        if (params.evidence) patch.evidence = params.evidence;
        if (params.reasoning) patch.reasoning = params.reasoning;
        if (params.poc) patch.poc = params.poc;
        // AN EMPTY ARRAY IS MEANINGFUL HERE — it is how the model says "the gate opened". The usual
        // "empty means absent" rule would make the gate impossible to clear, and the finding would
        // be pursued until its budget ran out.
        if (Array.isArray(params.blockers)) patch.blockers = params.blockers;
        if (params.pursuitClosed) patch.pursuitClosed = params.pursuitClosed;
        // priority is a SURFACE field, not a finding one. sec_update corrects a finding, so a
        // priority here means "the surface item this finding came from" — which is what the
        // model has in hand when it decides an item deserves to jump the queue.
        if (typeof params.priority === "number") {
          const owner = loadSec(root).snapshot.findings.find((f) => f.id === params.id)?.surfaceId;
          if (owner) {
            updateSurface(root, owner, { priority: params.priority });
          } else {
            return text(
              `${params.id} is a finding, not a surface item, and it carries no surfaceId — so there is nothing to re-prioritise.`,
            );
          }
        }
        const result = updateFinding(root, params.id, patch);
        if (!result.ok) {
          return text(`Update REJECTED — nothing changed:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const f = result.value;
        return text(`${f.id} updated: [${f.severity ?? "unrated"}] ${f.category} — ${f.title}`, { findingId: f.id });
      },
    }),
  );

  // ---------------------------------------------------------------
  pi.registerTool(
    defineTool({
      name: "sec_verify",
      label: "Run the claim and record what came back",
      description:
        "Run ONE command against a recorded finding and store exactly what it produced — the command line, its exit code, its output, and whether it matched the expectation you stated. This is the only tool in this mode that touches anything outside the source tree, so it is OFF unless the project enables allowCommandProbes. A confirmed run is what turns a static claim into a REPRODUCED finding, and the report separates the two.",
      promptSnippet: "sec_verify — run it and record what actually came back",
      promptGuidelines: [
        "State `expect` BEFORE you run: what do you predict this shows? It is required, and the verdict is computed from it — not from your reading of the output.",
        "Use this when the finding has a pasteable request or command. A finding you cannot run stays a static claim, and the report says so.",
        "A run that does NOT match the expectation is a RESULT: either the finding is wrong or the expectation was. Fix whichever is wrong; do not re-run until it agrees.",
        "Running nothing is also a legitimate outcome — a source-only audit is a valid audit, just a weaker one.",
      ],
      parameters: Type.Object({
        id: Type.String({ description: "The finding id to verify, e.g. F-0001." }),
        command: Type.String({
          description: "The exact command line to run. It is recorded verbatim so a reader can re-run it.",
        }),
        expect: Type.String({
          description: "What you predict this run shows, in prose, stated BEFORE running it.",
        }),
        expectOutput: Type.Optional(
          Type.String({
            description: "A substring the output must contain for the run to count as confirmed (e.g. 'root:' or a version banner).",
          }),
        ),
        expectExit: Type.Optional(
          Type.Union([Type.Literal("zero"), Type.Literal("nonzero")], {
            description: "Exit-code expectation. Defaults to 'zero'.",
          }),
        ),
      }),
      async execute(_id, params, _signal, _onUpdate, ctx) {
        const root = projectRootOf(ctx);
        const result = verifyFinding(root, params.id, {
          command: params.command,
          expect: params.expect,
          ...(params.expectOutput ? { expectOutput: params.expectOutput } : {}),
          ...(params.expectExit ? { expectExit: params.expectExit as "zero" | "nonzero" } : {}),
        });
        if (!result.ok) {
          return text(`Verify REFUSED — nothing was run:\n${result.errors.map((e) => `  - ${e}`).join("\n")}`);
        }
        const v = result.value;
        return text(
          [
            `${params.id}: ${v.confirmed ? "CONFIRMED by running it" : "NOT confirmed by the run"}`,
            `  command: ${v.command}`,
            `  exit: ${v.timedOut ? "KILLED (timeout)" : (v.exitCode ?? "unknown")}`,
            `  expected: ${v.expect}`,
            "",
            "output:",
            ...v.output.split("\n").slice(0, 40).map((l) => `  ${l}`),
            ...(result.warnings.length > 0 ? ["", ...result.warnings.map((w) => `NOTE: ${w}`)] : []),
          ].join("\n"),
          { findingId: params.id, confirmed: v.confirmed, exitCode: v.exitCode },
        );
      },
    }),
  );
}

/** The tool names a /loopsec brief may name, for the brief builders in loop.ts. */
export const SEC_TOOL_NAMES = [
  "sec_recon",
  "sec_surface",
  "sec_finding",
  "sec_clear",
  "sec_dig",
  "sec_reopen",
  "sec_update",
  "sec_verify",
] as const;
