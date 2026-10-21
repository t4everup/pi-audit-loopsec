/**
 * pi-audit-loopsec — extensions/loop-sec/reportText.ts
 *
 * The report's own words, in two languages.
 *
 * -----------------------------------------------------------------------
 * What is translated, and what is NOT
 * -----------------------------------------------------------------------
 *
 * This file holds the SCAFFOLDING: headings, labels, the method section, the
 * explicit non-claims. Those are the tool's words and the tool must say them in
 * the reader's language.
 *
 * It does NOT hold the findings. An assertion, a status reason, an evidence
 * excerpt and an impact are the MODEL's words, recorded verbatim in whatever
 * language the model wrote them. Translating them here would mean the report
 * paraphrases its own evidence, which is exactly the kind of laundering this
 * project exists to avoid — a reader must see the auditor's actual claim, not a
 * rendering of it.
 *
 * So a Chinese report needs both: these strings, AND a brief that tells the
 * model to write its assertions and evidence in Chinese. `reportLanguage` drives
 * both.
 *
 * -----------------------------------------------------------------------
 * Why a table and not a lookup at each call site
 * -----------------------------------------------------------------------
 *
 * A report with a missing translation is worse than one in the wrong language:
 * a half-translated heading reads as a bug and hides the structure. One object
 * per language means a new string cannot be added without both being updated —
 * the compiler refuses the incomplete one.
 */

export type ReportLanguage = "zh" | "en";

import type { VerificationTier } from "./types.js";

export const REPORT_LANGUAGES: ReportLanguage[] = ["zh", "en"];

export function isReportLanguage(value: unknown): value is ReportLanguage {
  return value === "zh" || value === "en";
}

/** The label for a severity, so a Chinese report does not say "HIGH". */
/**
 * A fence long enough to hold `parts` verbatim.
 *
 * Markdown closes a fence only with a run of backticks at least as long as the
 * opening one. The strings this report embeds are transcripts, and a transcript
 * frequently contains its OWN ``` fence — a model that ran a command and pasted
 * the output, or one that quoted a code block. Embedding that inside a ``` fence
 * closes the outer fence early.
 *
 * The damage is invisible to a parity check: the outer CLOSING fence then opens a
 * new fence, so the document keeps an EVEN number of fence lines while every
 * section after the bad one is swallowed into a code block. Measured on a real
 * audit: 9 of 228 evidence entries carried a fence, and the first of them
 * corrupted all 17 findings below it.
 *
 * So the fence is DERIVED from the content instead of assumed to be three.
 */
export function fenceFor(...parts: string[]): string {
  let longest = 0;
  for (const p of parts) for (const m of p.match(/`+/g) ?? []) longest = Math.max(longest, m.length);
  return "`".repeat(Math.max(3, longest + 1));
}
export function severityLabel(severity: string | undefined, lang: ReportLanguage): string {
  if (!severity) return lang === "zh" ? "未评级" : "UNRATED";
  const zh: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
  return lang === "zh" ? (zh[severity] ?? severity.toUpperCase()) : severity.toUpperCase();
}
// -----------------------------------------------------------------
//
// A second table rather than a second file, because the rule this file exists to
// enforce is "one object per language so a new string cannot be added without both
// being updated". Splitting the sec strings out would leave that rule in two places.
//
// The CAVEAT is the load-bearing part. Everywhere else in this extension the
// non-claims go at the foot of the report; here they go FIRST, because the reader is
// about to scroll findings GROUPED BY SEVERITY and severity is exactly the field
// this mode does not check.

export interface SecStrings {
  title: string;
  generatedFrom: string;
  objective: string;
  generatedAt: string;
  run: string;
  duration: string;
  stoppedBecause: string;
  /** `yes`/`no` for the summary's boolean rows, in the reader's language. */
  yes: string;
  no: string;
  stillRunning: string;

  // The caveat, printed before anything else.
  caveatTitle: string;
  caveatIntro: string;
  caveatColMissing: string;
  caveatColMeans: string;
  caveatNoTier: string;
  caveatNoTierWhy: string;
  caveatNoFalsification: string;
  caveatNoFalsificationWhy: string;
  caveatNoChallenge: string;
  caveatNoChallengeWhy: string;
  caveatNoSeverity: string;
  caveatNoSeverityWhy: string;
  caveatNoGate: string;
  caveatNoGateWhy: string;
  caveatEnforced: string;
  caveatRerun: string;

  summaryTitle: string;
  rowFindings: string;
  rowUnrated: string;
  rowPreAuth: string;
  rowPostAuth: string;
  rowUnassessed: string;
  rowNote: string;
  /** `侦察轮次` — how many recon sections the run recorded, out of how many it takes. */
  rowReconRounds: (recorded: number, planned: number) => string;
  /** Deep runs only: the context came from a finding, not from a recon pass. */
  rowDeepSeed: string;
  /** The banner that says this report is a DEEP run, naming the finding it came from. */
  deepBanner: (findingId: string, title: string, parentDir: string) => string;
  noFindings: string;
  /** The verification split — the one thing that tells a reader which lines were RUN. */
  rowVerified: string;
  rowUnverified: string;
  probesOffNote: (verified: number, total: number) => string;
  probesOnNote: (verified: number, total: number) => string;
  /** The heading of a finding's verification block. */
  verifyHeading: string;
  verifyConfirmed: string;
  verifyNotConfirmed: string;

  coverageTitle: string;
  rowCited: string;
  rowGapDirs: string;  coverageNotMeasured: (why: string) => string;
  coverageNoGap: string;
  coverageGapNote: string;
  coverageGapLine: (dir: string, files: number) => string;

  // The attack surface — the work list, and how far the run got with it.
  surfaceTitle: string;
  surfaceIntro: string;
  rowSurfaceTotal: string;
  rowSurfaceExamined: string;
  rowSurfaceCleared: string;
  rowSurfaceProductive: string;
  /** Items mid-dig, and the rounds a depth round may cost. */
  rowSurfaceDigging: string;
  /** Items examined and left unresolved — not the same as never looked at. */
  rowSurfaceAttempted: string;
  diggingTitle: string;
  diggingNote: string;
  diggingLine: (id: string, title: string, used: number, budget: number) => string;
  rowSurfaceRounds: string;
  /** Chains — findings that combine other findings. */
  rowChains: string;
  /** \
   * \
   * `被前提阻塞的高危发现` — the near misses: real, high, and not yet reachable. */
  rowGated: (gated: number, total: number) => string;
  chainTitle: string;
  chainNote: string;
  chainOfLabel: (ids: string) => string;
  chainLine: (id: string, sev: string, title: string, parts: string) => string;
  surfaceNone: string;
  surfaceAllExamined: string;
  surfaceOpenTitle: string;
  surfaceOpenNote: string;
  /** Items handed rounds that reached no conclusion — NOT the same as never looked at. */
  surfaceTouchedTitle: string;
  surfaceTouchedNote: string;
  surfaceClearedTitle: string;
  surfaceClearedNote: string;
  surfaceClearedLine: (id: string, title: string, reason: string, guard: string) => string;
  surfaceOpenLine: (id: string, kind: string, title: string, where: string) => string;
  surfaceItemLabel: (id: string) => string;

  findingsTitle: (n: number) => string;
  noneRecorded: string;

  notReadTitle: string;
  notReadNote: string;

  // One finding. ORDERED THE WAY A HUNTER READS IT, and every label earns its line.
  // The old block put four labelled lines (位置 / 来自攻击面 / 是否需要身份认证 / 记录于)
  // in a wall before anything useful, buried the PoC under 36 lines of evidence, and
  // repeated a two-line disclaimer on every finding when the preamble already carried
  // the full table. Measured on a real X-Road report: 27-102 lines per finding, of which
  // the metadata was 8-9 and the caveat 2 — pure overhead on every single one.
  authPre: string;
  authPost: string;
  authUnassessed: string;
  /** `认证：` — the label for the one-line metadata strip. */
  authShort: string;
  /** What separates the fields of that strip. */
  metaSeparator: string;
  roundShort: (n: number) => string;
  surfaceShort: (id: string) => string;
  /** `怎么打` — the PoC, and it comes BEFORE the chain. */
  pocHeading: string;
  /** `调用链` — the numbered path. */
  chainHeading: string;
  /** `链子分析` — the sink→source prose, when a structured chain exists as well.
  *  Fenced like the chain: the reasoning IS part of the 6-part hunter format. */
  notesHeading: string;
  evidenceHeading: string;
  notVerifiedShort: string;
  /**  — the gate block of a gated finding. */
  gateHeading: string;
  gateOpen: string;
  pursuitOpen: (spent: number) => string;
  /**
   * Why this finding was DEEPENED, and how much of its depth budget it has spent.
   *
   * Without this the report cannot distinguish "the run decided this was the thing worth finishing"
   * from "the run happened to work on it" — the depth reflex is the whole reason a breakthrough is
   * pursued instead of filed, and it left no trace in the report.
   */
  depthLine: (reasons: string, spent: number, budget: number) => string;
  depthReasonGate: string;
  depthReasonDeepen: string;
  depthReasonUnproven: string;
  pursuitClosed: (spent: number, reason: string) => string;
  /** The finding WAS run — what is still missing is falsification and a challenge round. */
  notFalsifiedShort: string;
  /** Labels inside a finding's verification fence. */
  verifyCommand: string;
  verifyExit: string;
  verifyExpect: string;
  verifyOutput: string;
  verifyTimeout: string;

  footer: string;
}

const SEC_ZH: SecStrings = {
  title: "# /loopSEC — 发现",
  generatedFrom: "_由 `/loopSEC` 运行的持久化状态生成。这里没有任何摘要由模型生成。_",
  objective: "目标",
  generatedAt: "生成于",
  run: "运行",
  duration: "时长",
  stoppedBecause: "停止原因",
  yes: "是",
  no: "**没有**",
  stillRunning: "（仍在运行）",

  caveatTitle: "## 先读这一段 —— 这份报告**不是**什么",
  caveatIntro:
    "**这是一份三角测量清单，不是已验证的审计。** `/loopSEC` 不跑假设树，因此移除了所有让另一份报告的发现可被核查的机制：",
  caveatColMissing: "没有的东西",
  caveatColMeans: "在这里意味着什么",
  caveatNoTier: "**只有跑过的条目才有「已复现」标记**",
  caveatNoTierWhy: "其余是静态声明——没跑就是没跑。概览里给了两者的数量。",
  caveatNoFalsification: "**没有证伪尝试**",
  caveatNoFalsificationWhy: "没有任何一条被尝试推翻过。误报率是**未知**，不是低。",
  caveatNoChallenge: "**没有对抗复核**",
  caveatNoChallengeWhy: "每一条都是审计员在附和自己。",
  caveatNoSeverity: "**没有等级核查**",
  caveatNoSeverityWhy: "等级是审计员一次性的判断，未经复核。",
  caveatNoGate: "**没有断言门禁**",
  caveatNoGateWhy: "一条发现可能是对某个区域的模糊描述，而不是关于行为的断言。",
  caveatEnforced:
    "**强制执行的是：每条发现都带物证。** `file:line` 或一段物证摘录是必需的，所以下面每一行都可以被人工打开核查。这是本模式唯一的保证，也是那条规则存在的原因。",
  caveatRerun:
    "打算上报的发现，用 `/loop` 重跑同一个目标 —— 那里它才会拿到验证等级、一次证伪尝试和一次对抗复核。",

  summaryTitle: "## 概览",
  rowFindings: "记录的发现",
  rowUnrated: "**未评级的**",
  rowPreAuth: "无需认证可达",
  rowPostAuth: "标注为认证后",
  rowUnassessed: "**认证要求未评估**",
  rowNote: "已记录侦察笔记",
  rowReconRounds: (recorded, planned) => `侦察轮次（决定了本次能看到什么）`,
  rowDeepSeed: "种子上下文（来自父发现的记录，不是一次侦察）",
  deepBanner: (findingId, title, parentDir) =>
    "> **这是一次深挖运行（不是扫描）。** 全部工作围绕 `" +
    findingId +
    "` 这一个发现展开：" +
    title +
    "\n>\n> 上下文来自 `" +
    (parentDir === "." ? "主运行" : parentDir) +
    "` 记录的该发现，没有侦察阶段；工作清单是子问题。",
  rowVerified: "**已复现（跑过命令，结果符合跑前声明的预期）**",
  rowUnverified: "静态声明（没有跑过任何东西）",
  probesOffNote: (v, t) =>
    `\`allowCommandProbes\` 是关的，所以本次**没有任何验证运行**：下面 ${t} 条全是**静态声明**。` +
    `打开该设置（\`/loopsec config allowCommandProbes=true\`）可以让审计真的把 PoC 跑一遍。`,
  probesOnNote: (v, t) => `其中 **${v}/${t}** 条跑过命令，且结果符合跑之前声明的预期。`,
  verifyHeading: "**验证**",
  verifyConfirmed: "已复现 —— 下面的命令真的运行过，结果符合跑之前声明的预期",
  verifyNotConfirmed: "**未复现** —— 跑过了，但结果**不符合**跑之前声明的预期：要么发现是错的，要么预期是错的",
  noFindings:
    "**没有记录任何发现。** 这是合法结果——一轮为了看起来有产出而编造发现，比空手而归更糟——但它**不是**项目干净的证据。见下面的「未读」。",

  coverageTitle: "## 覆盖",
  rowCited: "**被某条发现引用过的文件**",
  rowGapDirs: "**ZERO 发现的目录**",
  coverageNotMeasured: (why) => `_未测量 —— ${why}。**未测量不等于已覆盖。**_`,
  coverageNoGap:
    "每个够大的目录都至少有一条发现引用过它。这不等于查干净了，只等于没有整块空白。",
  coverageGapNote:
    "> **一个目录里没有发现，不是「干净」，是「未读」。** 这些是侦察笔记没有覆盖到的部分，它们限制了这次运行到底看了项目的多少。",
  coverageGapLine: (dir, files) => `- \`${dir}\` — ${files} 个文件，没有记录到任何东西`,

  surfaceTitle: "## 攻击面",
  surfaceIntro:
    "这次运行枚举的攻击面，以及它每一项做到了哪一步。**「已分析并确认有防护」是一个结果** —— 它是「这部分有人看过并确认没问题」的唯一证据。",
  rowSurfaceTotal: "**攻击面上的项**",
  rowSurfaceExamined: "**已分析**",
  rowSurfaceCleared: "已确认有防护",
  rowSurfaceProductive: "产出了发现",
  rowSurfaceDigging: "**仍在深挖（未定论）**",
  rowSurfaceAttempted: "**看过但未定论**",
  diggingTitle: "## 仍在深挖",
  diggingNote:
    "这些项被读过、**主动要求了更多轮**，但还没得出结论。它们既不是「已确认有防护」，也不是「没看过」—— 是一段没走完的追踪。",
  diggingLine: (id, title, used, budget) => `- **${id}** ${title} — 已用 ${used}/${budget} 个深挖轮，仍未定论`,
  rowSurfaceRounds: "**花在枚举上的轮次**",
  rowChains: "**组合链**",
  rowGated: (gated, total) => `**被前提阻塞的高危发现（近失，优先追索）**`,
  chainTitle: "## 组合链",
  chainNote:
    "这些发现**由其他发现组合而成** —— 它们的任何一部分单独都到不了这里。它们通常是整份报告里最重的东西：一个写原语单独是中危，写进一个会被执行的文件就是 root 代码执行。",
  chainOfLabel: (ids) => `**组合自：** ${ids}`,
  chainLine: (id, sev, title, parts) => `- **${id}** [${sev}] ${title}
  - 组合自：${parts}`,
  surfaceNone: "_这次运行没有枚举攻击面。_",
  surfaceAllExamined: "列表上的每一项都已经分析过了。",
  surfaceOpenTitle: "## 尚未分析",
  surfaceTouchedTitle: "## 看过但未定论",
  surfaceTouchedNote:
    "这些项被分配过轮次，但**既没确认有防护、也没得出结论**。它们不是「没看过」—— 是看过了、没查完。别把这一节和上一节混起来。",
  surfaceOpenNote:
    "这些项从没被分配过轮次。**它们不是干净的，是没看过。**",
  surfaceClearedTitle: "## 已分析并确认有防护",
  surfaceClearedNote:
    "这些项被读过并追踪过，结论是**不可利用**，理由如下。这一节和上面的发现一样重要 —— 它是一份分析报告而非一份 bug 列表的原因。",
  surfaceClearedLine: (id, title, reason, guard) => `- **${id}** ${title}\n  - ${reason}\n  - 守卫位置：${guard}`,
  surfaceOpenLine: (id, kind, title, where) => `- \`${id}\` [${kind}] ${title}${where ? ` — \`${where}\`` : ""}`,
  surfaceItemLabel: (id) => `**来自攻击面：** \`${id}\``,

  findingsTitle: (n) => `## 发现（${n}）`,
  noneRecorded: "_没有记录。_",

  notReadTitle: "## 未读",
  notReadNote: "这些子树从未被任何发现引用过。它们不是干净的，是没人看过。",

  authPre: "**认证前可达**",
  authPost: "认证后",
  authUnassessed: "**未评估**（≠ 认证前）",
  authShort: "认证：",
  metaSeparator: " · ",
  roundShort: (n) => `第 ${n} 轮`,
  surfaceShort: (id) => `攻击面 ${id}`,
  pocHeading: "**怎么打**",
  chainHeading: "**调用链**",
  notesHeading: "**链子分析**",
  evidenceHeading: "**物证**",
  gateHeading: "**前提（要利用它还需要什么成立）**",
  gateOpen: "_（没有剩余前提——门已打开）_",
  pursuitOpen: (spent) => `追索中：已花 ${spent} 轮攻这个前提，仍未打开。`,
  depthLine: (reasons, spent, budget) => `**为什么在深挖：** ${reasons}（已花 ${spent}/${budget} 轮）`,
  depthReasonGate: "它是被前提挡住的近失——攻开前提比另找一条路更值",
  depthReasonDeepen: "记录时被标为突破点",
  depthReasonUnproven: "高危但一次都没跑过——静态结论还没被证伪",
  pursuitClosed: (spent, reason) => `追索已结束（${spent} 轮）：${reason}`,
  notVerifiedShort: "_未经验证：无等级 · 无证伪 · 无对抗复核_",
  notFalsifiedShort: "_未经证伪：没有任何人尝试推翻它，也没有对抗复核。跑过不等于对。_",
  verifyCommand: "命令",
  verifyExit: "退出码",
  verifyExpect: "跑前预期",
  verifyOutput: "输出",
  verifyTimeout: "被超时杀掉，没有跑完",

  footer:
    "_由 pi-audit-loopsec 从 `.pi-loopsec/` 生成 —— 仅追加的日志、发现台账和侦察笔记。重跑 `/loopSEC report` 可从状态重新生成。_",
};

const SEC_EN: SecStrings = {
  title: "# /loopSEC — findings",
  generatedFrom: "_Generated from the recorded state of a `/loopSEC` run. Nothing here is summarised by a model._",
  objective: "Objective",
  generatedAt: "Generated",
  run: "Run",
  duration: "Duration",
  stoppedBecause: "Stopped because",
  yes: "yes",
  no: "**no**",
  stillRunning: "(still running)",

  caveatTitle: "## READ THIS FIRST — what this report is not",
  caveatIntro:
    "**This is a triage list, not a verified audit.** `/loopSEC` runs without the hypothesis tree, and that removes every mechanism that made the other report's findings checkable:",
  caveatColMissing: "Not present",
  caveatColMeans: "What that means here",
  caveatNoTier: "**Only the findings that were RUN carry the REPRODUCED mark**",
  caveatNoTierWhy: "The rest are static claims. The summary gives both counts.",
  caveatNoFalsification: "**No falsification attempt**",
  caveatNoFalsificationWhy: "Nobody tried to prove any of these wrong. The false-positive rate is UNKNOWN, not low.",
  caveatNoChallenge: "**No challenge round**",
  caveatNoChallengeWhy: "Each finding is the auditor agreeing with itself.",
  caveatNoSeverity: "**No severity check**",
  caveatNoSeverityWhy: "Severity is the auditor's own judgement, made once, unreviewed.",
  caveatNoGate: "**No assertion gate**",
  caveatNoGateWhy: "A finding may be a vague statement of an area rather than a claim about behaviour.",
  caveatEnforced:
    "**What IS enforced: every finding carries an artifact.** A `file:line` or an evidence excerpt is required, so every line below can be opened and checked by hand. That is the only guarantee this mode makes, and it is why the requirement exists.",
  caveatRerun:
    "For findings you intend to act on, re-run the same objective under `/loop` — there the finding gets a tier, an attempt to refute it, and a challenge round.",

  summaryTitle: "## Summary",
  rowFindings: "Findings recorded",
  rowUnrated: "**no severity recorded**",
  rowPreAuth: "Reachable WITHOUT authentication",
  rowPostAuth: "Marked post-auth",
  rowUnassessed: "**Authentication NOT assessed**",
  rowNote: "Recon note recorded",
  rowReconRounds: (recorded, planned) => `Recon rounds (what this run can see)`,
  rowDeepSeed: "Seed context (the parent finding record, not a recon pass)",
  deepBanner: (findingId, title, parentDir) =>
    "> **This is a DEEP run, not a sweep.** Every round works one finding: `" +
    findingId +
    "` — " +
    title +
    "\n>\n> The context is the record `" +
    (parentDir === "." ? "the main run" : parentDir) +
    "` kept for it; there is no recon phase, and the work list is sub-questions.",
  rowVerified: "**Reproduced (ran, matched the pre-stated expectation)**",
  rowUnverified: "Static claims (nothing was run)",
  probesOffNote: (v, t) =>
    `\`allowCommandProbes\` is OFF, so **nothing was run** for this report: all ${t} finding(s) below are **static claims**. ` +
    `Turn it on (\`/loopsec config allowCommandProbes=true\`) to have the audit actually run its PoCs.`,
  probesOnNote: (v, t) => `**${v}/${t}** were run and matched the expectation stated before the run.`,
  verifyHeading: "**Verification**",
  verifyConfirmed: "REPRODUCED — the command below was actually run and matched the expectation stated before it",
  verifyNotConfirmed: "**NOT REPRODUCED** — it was run and did NOT match the pre-stated expectation: either the finding is wrong or the expectation was",
  noFindings:
    "**No findings were recorded.** That is a legitimate outcome — a run that invents findings to look productive is worse than one that comes back empty — but it is not evidence that the project is clean. See the unread list below.",

  coverageTitle: "## Coverage",
  rowCited: "**Files cited by a finding**",
  rowGapDirs: "**Directories with ZERO findings**",
  coverageNotMeasured: (why) => `_Not measured — ${why}. **Not measured is not fully covered.**_`,
  coverageNoGap:
    "Every directory of any size is cited by at least one finding. That is not the same as having been cleared — it only means there is no whole block left blank.",
  coverageGapNote:
    "> **A directory with no finding is not \"clean\", it is UNREAD.** These are the parts the recon note did not reach, and they bound how much of the project this run actually saw.",
  coverageGapLine: (dir, files) => `- \`${dir}\` — ${files} file(s), nothing recorded from it`,

  surfaceTitle: "## Attack surface",
  surfaceIntro:
    "What this run decided was worth looking at, and how far it got with each item. **\"Examined and guarded\" is a RESULT** — it is the only evidence that a part of the project was looked at and found sound.",
  rowSurfaceTotal: "**Items on the surface**",
  rowSurfaceExamined: "**Examined**",
  rowSurfaceCleared: "Examined and guarded",
  rowSurfaceProductive: "Produced a finding",
  rowSurfaceDigging: "**Still mid-dig (unsettled)**",
  rowSurfaceAttempted: "**Examined but unsettled**",
  diggingTitle: "## Still mid-dig",
  diggingNote:
    "These were read, and more rounds were **deliberately asked for**, but no conclusion was reached. They are neither \"examined and guarded\" nor \"never looked at\" — they are an unfinished trace.",
  diggingLine: (id, title, used, budget) => `- **${id}** ${title} — ${used}/${budget} depth round(s) used, still unsettled`,
  rowSurfaceRounds: "**Rounds spent enumerating**",
  rowChains: "**Chains**",
  rowGated: (gated, total) => `**High findings blocked by a gate (near misses, pursued first)**`,
  chainTitle: "## Chains",
  chainNote:
    "These findings are **combinations of other findings** — no part of them reaches this on its own. They are usually the heaviest thing in the report: a write primitive alone is medium, and the same write into a file that gets executed is root code execution.",
  chainOfLabel: (ids) => `**Combines:** ${ids}`,
  chainLine: (id, sev, title, parts) => `- **${id}** [${sev}] ${title}
  - combines: ${parts}`,
  surfaceNone: "_This run never enumerated an attack surface._",
  surfaceAllExamined: "Every item on the list has been examined.",
  surfaceOpenTitle: "## Not analysed",
  surfaceTouchedTitle: "## Examined but unsettled",
  surfaceTouchedNote:
    "These items were handed rounds and reached **no conclusion** — neither a named guard nor a finding. They are not \"never looked at\"; they are looked at and unfinished. Do not read this section as the one above it.",
  surfaceOpenNote:
    "These items were NEVER handed a round. **They are not clean, they are unread.**",
  surfaceClearedTitle: "## Examined and found guarded",
  surfaceClearedNote:
    "These items were read and traced, and the conclusion was NOT exploitable, for the reason given. This section matters as much as the findings above — it is what makes this an analysis rather than a list of bugs.",
  surfaceClearedLine: (id, title, reason, guard) => `- **${id}** ${title}\n  - ${reason}\n  - guard at: ${guard}`,
  surfaceOpenLine: (id, kind, title, where) => `- \`${id}\` [${kind}] ${title}${where ? ` — \`${where}\`` : ""}`,
  surfaceItemLabel: (id) => `**From surface item:** \`${id}\``,

  findingsTitle: (n) => `## Findings (${n})`,
  noneRecorded: "_None recorded._",

  notReadTitle: "## Not read",
  notReadNote: "These subtrees were never cited by a finding. They are not clean; nobody looked.",

  authPre: "**reachable WITHOUT authentication**",
  authPost: "needs authentication",
  authUnassessed: "**NOT ASSESSED** (not the same as pre-auth)",
  authShort: "auth:",
  metaSeparator: " · ",
  roundShort: (n) => `round ${n}`,
  surfaceShort: (id) => `surface ${id}`,
  pocHeading: "**How to run it**",
  chainHeading: "**Call chain**",
  notesHeading: "**Chain analysis**",
  evidenceHeading: "**Evidence**",
  gateHeading: "**Gate (what must hold to use it)**",
  gateOpen: "_(no remaining precondition — the gate is open)_",
  pursuitOpen: (spent) => `PURSUED: ${spent} round(s) spent attacking this gate, not yet opened.`,
  depthLine: (reasons, spent, budget) => `**Why this was deepened:** ${reasons} (${spent}/${budget} rounds spent)`,
  depthReasonGate: "it is a near miss behind a precondition — opening the gate beats finding another path",
  depthReasonDeepen: "it was marked a breakthrough when recorded",
  depthReasonUnproven: "high-or-worse and never once run — a static claim nobody tried to falsify",
  pursuitClosed: (spent, reason) => `Pursuit ended (${spent} round(s)): ${reason}`,
  notVerifiedShort: "_NOT VERIFIED: no tier · no refutation attempt · no challenge round_",
  notFalsifiedShort: "_Not falsified: nobody tried to refute it and there was no challenge round. RUNNING is not the same as CORRECT._",
  verifyCommand: "command",
  verifyExit: "exit",
  verifyExpect: "predicted before the run",
  verifyOutput: "output",
  verifyTimeout: "KILLED on timeout, did not finish",

  footer:
    "_Written by pi-audit-loopsec from `.pi-loopsec/` — the append-only log, the findings journal and the recon note. Re-run `/loopSEC report` to regenerate it from state._",
};

export const SEC_STRINGS: Record<ReportLanguage, SecStrings> = { zh: SEC_ZH, en: SEC_EN };

export function secStrings(lang: ReportLanguage): SecStrings {
  return SEC_STRINGS[lang];
}

/**
 * The coverage headline, in the reader's language.
 *
 * Lives here rather than in coverage.ts for the reason this file exists — and it has
 * to take PRIMITIVES rather than a `CoverageReport`, because coverage.ts imports this
 * module and the reverse would be a cycle.
 *
 * It is here at all because the line appears INSIDE the report: a Chinese report that
 * says `59 of 898 file(s) cited (7%)` has an English sentence in the middle of it,
 * which reads as a bug.
 */
export function coverageHeadlineText(
  lang: ReportLanguage,
  cited: number | null,
  total: number | null,
  untouched: number | null,
  truncated: boolean,
  reason: string,
): string {
  if (lang === "en") {
    if (total === null) return `not measured — ${reason}`;
    const pct = total === 0 ? 0 : Math.round((cited! / total) * 100);
    return (
      `${cited} of ${total} file(s) cited (${pct}%)` +
      ((untouched ?? 0) > 0 ? ` — ${untouched} in untouched subtrees` : "") +
      (truncated ? " — a lower bound, the walk hit its budget" : "")
    );
  }
  if (total === null) return `未测量 —— ${reason}`;
  const pct = total === 0 ? 0 : Math.round((cited! / total) * 100);
  return (
    `${cited} / ${total} 个文件被引用过（${pct}%）` +
    ((untouched ?? 0) > 0 ? ` —— 其中 ${untouched} 个位于完全未被触碰的子树中` : "") +
    (truncated ? " —— 这是下界，遍历碰到了预算上限" : "")
  );
}


