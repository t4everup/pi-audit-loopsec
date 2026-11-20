/**
 * pi-audit-loopsec — extensions/loop-sec/contract.ts
 *
 * THE CONTRACT: what counts as the result, stated once in full and reminded every round.
 *
 * The loop already carried an objective — a sentence like "挖掘认证前rce". That is a DIRECTION, and a
 * model reading it literally hunts a direct path: one unauthenticated entry, one sink. The most valuable
 * result in this mode is usually not that. It is a CHAIN — an unauthenticated entry plus one primitive
 * already recorded, reaching arbitrary command execution. Nothing in the objective says so, so the
 * contract says it.
 *
 * TWO LAYERS, because a wall of text repeated forty times is wallpaper:
 *   * the FULL text once, in the first recon brief — the round where the run decides what it is doing;
 *   * a SIX-LINE digest on every later brief, which is enough to keep the shape in view.
 *
 * And the file is SEEDED INTO THE PROJECT (`.pi-loopsec/contract.md`) so an operator can tighten it for a
 * target — a scope statement, a forbidden technique, a different endpoint bar — without touching code.
 * The seeded copy is what gets injected, so an edit takes effect on the next round.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { secStateDir } from "./store.js";

export const CONTRACT_FILE = "contract.md";

/**
 * The default contract.
 *
 * Kept as a list of {head, body} rather than one blob so the digest can be derived from it: a reminder
 * that drifts from the full text is worse than no reminder.
 */
export const CONTRACT_DEFAULT: ReadonlyArray<{ head: string; body: string }> = [
  {
    head: "起点",
    body:
      "攻击者未持有任何有效会话 / 口令 / token。若链路中途需要凭据，**获得凭据的过程本身也必须无认证可完成**（不得依赖「注册后由管理员批准」这类需要有人动手的前提）。",
  },
  {
    head: "路径",
    body:
      "不限跳数、不限漏洞组合。允许经过数据库、cron/后台任务、队列、文件、模板、日志消费者、子进程、第三方组件。**中间件不是终点。**",
  },
  {
    head: "组合",
    body:
      "链的每一跳必须由**上一跳的产物驱动**（A 写 → B 读 → B 的 sink）。各自独立成立的漏洞**并列不算一条链**。",
  },
  {
    head: "终点",
    body:
      "能以**任意服务账户**（apache / www-data / xdmod / mysql …）执行**攻击者指定的命令**。\n\n**不算终点：**仅时间/报错盲注、仅文件读、仅 DB 超级用户、仅能执行固定命令。",
  },
  {
    head: "基线",
    body:
      "先取目标版本指纹，以该版本对应的源码与 patch 历史为审计基线；源码与目标版本不一致时**以 diff 为准**（patch 给出「修复前长什么样」）。",
  },
  {
    head: "纪律",
    body:
      "每条断言给**完整链**（入口 → … → 终点）。任一跳是「假如/可能」必须标 **[假设]** 并给验证步骤。验证优先用只读/可回滚手段；落盘或改数据必须记录回滚证据。",
  },
];

export function contractPath(projectRoot: string): string {
  return path.join(secStateDir(projectRoot), CONTRACT_FILE);
}

/** The full text, as injected in the first recon round. */
export function renderContractFull(): string {
  const lines = ["--- 本次审计的验收标准（贯穿所有轮次）---"];
  CONTRACT_DEFAULT.forEach((c, i) => {
    lines.push("");
    lines.push(`**【${i + 1}】${c.head}**`);
    for (const l of c.body.split("\n")) lines.push(l === "" ? "" : `  ${l}`);
  });
  lines.push("");
  lines.push("**这六条不是建议，是「什么算结果」。** 一条只能读文件、只能盲注、只能跑固定命令的链");
  lines.push("不满足【终点】—— 把它记为中间能力（`sec_observe` 或一条发现），而不是最终结果。");
  return lines.join("\n");
}

/** The six-line reminder, for every round after the first. */
export function renderContractDigest(): string {
  const one = (s: string): string => s.split("\n")[0]!.replace(/。$/, "");
  return [
    "--- 验收标准（摘要，全文见 `.pi-loopsec/contract.md`）---",
    ...CONTRACT_DEFAULT.map((c, i) => `  ${i + 1}. **${c.head}** ${one(c.body)}`),
    "  → 每一跳由上一跳的产物驱动；只能读文件/只能盲注/只能跑固定命令 **不算终点**。",
  ].join("\n");
}

/**
 * Seed the file, then read it back.
 *
 * The FILE is the source of truth once it exists, so an operator's edit is what reaches the model. Seeding
 * is done once and never overwrites: an edited contract that got rewritten by the plugin would be a
 * setting that appears to be ignored.
 */
export function ensureContractFile(projectRoot: string): string {
  const file = contractPath(projectRoot);
  try {
    if (!fs.existsSync(file)) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const seeded = [
        "# 验收标准（本项目的 contract）",
        "",
        "> 这个文件是注入给模型的「什么算结果」。可以直接改；改动从下一轮开始生效。",
        "> 删掉或留空则回到内置默认。",
        "",
        renderContractFull(),
        "",
      ].join("\n");
      fs.appendFileSync(file, seeded, "utf-8");
    }
    return fs.readFileSync(file, "utf-8");
  } catch {
    return "";
  }
}
