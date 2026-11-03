# STABILITY — 已知缺陷与待办

> 目标：一个可以放心跑的版本。每一条都带证据（文件:行号），
> 并给出**怎么验证修好了**，而不是"应该没问题"。
>
> 最后更新：本轮稳定性复核之后。

---

## 一、本轮已修（6 项，均有回归测试）

| # | 缺陷 | 证据 | 后果 |
|---|---|---|---|
| 1 | `/loopsec config` 的正则写成 `/s+/`，少一个反斜杠 | `index.ts` `pairs` 解析 | 任何含 `s` 的键被切碎：`allowCommandProbes=true` → `["=true"]`，键变成空串，报 "unknown setting" 且**不告诉你错在哪**。而这个动词是开启 `sec_verify` 同意门的唯一文档化途径 |
| 2 | `runRound()` 直接调 `tickLoop`，绕过调度器 | `index.ts` `const runRound` | `/loopsec next` 和 `start`/`deep` 之后的自动首轮**不写 turn claim**，那一轮的工具调用会解析到操作者命令指向的运行 —— 在多运行项目里就是写错日志；同时跳过轮转 |
| 3 | `parkOnSendFailure` 不释放 turn claim | `loop.ts` `parkOnSendFailure` | 简报发送失败后 claim 残留，后续每次工具调用/操作者命令都解析到一个"没人在做的轮次" |
| 4 | `stopLoop` 不释放 turn claim | `loop.ts` `stopLoop` | 放弃一轮后 `use` 因"有轮次在飞"永久拒绝 —— **项目锁死**，无法指向别的运行 |
| 5 | turn claim 没有失效判定 | `store.ts` `readTurnClaim` | 崩溃后 claim 永久有效。现在改为**精确判定**：claim 记的轮号必须等于该运行的 `awaitingRound`，否则视为死 claim 并释放（不用超时，不用猜） |
| 6 | 终轮报告按 claim 解析路径 | `sec.ts` `writeSecReport` / `index.ts` 调用点 | 刚停止的运行的报告会写进"命令当前指向的那个运行"目录 —— **静默覆盖另一份审计的交付物** |

回归测试：`tests/sec.test.ts` 末尾 6 条（config 解析、死 claim 释放、stop 释放、park 释放、
报告写进已结束的运行、单运行项目路径不变）。**250 测试 / 0 失败。**

---

## 二、P0 — 稳定性，必须先做

### 2.1 多进程并发没有锁

**现状**：轮次认领（`active.json` 的 `turn`）只在**单进程**内成立。两个 pi 窗口打开同一个项目时，
两边都会 `listRuns` → `pickNextRun` → `claimTurn` → `tickLoop`，**互相覆盖对方的 claim 和日志**。

**为什么不能用文件锁**：本仓库禁止持有 fd / rename / link（非 NTFS 会 EISDIR），见
`store.ts` 顶部说明与 `tests/store.test.ts` 的守卫测试。

**可行方案**（都不碰 fd/rename）：
1. **目录锁**：`fs.mkdirSync(lock)` 是原子的，两个进程只有一个成功。锁里写 `{pid, at, run}`。
   失败方直接跳过本轮（不是报错）。
2. **陈旧锁**：`at` 早于 `max(10 分钟, 3×平均轮时长)` 视为死锁并覆盖 —— 进程被杀了要能自愈。
3. 加 `lockTtlMs` 设置（默认 600000）。

**验证**：起两个 `tickLoop` 循环（或两个 bun 进程）指向同一项目，断言总轮数 == 单进程轮数，
日志行数 == 轮数的常数倍，且没有任何一行的 run 归属错乱。

**优先级理由**：这是唯一会**静默损坏审计记录**的剩余问题，而记录是这份工具的产出本身。

### 2.2 `active.json` 每次派发写两遍

`loop.ts:863` 和 `:874` —— 先按旧轮号认领，发送成功后再按真实轮号重认领。
两次之间如果进程被杀，claim 的轮号就与 `awaitingRound` 不一致；因为 5 号修复把它判为死 claim，
**行为是安全的**（释放而不是死锁），但仍是一次不必要的写。
优化：把 `round` 从 claim 里去掉，只依赖 `awaitingRound` 判定归属；或让 `tickLoop` 返回轮号后再写一次。

**优先级**：P1（正确性已由 5 号修复兜住，不是缺陷）。

---

## 三、P1 — 应做，影响日常使用

### 3.1 深挖之后无法"回到扫描"的明确语义

`deep end` 现在停掉当前认领的深挖运行并释放 claim。但如果操作者先 `use` 了别的运行，
`deep end` 停的是**那个**运行（`endDeepRun` 用 `readActiveRun`）。语义应当明确成
`deep end [<name>]`：给了名字就停那个，没给就停最近创建的深挖运行。

**验证**：起扫描 + 两个深挖，`use` 到扫描后执行 `deep end`，断言扫描**没有**被停。

### 3.2 深挖找不到"父运行"之外的发现

`startDeepRun` 用 `parentSnapshot`（当前认领的运行）的 findings 找 F-id
（`loop.ts` `parentSnapshot.findings.find`）。若操作者的命令指向运行 A，而 F-0008 在运行 B，
`deep F-0008` 会拒绝并列出 A 的发现 —— 信息是错的。

**修**：在**所有**运行里搜这个 id，命中后把该运行记为父运行的 `parentDir`。

### 3.3 `sec_verify` 的输出截断按"字符"而非"字节"，且不脱敏

> 注意：`allowCommandProbes` 现在是**默认开启**（300s / 20k），所以这一条的风险面比之前大 ——
> 探针默认会跑，而输出（可能含口令/token）会原样写进 `tree.jsonl` 和报告。
> 另外没有针对破坏性命令的护栏：`DELETE|DROP|TRUNCATE|UPDATE|rm ` 之类的命令会被照跑不误，
> 唯一的刹车是每个项目可以 `/loopsec config allowCommandProbes=false`。

`maxOutputChars` 默认 8000。命令输出里可能有 token/密码（例如连库的 PoC），
现在会原样进入 `tree.jsonl` 和报告。审计工具把凭据写进交付物是危险的。

**修**：写前做一次**保守**脱敏（`(?i)(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*\S+` → `=***`），
并在报告里说明"已脱敏，原值未保存"。不要假装脱敏完整 —— 写明它是尽力而为。

### 3.4 没有时间预算

只有轮数（`maxRounds`）和平台（`plateauWindow`）。一整轮可能几十秒到几分钟，
"再跑 20 轮"在真实项目上可能是两小时。

**修**：`/loopsec pause 30m`，以及 `maxActiveMs` 设置。实现位置在 `tickLoop` 的
"operator round budget" 分支旁边（`loop.ts:1444` 附近），`loopTiming` 已经算好了 `activeMs`。

### 3.5 `pursuitSpent` 在派发时自增，吃掉了 plateau 名额

`loop.ts:1822`：`updateFinding(..., { pursuitSpent: +1 })` 发生在**派发前**，所以一次
"派发了但简报没送达"的轮次也算花掉了预算。深挖预算本来就是稀缺资源。

**修**：改到 `evaluateRound` 里，按"这一轮确实存在"记账（和 `findingCountAtStart` 的基线判定同一个位置）。

### 3.6 报告每轮重写 + 每轮全项目扫盘

`loop.ts:1753` 每轮调 `secCoverage(snapshot, projectRoot)`，它走整个项目目录
（`maxFilesScanned` 默认 4000）；`:1855` 每轮重写一遍完整报告。netbox/sentry 这类规模上，
**每轮都要走一遍几千个文件**。

**修**：
- 覆盖报告缓存 + 失效条件（项目文件 mtime 或每 N 轮一次）；
- 报告每轮只写"增量"或仅在线程空闲/轮次结束时写；`/loopsec report` 永远强制全量。

**验证**：8000 文件的项目，跑 20 轮，断言 `readdir` 调用次数从 20×N 降到 ≤3×N。

### 3.7 `secStateDir` 的回退会折所有日志

`store.ts:558`：没有 claim 可解析时（例如 legacy 单运行项目、或刚 `stop` 完），
`listRuns` → `describeRun` → `loadFrom` 会**完整折每一条日志**。而 `secStateDir` 在
**每一次工具调用**上都会走到。

**修**：回退时只需判断"有几条运行"，不必知道它们的状态 —— 用 `fs.existsSync` 数目录即可。

**验证**：放 5 个各 5000 事件的运行，删掉 `active.json`，测一次 `loadSec` 的耗时
（修前应是 O(25000 行)，修后 O(1)）。

---

## 四、P2 — 优化，规模上才会遇到

| 项 | 位置 | 说明 |
|---|---|---|
| `pickNextRun` 每个运行折两次 | `loop.ts` `pickNextRun` | `listRuns` 折一次、`loadSecIn` 再折一次。5 个运行 = 每轮 10 次全量折。可让 `describeRun` 顺带返回 `awaitingRound` |
| `findRun` 用 `listRuns`（全折） | `store.ts` `findRun` | `use <name>` 触发。只匹配目录名时不需要读日志 |
| `listRuns` 对 1000+ 运行线性 | `store.ts:313` | 目前按名字字典序（`sec001..sec999` 正确，靠补零）。超过 999 需要数字排序。**当前不是 bug**，写在这里是因为补零是隐式依赖 |
| `recon.md` 与 `tree.jsonl` 双写 | `sec.ts` `submitSecRecon` | 已有注释说明：镜像不是记录。可接受，别让它变成第二真相 |
| 报告全文嵌在 `SEC-FINDINGS.md` | `sec.ts` `appendSecLedger` | 每轮追加，文件会线性长大。可考虑只追加"本轮变化" |

---

## 五、明确不做（附理由，避免以后反复讨论）

- **二进制/反编译审计**：超出源码审计范围，且需要另一套证据模型。
- **真并发多轮**（两条简报同时飞）：一个对话只能有一轮在飞；强行并发会让两轮的
  `sec_finding` 无法归属。现在的**轮转**是唯一正确的形态。
- **多模型评审**：需要宿主侧编排，不属于本扩展。
- **自动修复补丁**：这是审计工具，产出是报告，不是改代码。

---

## 六、验收清单（达到即"稳定"）

按顺序跑，每项都有明确的通过条件：

1. `bun test` → **0 失败**（当前 250）。
2. 扩展单文件类型检查无 `error TS`（整仓 `tsc` 在本机会 OOM，见下）。
3. **单运行项目**：旧 `.pi-loopsec/tree.jsonl` 无 `active.json`，`status`/`report` 正常。
4. **多运行**：起 2 个运行，`ls` 顺序正确，`status` 各自独立，跑 10 轮后两个都有进展
   且互不污染（`sec001` 的发现数不变）。
5. **深挖**：`deep F-0001` 建 `runs/secNNN-deep-F0001-<标题>/`，父运行**仍在 running**；
   `deep end` 只停深挖运行；再次 `deep F-0001` **重开同一个目录**（编号不变）。
6. **发送失败**：mock `sendUserMessage` 抛错，断言运行被 pause、claim 被释放、
   `/loopsec use` 仍可用。
7. **崩溃窗口**：手写一个 `active.json` 指向没有 `tree.jsonl` 的目录，断言
   `secStateDir` 回退、`deep end` 能释放、工具不崩。
8. **路径逃逸**：`active.json` 指向 `../../etc`、绝对路径、`runs/..`，全部拒绝。
9. **配置**：`/loopsec config allowCommandProbes=true` 之后 `sec_verify` 可用，
   写进 `.pi-loopsec/settings.json`，并且 `sec_verify` 的拒绝信息不再指向不存在的命令。
10. **报告归属**：两个运行各跑一轮，断言两个 `SEC-REPORT.md` 内容不同、互不覆盖。

---

## 七、环境限制（不是缺陷，但会误导人）

- **整仓 `tsc` 在本机会 OOM**（可用内存 < 1GB）。用单文件：
  ```
  node --max-old-space-size=2560 ./node_modules/typescript/bin/tsc --noEmit \
    --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2023 \
    --types node --strict --noUncheckedIndexedAccess --skipLibCheck \
    --allowImportingTsExtensions extensions/loop-sec/*.ts
  ```
- **`python3` 是 Windows Store 占位程序**，静默退出。改文件请用 `write`/`edit` 工具或 node，
  并且**写入后读回断言** —— 本轮有 3 次补丁"打印成功但文件没变"，都是这样才发现的。
- **测试不能在安装克隆里依赖宿主**：`index.ts` 会拉进 `tools.ts` → `@earendil-works/pi-coding-agent`，
  该模块由宿主提供、克隆的 `node_modules` 里没有。所以解析器单独放在 `args.ts`（零 import）。
- **bash heredoc 会吃掉反引号 / `${` / 反斜杠**：不要用 heredoc 写含模板字符串的代码。
