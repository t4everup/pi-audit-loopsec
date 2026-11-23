# pi-audit-loopsec

A source-code audit engine for [pi](https://github.com/earendil-works/pi-coding-agent).
Point it at a project, give it an objective, and it enumerates the attack surface,
works one item at a time, and produces a triage report you can open line by line.

**One command: `/loopsec`.** The hypothesis modes (`/goal`, `/loop`, `/hypothesis`)
and their tools were removed — an extension whose surface lists modes it no longer
drives is how a model starts a run that nothing will evaluate. What survives from
the old engine is exactly what a triage run needs: the append-only event log and
its fold, the loop state machine (round cap, plateau, pause budget, the
anti-stacking fence), operator notes, settings, coverage walking, and the brief
assembly.

## Install

```bash
git clone https://github.com/t4everup/pi-audit-loopsec
# symlink or copy it where pi loads extensions, then /reload
```

## The round loop

```text
/loopsec "<objective>"      one command; no contract, no finish line
   │
   ├─ recon       map the project, then read the request lifecycle and the auth wiring
   │              (2 rounds by default; the note SETS THE CEILING)
   ├─ pursue      a finding one hop from the objective — depth beats the plan
   │              (3 rounds per finding, capped, and exempt while it holds a grant)
   ├─ combine     one slot spent asking whether two recorded findings form a CHAIN
   │              (every 6 rounds; pursuit outranks it, the plan does not)
   └─ surface / analyze
                  ├─ surface: enumerate the attack surface into a work list
                  │  └─ "all examined" means ENUMERATE MORE, not "finished"
                  └─ analyze: work ONE item, all the way down
                     ├─ the item is ASSIGNED by the loop, not chosen by the model
                     ├─ a depth round (sec_dig) is budgeted, never automatic
                     ├─ examining an item and finding it GUARDED is a RESULT (sec_clear)
                     ├─ blocked items (requires=) are not candidates until their prereq answers
                     └─ "looked at it, no conclusion" is its own status
   the report regenerates EVERY round; watch it fill in
```

Plateau: `plateau=8` (default) consecutive unproductive rounds stop the run.
`maxRounds=0` (default) is unbounded. Never two surface-side rounds in a row.

See **[STABILITY.md](STABILITY.md)** for the known-defect list, the remaining work, and the
acceptance checklist for a version that is safe to run unattended.

## The tools

| tool | what it does |
|---|---|
| `sec_recon` | the ONE recon pass; sets the ceiling of what the run can see |
| `sec_surface` | enumerate the attack surface — a COORDINATE, never a claim |
| `sec_finding` | record a finding — **must carry `file:line` or an evidence excerpt** |
| `sec_clear` | mark an item examined and guarded. The reason must NAME the guard, `file`+`line` must point at it |
| `sec_dig` | hand the SAME item another bounded round |
| `sec_reopen` | withdraw a clearance: the guard does not actually hold |
| `sec_update` | correct a finding instead of recording a duplicate; on an `S-` id it changes `requires` / `priority` / `title` |
| `sec_verify` | run ONE command against a finding, with its `expect` stated first |
| `sec_observe` | write down a **fact** the code showed you (not a finding) — `file:line`, or `files` for a module/build |
| `sec_recall` | search what the run has established: observations, findings AND clearances |
| `sec_show` | open one record in full — the brief truncates at **12** findings and **12** clearances |
| `sec_escalate` | ask for MORE rounds on ONE item, with a reason — granted, clamped at +12 |

`sec_observe` / `sec_recall` / `sec_show` are the **read side**. Without them the brief was the only
channel and had to truncate, and a truncated record with no way back is a lost record: a round would
re-read a file somebody had already cleared. The brief can now stay small, because nothing has to be
carried in it.

### Asking for more rounds — `sec_escalate`

Every depth budget used to be a constant, so the only party that had READ THE CODE could change the
order (`priority`) and the reason (`deepen`) but never the amount. That is the wrong place for the
judgement:

```text
sec_escalate id=F-0008 rounds=5 reason="守卫只读 query，处理器读 body，只差一跳就能认证前触发"
```

- **granted and clamped**: +12 rounds per item, however many times you ask;
- **the reason is required** (20+ chars) and must say what is LEFT — "it is important" is refused;
- the response always states the **effective** budget, because a model that asked for 40 and got 12
  must know it got 12;
- an escalated finding is **exempt from the depth ratio** (3 in a row / half of the last 10), because
  that ratio exists to stop an UNASKED-FOR depth run from starving breadth;
- the reason is recorded as an observation, so the grant is auditable in the record.

### A COMBINE round — the pair is a slot, not a paragraph

The contract says "各自独立成立的漏洞并列不算一条链". That is a rule, and a rule a busy round can skip. So
one round every six is spent on it, with three things the analyze brief cannot give: the **full**
findings list (that one truncates at 12), **what each finding offers** derived mechanically from its
class (写文件 / 读文件 / 出网·触内网 / 跨过一道访问控制 / 一个凭据 / 执行代码), and the three questions
that separate a chain from a coincidence (does A's product feed B, where is the gap, does the START
still hold).

A pass that concludes "these do not combine" is a result: record it with `sec_observe` and the round
is not empty. One that writes nothing counts against the plateau.

### Dependencies — the order of an audit is not its enumeration order

```text
sec_surface(title="有没有入口跳过守卫？", requires=["S-0001"], ...)
```

`S-0001` means: do not hand this item a round until `S-0001` is **cleared**. On a real finding the
decisive question was "does the guard read the same parameter the handler does?" — four other
questions rested on that premise and could not be answered before it, and a flat list made them
parallel.

- the bar is `cleared`, not `examined` — an item that produced a finding has not answered anything;
- a **cycle is refused at write time**, because a cycle never unblocks and would look like an item
  merely waiting its turn;
- `requires=[]` **clears** the list — a list that cannot be emptied cannot be corrected;
- no deadlock by construction: the graph is a DAG, so while any item is open there is always one
  whose prerequisites are satisfied.

## The contract — what counts as a result

The objective is a DIRECTION. A model reading it literally hunts one unauthenticated entry into one
sink, and the result that matters here is usually a **chain**. So the acceptance bar rides along with
every brief: **full text in the first recon round**, then a six-line digest on every round after —
because a page of rules repeated forty times is wallpaper.

```text
.pi-loopsec/runs/<run>/contract.md     # seeded once, editable per target, and what gets injected
```

The six clauses: **起点** (no session / password / token — and if a hop needs a credential, GETTING it
must also be doable unauthenticated), **路径** (unbounded hops; database, cron, queue, file, template,
log consumer, subprocess, third-party component — middleware is not the end), **组合** (each hop must
be driven by the previous hop's product; parallel bugs are not a chain), **终点** (arbitrary command
execution under any service account — file read only, blind injection only, a fixed command only, or
DB superuser only **do not count**), **基线** (fingerprint the target version; when source and target
disagree, the diff wins), **纪律** (every claim gives the whole chain; a "maybe" hop is marked
[假设]; verification prefers read-only, and anything that writes records how to roll back).

IT IS ENFORCED, not just printed. Two finding fields make the bar checkable:

| field | why it is a closed vocabulary |
|---|---|
| `impact` | the report **counts** "reached the bar"; free text would turn that count into a grep. `rce-arbitrary / rce-via-component / rce-scheduled` reach it; `file-read / blind-injection / fixed-command / db-superuser / …` explicitly do not. An unknown value is **recorded with a warning**, never refused — the artifact matters more than the label |
| `assumptions` | hops marked [假设]. A finding with assumptions **cannot** be counted as reaching the bar until each hop is verified |

The report's header states it and counts: `**达到【终点】: 1/3** 条发现`, plus how many are excluded by
assumptions and how many have no `impact` at all.

## The command

```text
/loopsec "<objective>" [maxRounds=0] [plateau=8] [focus=a,b]   # STARTS A NEW RUN
/loopsec ls                     # every run, and how far each got
/loopsec use <name>             # point your next command at one run
/loopsec status | pause [n] | resume [n] | stop | next
/loopsec tree | log | report | note <text> | context <text> | notes
/loopsec deep <F-id> [maxRounds] [说明…] | deep status | deep end
/loopsec dismiss | show | help
```

An objective that is GIVEN starts a new run; a bare `/loopsec` continues the run your
commands point at.

## Several runs at once

Every run lives in its own directory, named from the objective:

```text
.pi-loopsec/
  runs/
    sec001-挖掘认证前漏洞/    tree.jsonl  SEC-REPORT.md  recon.md  settings.json
    sec002-文件读取利用/      tree.jsonl  SEC-REPORT.md  recon.md  settings.json
  active.json                 which run your COMMANDS mean, and which a ROUND is working
```

They run **side by side**, not one at a time: starting a second run does not pause the
first, and `deep` is just another run rather than a takeover.

One conversation, so the rounds are interleaved: each settle settles whatever round was in
flight and gives the next one to the **least-recently-advanced** run. That rule is
self-correcting — a run that just took three rounds sinks to the back without anybody
counting turns, and a run you resume after an hour comes back to the front.

`active.json` holds **two** claims, and the split is what makes this work without touching
a single tool:

* **turn** — written when a brief is sent, released when the round settles. This is how a
  `sec_finding` called during that turn lands in the right run's log; the tools only see
  `ctx.cwd`, and they resolve this.
* **current** — what **you** mean when you type `report`, `status`, `note`. `use` sets it.

A pre-`runs/` project (one directory, no claim) still resolves with no pointer at all.

`focus=a,b` is a PREFERENCE, not a filter: it REORDERS the work list (an item whose
`categories` match is assigned before one enumerated earlier), and a finding found
outside them is still recorded.

## A DEEP run — one finding, its own folder

A sweep gives a finding three rounds (`pursuitRounds`) and then never returns it.
When that is not enough:

```text
/loopsec deep F-0008               # work ONE finding, in .pi-loopsec/runs/<name>/
/loopsec deep F-0008 30             # with a round cap
/loopsec deep F-0008 重点关注绕过     # with the operator's own steer
/loopsec deep status               # sub-questions, new findings, budget
/loopsec deep end                  # hand the project back to the sweep
```

A deep run is not a sweep with a bigger budget. Its work list is **SUB-QUESTIONS** —
"which parameter does the guard read, and which does the handler read?" — because the
round after the seed has to produce the *next* question. Repeating the same playbook
for twenty rounds is what the sweep already did for three.

- The run you came FROM is **not paused** — the whole point is that it keeps going. `deep end`
  stops the deep run itself (so it stops taking scheduler turns) and leaves everything else alone.
- `deep <F-id>` on a finding that already has a run **REOPENS** it — round, sub-questions and
  findings kept, and resumed if it had stopped. `deep <F-id> <n>` raises a reached round cap in
  the same act.
- Both directions refuse while a round is **in flight**: the tools resolve the active run when
  they are *called*, so switching either way would write that turn into the wrong log. Use
  `/loopsec cancel` to clear it.
- `deep end` also releases a **half-built** run (pointer set, no run state — the crash window),
  because otherwise the project can only be recovered by deleting a file by hand.
- A trailing sentence is the operator's **steer** (`/loopsec deep F-0008 重点关注绕过`).
  `maxRounds`, if given, must come FIRST — the rest of the line is your words, verbatim.
  The steer is a DIRECTION, not a conclusion: the seed tells the run that if the axis turns
  out wrong it must say so ("按 X 方向查了，不成立，因为 …") rather than shape the finding
  to match it. Steer later with `/loopsec context <text>`.
- The seed is assembled **mechanically** from the parent finding's own fields. Nothing
  the parent did not record can appear in it.
- There is **no recon phase**: the run was opened FROM a finding, not from a map.
- A round **in flight** blocks `deep`: the tools resolve the active run when they are
  called, so switching mid-round would write that turn into the deep log.
- Settings **layer**: `runs/<run>/settings.json` overrides `.pi-loopsec/settings.json`, which
  overrides the user layer, key by key — so `allowCommandProbes` is inherited rather than lost.

## Probes: ON by default

`sec_verify` runs ONE shell command per finding — **the command the model wrote** — inside the
audited project, as you. That is the only thing here that touches anything outside the source tree.
It is **ON by default** (300s timeout, 20k output cap), because the difference between "I read the
sink" and "I made it fire" is the whole product.

Nothing to configure on a fresh project. What is left is the opt-out, for a target where a PoC has
side effects — a live service, a shared database:

```text
/loopsec config allowCommandProbes=false        # this project only
```

Turning it off does not stop the model from running anything (it has its own shell); it stops the
AUDIT LOOP from doing it unattended and from recording the result as verification. Every finding
then closes with `_未经验证：无等级 · 无证伪 · 无对抗复核_` and the overview says the report is
entirely static claims.

To change the defaults for every project at once (this is optional now):

```text
/loopsec config --global allowCommandProbes=true commandTimeoutMs=300000 maxOutputChars=20000
```

### A failing provider PAUSES, it does not STOP

The declared SDK says nothing about WHY a turn ended, so an exhausted quota, a dead network and a killed session all look alike from here: **a round with no tool call at all**. The loop used to keep sending briefs (burning whatever quota was left) and then STOP on the plateau with "the well looks dry" — a claim about the code that nothing supports, printed in the report.

After `pauseOnSilentRounds` (default **3**, 0 disables) consecutive silent rounds the run is **paused**, with a reason naming the likely causes and pointing at `resume`. It is checked BEFORE the plateau, because when both are due the environment is the likelier explanation and the one you can act on.

```text
3 轮连续没有任何工具调用 —— 可能是模型额度用尽、网络/供应商故障，或者会话被中断。
这不是对项目的任何结论（项目没被分析过一轮），所以运行被 PAUSE 而不是 STOP。
修好之后 /loopsec resume 会从第 3 轮继续。
```

`resume` clears the streak, so a fixed key does not re-pause on the next tick.

### Mutation needs its OWN consent

`allowCommandProbes` says this project may be probed. It does not say a probe may **change** something,
and the model writing the command cannot tell whether the target holds real data. So commands matching
`DELETE / DROP / TRUNCATE / UPDATE / INSERT / ALTER / GRANT / rm / rmdir / mv / shutdown / mkfs / dd`
are refused unless `allowDestructiveProbes=true` (default **false**).

The guard is tuned toward letting the audit READ: a leading read-only tool (`rg`, `grep`, `find`,
`awk`, `sed`, `cat`, `jq`, …) makes the rest of the line data, not instructions, so
`rg -n 'DELETE FROM' src/` still runs. It is a guard against a slip, not a sandbox — `find . -delete`
leads with `find` and gets through.

### Probe output is REDACTED, best-effort

A probe's output routinely carries the target's own credentials. Values after
`password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key` (= or :),
`Authorization: Bearer <jwt>` and bare JWTs are replaced with `***` **before anything is stored**; the
original is never kept. It is called best-effort everywhere, including in the report, because it is: a
blob with no key in front of it is not caught, and `SecVerification.redacted` records that something
was replaced so a reader does not assume those are the exact bytes.

### Three verdicts, not two

| verdict | meaning |
|---|---|
| `reproduced` | the run matched the expectation stated before it |
| `disconfirmed` | the run finished and contradicted it |
| **`inconclusive`** | the run **cannot speak to the finding**: it timed out, it was killed, or a declared precondition did not hold |

`sec_verify` takes `precondition` ("a valid session cookie", "the service is up on 8080") and
`preconditionHeld`. Declaring one and reporting `false` is how the model says "I could not test it" —
the alternative was recording "the service was down" as evidence the finding is wrong, and then saying
a vulnerability does not hold on the strength of a run that never tested it.

The checks run in that order: precondition first (a run without its session says nothing whatever the
exit code), then "did not finish", then the expectation. The verdict is **recomputed on read** — a log
that claims `inconclusive` beside an exit code that plainly reproduced is not trusted.

Layers, lowest priority first — a project file still overrides the user one, so a target that must
not be probed says so locally:

```text
~/.pi-loopsec/settings.json                        # every project (PI_LOOPSC_HOME overrides the dir)
<project>/.pi-loopsec/settings.json                # this project
<project>/.pi-loopsec/runs/<run>/settings.json     # this run
```

`/loopsec config` prints **where** `allowCommandProbes` came from, so a consent inherited from the
user layer is never silent — a gate nobody can locate is indistinguishable from no gate.

The command itself is bounded (timeout + output cap from settings) and must have its `expect`
stated BEFORE the run; `confirmed` is computed from the exit code and output, never from the
model's opinion of what the output means.

## State — `.pi-loopsec/`

| file | what it is |
|---|---|
| `tree.jsonl` | append-only event log; state is a fold over it |
| `SEC-REPORT.md` | the deliverable, regenerated every round |
| `SEC-FINDINGS.md` | the per-round journal |
| `OPERATOR.md` | a mirror of what the operator told the run |
| `settings.json` | optional; see the table below |
| `active.json` | `{current, turn}` — which run your commands mean, and which run the in-flight round is working |
| `runs/<name>/` | one directory per run: its own `tree.jsonl`, `SEC-REPORT.md`, `recon.md`, `settings.json` |
| `recon.md` | the recon note mirrored for re-reading (or a deep run's seed) |
| `contract.md` | the acceptance bar injected into every brief — editable per target |
| `turn.lock/` | one round at a time across PROCESSES (an atomic `mkdir`; `owner.json` names the pid) |
| `deep/<F-id>/` | a deep run's own `tree.jsonl`, `SEC-REPORT.md`, `recon.md`, `settings.json` |

### Settings that matter

| setting | default | what it changes |
|---|---|---|
| `allowCommandProbes` | **true** | may a probe RUN at all (300s / 20k bounds) |
| `allowDestructiveProbes` | **false** | may a probe MUTATE (DELETE / DROP / rm / …) |
| `pursuitRounds` | 3 | depth rounds per finding, before `sec_escalate` can add more |
| `reconRounds` | 2 | recon sections before the surface phase |
| `coverageEveryRounds` | 5 | how often the project walk runs |
| `pauseOnSilentRounds` | 3 | silent rounds (no tool call at all) before the run PAUSES; 0 disables |
| `lockTtlMs` | 1800000 | how long a round lock survives a dead process |
| `commandTimeoutMs` | 300000 | per-probe time budget |
| `maxOutputChars` | 20000 | per-probe output cap (after redaction) |
| `maxFilesScanned` | 4000 | the coverage walk budget |
| `reportLanguage` / `fenceLanguage` | zh / c | the report |
| `focus` | none | reorders the work list; never filters a finding |

**One ROUND in flight, many runs live — across PROCESSES too.** The eight tools resolve `active.json`'s turn claim, so
the round being worked determines where its writes go. That is why several runs can advance in rotation
without any of them knowing that the others exist.

A round lock (an atomic `mkdir`) makes that hold across windows: a second pi window on the same project
SKIPS its turn rather than interleaving. `lockTtlMs` (default 30 min) only matters for an owner that
cannot be asked — a **dead** owner is detected by pid liveness and taken over in milliseconds, so closing
a window mid-round does not leave the project locked. Re-entering the lock refreshes its timestamp, so a
long-running window is never taken for stale.

**exFAT-safe:** only `appendFileSync` and `writeFileSync`. No rename, no link, no
held descriptor. A torn last line is repaired, never silently swallowed.

A pre-existing sec project whose state still sits in `.pi-hypothesis/` migrates by
renaming the directory — the log format did not change. A project that ran the old
hypothesis modes keeps its `.pi-hypothesis/` untouched and unread.

## Performance — what a round costs

Two things dominated a long run and both are bounded now.

**The coverage walk** reads the project tree (up to `maxFilesScanned`, 4000 by default) to find
directories nothing has cited. Its output goes only into the report — the model never sees it and no
decision reads it. On a 3000-file project a fresh walk is **~1.2s**; it now runs every
`coverageEveryRounds` rounds (default **5**) and the report prints which round the figure is from.
`/loopsec report` always walks: an operator asking for the report wants the number now.

**The log fold** re-read and re-parsed the whole append-only log on every `loadSec` call, and a round
calls it three to four times. It is memoised on the log's `(size, mtime)` — an append changes the size,
so the memo cannot serve stale state — measured at **5.8ms → 2.1ms** per load on a 600-event log. Every
caller gets its own arrays, so one caller's `push` cannot corrupt the cache.

If a run feels slow on a large target, raise `coverageEveryRounds` before anything else:

```text
/loopsec config coverageEveryRounds=20
```

## The report

Grouped by severity, worst first. Each finding renders as six parts, in the order
a hunter reads them:

````markdown
### 1. F-0001 · 高危 · rce

> 认证前代理内部 objectstore：任意方法/头部/请求体转发并完整回显

`src/app/proxy.py:88` · 认证：认证前可达 · 第 3 轮 · 攻击面 S-0001

**怎么打**   → fenced PoC, manual request first
**调用链**   → fenced numbered path, one file:line per hop
**链子分析** → fenced sink→source reasoning
**物证**     → fenced excerpt at the sink
````

The caveat LEADS the report: no verification tier, no falsification attempt, no
challenge round. The one enforced guarantee is that every finding carries an
artifact you can open and check. A run that recorded nothing is stated as such —
a report that invents findings to look productive is worse than an empty one.

**A directory with no finding is not "clean", it is UNREAD**, and the report says
which subtrees were never touched.

## Design rules

- **A finding is a coordinate plus an artifact.** No artifact, no finding — the
  store drops one written without it, so a hand-edited log cannot put a bare
  claim back.
- **"Examined and guarded" is a RESULT.** It is the only evidence that a part of
  the project was looked at and found sound; clearing an item requires naming the
  guard, and a clearance can be reopened.
- **The executor suggests; the model decides.** Nothing in this extension grades
  severity, infers impact, or assumes reachability.
- **No model-generated summaries in the report.** Every line is derived from the
  recorded state; the model's words are quoted verbatim.
- **Domain knowledge lives in the extension, not a skill file** — the per-class
  ladders are questions, never conclusions.
- **The plugin SCHEDULES; the model decides.** What the loop controls: which item is next (rank, then
  `focus`, then `priority`), when depth outranks the plan, when a combine pass is due, the totals
  (plateau, round cap, +12 escalation). What the model controls: what is worth deepening (`deepen`),
  what should be looked at first (`priority`), how many rounds a breakthrough needs (`sec_escalate`),
  and every conclusion. A cap that decides the model's judgement is a bug; a cap that bounds one lead
  from starving the run is not.
- **A refusal must never destroy evidence.** A wrong `impact` word, a clearance with no line, a
  dependency naming a missing item — each of those is a WARNING that keeps the record, not a refusal
  that drops it. The one hard refusal left is "no artifact": that is what the mode is.
- **Absence is stated, never implied.** "No gates recorded" is not "no gates needed"; "not measured"
  is not "fully covered"; "not falsified" is not "correct".

## Removed: the hypothesis modes

`/goal`, `/loop`, `/hypothesis` and the eleven `hypothesis_*` tools once shared
this extension. Their code — the scheduler, the tree, the combination passes, the
`.md` report, the verify probes — is gone; the loop kinds stay in the type only
so an old log still folds and its loop still renders in status. Findings you
intended to act on were the reason the modes existed; if that need returns, the
git history has the whole tree.
