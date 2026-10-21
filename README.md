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
/start <objective>          one command; no contract, no finish line
   │
   ├─ round 1   recon       read the project once, submit the note (sec_recon)
   ├─ round 2   surface     enumerate the attack surface into a work list (sec_surface)
   ├─ round 3+  analyze     work ONE item, all the way down (sec_finding / sec_clear)
   │                            ├─ the item is assigned by the loop, not chosen by the model
   │                            ├─ a depth round (sec_dig) is budgeted, never automatic
   │                            ├─ examining an item and finding it GUARDED is a RESULT,
   │                            │   recorded (sec_clear) — the report shows it
   │                            └─ "looked at it, no conclusion" is its own status
   └─ the report regenerates EVERY round; watch it fill in
```

Plateau: `plateau=8` (default) consecutive unproductive rounds stop the run.
`maxRounds=0` (default) is unbounded. Never two surface-side rounds in a row.

## The tools

| tool | what it does |
|---|---|
| `sec_recon` | the ONE recon pass; sets the ceiling of what the run can see |
| `sec_surface` | enumerate the attack surface — a COORDINATE, never a claim |
| `sec_finding` | record a finding — **must carry `file:line` or an evidence excerpt** |
| `sec_clear` | mark an item examined and guarded. The reason must NAME the guard, `file`+`line` must point at it |
| `sec_dig` | hand the SAME item another bounded round |
| `sec_reopen` | withdraw a clearance: the guard does not actually hold |
| `sec_update` | correct a finding instead of recording a duplicate |

## The command

```text
/loopsec "<objective>" [maxRounds=0] [plateau=8] [focus=a,b]
/loopsec status | pause [n] | resume [n] | stop | next
/loopsec tree | log | report | note <text> | context <text> | notes
/loopsec deep <F-id> [maxRounds] [说明…] | deep status | deep end
/loopsec dismiss | show | help
```

`focus=a,b` is a PREFERENCE, not a filter: it REORDERS the work list (an item whose
`categories` match is assigned before one enumerated earlier), and a finding found
outside them is still recorded.

## A DEEP run — one finding, its own folder

A sweep gives a finding three rounds (`pursuitRounds`) and then never returns it.
When that is not enough:

```text
/loopsec deep F-0008               # work ONE finding, in .pi-loopsec/deep/F-0008/
/loopsec deep F-0008 30             # with a round cap
/loopsec deep F-0008 重点关注绕过     # with the operator's own steer
/loopsec deep status               # sub-questions, new findings, budget
/loopsec deep end                  # hand the project back to the sweep
```

A deep run is not a sweep with a bigger budget. Its work list is **SUB-QUESTIONS** —
"which parameter does the guard read, and which does the handler read?" — because the
round after the seed has to produce the *next* question. Repeating the same playbook
for twenty rounds is what the sweep already did for three.

- The sweep is **paused**, not stopped, and its log is never touched.
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
- Settings **layer**: `deep/F-0008/settings.json` overrides `.pi-loopsec/settings.json`
  key by key, so `allowCommandProbes` is inherited rather than lost.

## State — `.pi-loopsec/`

| file | what it is |
|---|---|
| `tree.jsonl` | append-only event log; state is a fold over it |
| `SEC-REPORT.md` | the deliverable, regenerated every round |
| `SEC-FINDINGS.md` | the per-round journal |
| `OPERATOR.md` | a mirror of what the operator told the run |
| `settings.json` | optional; `reportLanguage` (zh default), `fenceLanguage` (`c`), `pursuitRounds`, `reconRounds`, `allowCommandProbes` |
| `active.json` | which run is live. `deep/F-0008` while a deep run owns the project, absent for the sweep |
| `recon.md` | the recon note mirrored for re-reading (or a deep run's seed) |
| `deep/<F-id>/` | a deep run's own `tree.jsonl`, `SEC-REPORT.md`, `recon.md`, `settings.json` |

**One active run per project.** The eight tools have no idea which run they belong to —
they resolve `active.json` — so two live runs would write into each other's log. That
is why `deep` takes the project over instead of running beside it.

**exFAT-safe:** only `appendFileSync` and `writeFileSync`. No rename, no link, no
held descriptor. A torn last line is repaired, never silently swallowed.

A pre-existing sec project whose state still sits in `.pi-hypothesis/` migrates by
renaming the directory — the log format did not change. A project that ran the old
hypothesis modes keeps its `.pi-hypothesis/` untouched and unread.

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

## Removed: the hypothesis modes

`/goal`, `/loop`, `/hypothesis` and the eleven `hypothesis_*` tools once shared
this extension. Their code — the scheduler, the tree, the combination passes, the
`.md` report, the verify probes — is gone; the loop kinds stay in the type only
so an old log still folds and its loop still renders in status. Findings you
intended to act on were the reason the modes existed; if that need returns, the
git history has the whole tree.
