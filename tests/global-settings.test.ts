import { loadSettings, saveSettings, settingsPath, userSettingsPath } from "../extensions/loop-sec/settings.ts";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import * as assert from "node:assert/strict";

test("--global applies to every project; a project file still overrides it", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "home-"));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "proj-"));
  process.env.PI_LOOPSC_HOME = home;

  // Nothing set anywhere: the built-in defaults already allow probes, so a project needs no file at all.
  assert.equal(loadSettings(proj).settings.allowCommandProbes, true);
  assert.equal(loadSettings(proj).source, "defaults");
  assert.equal(loadSettings(proj).provenance?.allowCommandProbes, undefined, "a default has no file to name");

  // A global write still has a purpose: it can OVERRIDE the default for every project, and it is
  // recorded as the source so the change is locatable.
  const g = saveSettings(proj, { allowCommandProbes: false, commandTimeoutMs: 240_000 }, { global: true });
  assert.equal(g.ok, true, g.errors.join("; "));
  assert.equal(fs.existsSync(path.join(home, "settings.json")), true, "written to the USER layer");
  assert.equal(fs.existsSync(settingsPath(proj)), false, "and NOT into the project");

  const other = fs.mkdtempSync(path.join(os.tmpdir(), "proj2-"));
  const loaded = loadSettings(other);
  assert.equal(loaded.settings.allowCommandProbes, false, "a second project inherits the global override");
  assert.equal(loaded.settings.commandTimeoutMs, 240_000);
  assert.equal(loaded.settings.maxOutputChars, 20_000, "and the other key keeps its built-in default");
  // Provenance names the file, so the gate is locatable.
  assert.equal(loaded.provenance?.allowCommandProbes, path.join(home, "settings.json"));
  assert.equal(userSettingsPath(), path.join(home, "settings.json"));

  // A project that MUST be probed says so locally, and wins.
  const local = saveSettings(other, { allowCommandProbes: true });
  assert.equal(local.ok, true);
  const over = loadSettings(other);
  assert.equal(over.settings.allowCommandProbes, true, "the project layer overrides the user layer");
  assert.equal(over.settings.commandTimeoutMs, 240_000, "and inherits the rest");
  assert.equal(over.provenance?.allowCommandProbes, settingsPath(other));
  assert.equal(over.provenance?.commandTimeoutMs, path.join(home, "settings.json"));

  delete process.env.PI_LOOPSC_HOME;
});

test("a deep run inherits the user layer too", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "home3-"));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "proj3-"));
  process.env.PI_LOOPSC_HOME = home;
  saveSettings(proj, { commandTimeoutMs: 240_000 }, { global: true });
  const deepDir = path.join(proj, ".pi-loopsec", "runs", "sec001-x");
  fs.mkdirSync(deepDir, { recursive: true });
  fs.writeFileSync(path.join(deepDir, "tree.jsonl"), "", "utf-8");
  fs.writeFileSync(path.join(proj, ".pi-loopsec", "active.json"), JSON.stringify({ current: { dir: "runs/sec001-x", run: "sec001-x" } }), "utf-8");
  assert.equal(loadSettings(proj).settings.commandTimeoutMs, 240_000, "the same global value, inside a deep run");
  delete process.env.PI_LOOPSC_HOME;
});
