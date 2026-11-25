import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { BotBox, BoxRunner, BOX_EGRESS_PORT } from "./box.ts";
import type { BoxPlan } from "./plan.ts";
import { homeProgramsDistrusted } from "./program-trust.ts";
import { seatbeltArgs, seatbeltProfile } from "./seatbelt.ts";

const bridge = { socat: null, bridgeScript: "/app/dist-server/bot-box/box-bridge.js", node: "/usr/local/bin/node" };
const setup = {
  dataDir: "/data/.openmausbot",
  home: "/data",
  codeRoots: ["/app"],
  engineRoots: [] as string[],
  bridges: [{ name: "egress", port: BOX_EGRESS_PORT, socket: "/data/.openmausbot/box/egress.sock" }],
};

describe("Seatbelt profiles", () => {
  it("turns the plan's mounts into read grants, write grants and a deny over the hidden data folder", () => {
    const plan: BoxPlan = {
      mounts: [
        { kind: "ro", source: "/usr", target: "/usr" },
        { kind: "bind", source: "/data", target: "/data" },
        { kind: "tmpfs", target: "/data/.openmausbot" },
        { kind: "bind", source: "/data/.openmausbot/task-workspaces/b1/t1", target: "/data/.openmausbot/task-workspaces/b1/t1" },
        { kind: "ro", source: "/app", target: "/app" },
      ],
      options: [],
      net: "shared",
      writable: ["/data", "/data/.openmausbot/task-workspaces/b1/t1"],
      botId: "b1",
    };
    const profile = seatbeltProfile(plan);
    expect(profile).toContain("(deny default)");
    expect(profile).toContain(`(allow file-read* (subpath "/usr"))`);
    expect(profile).toContain(`(allow file-read* file-write* (subpath "/data"))`);
    expect(profile).toContain(`(deny file-read* file-write* (subpath "/data/.openmausbot"))`);
    expect(profile).toContain(`(allow file-read* file-write* (subpath "/data/.openmausbot/task-workspaces/b1/t1"))`);
    expect(profile).toContain(`(deny file-write* (literal "/data/.git") (subpath "/data/.git"))`);
    expect(profile).toContain("(allow network*)");
  });

  it("makes HOME readable but not writable when a turn may write only its own folders", () => {
    const plan: BoxPlan = {
      mounts: [
        { kind: "bind", source: "/data", target: "/data" },
        { kind: "bind", source: "/data/task-workspaces/b1/t1", target: "/data/task-workspaces/b1/t1" },
      ],
      options: [],
      net: "shared",
      writable: ["/data", "/data/task-workspaces/b1/t1"],
      botId: "b1",
    };
    const profile = seatbeltProfile(plan, { readOnlyHome: "/data" });
    expect(profile).toContain(`(allow file-read* (subpath "/data"))`);
    expect(profile).not.toContain(`(allow file-read* file-write* (subpath "/data"))`);
    expect(profile).toContain(`(allow file-read* file-write* (subpath "/data/task-workspaces/b1/t1"))`);
  });

  it("wraps a command after `--`", () => {
    expect(seatbeltArgs("(version 1)", "/usr/local/bin/claude", ["-p"])).toEqual(["-p", "(version 1)", "--", "/usr/local/bin/claude", "-p"]);
  });

  it("denies reads of the folders the plan hides", () => {
    const plan: BoxPlan = {
      mounts: [],
      options: [],
      net: "shared",
      writable: [],
      botId: null,
      readDeny: ["/tmp/worker-b"],
    };
    expect(seatbeltProfile(plan)).toContain(`(deny file-read* (subpath "/tmp/worker-b"))`);
  });
});

describe("BoxRunner with sandbox-exec", () => {
  it("runs the inner command under the profile, with the allow-listed environment and the host's network", () => {
    const runner = new BoxRunner({ sandboxExec: "/usr/bin/sandbox-exec", bridge, setup, denyEnv: new Set(["SECRET"]) });
    const wrapped = runner.wrap({
      command: "/usr/local/bin/claude",
      args: ["-p"],
      cwd: "/data/.openmausbot/task-workspaces/b1/t1",
      env: { PATH: "/usr/bin", HOME: "/data", SECRET: "x" },
    });
    expect(wrapped.command).toBe("/usr/bin/sandbox-exec");
    expect(wrapped.args[0]).toBe("-p");
    const separator = wrapped.args.indexOf("--");
    expect(separator).toBeGreaterThan(0);
    expect(wrapped.args.slice(separator + 1)).toEqual(["/usr/local/bin/claude", "-p"]);
    expect(wrapped.plan.net).toBe("shared");
    expect(wrapped.env).toEqual({ PATH: "/usr/bin", HOME: "/data" });
    expect(wrapped.extraFds).toEqual([]);
    expect(wrapped.token).toBeNull();
  });
});

describe.skipIf(process.platform !== "darwin")("Seatbelt on this Mac", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });
  const temp = () => {
    const dir = mkdtempSync(join(tmpdir(), "omb-seatbelt-"));
    dirs.push(dir);
    return dir;
  };

  it("writes inside the granted folder and is refused outside it", () => {
    const root = temp(), allowed = join(root, "allowed"), denied = join(root, "denied");
    mkdirSync(allowed);
    mkdirSync(denied);
    const plan: BoxPlan = { mounts: [{ kind: "bind", source: allowed, target: allowed }], options: [], net: "shared", writable: [allowed], botId: null };
    const command = `echo ok > ${allowed}/inside; echo no > ${denied}/outside`;
    spawnSync("/usr/bin/sandbox-exec", seatbeltArgs(seatbeltProfile(plan), "/bin/sh", ["-c", command]), { encoding: "utf8" });
    expect(readFileSync(join(allowed, "inside"), "utf8").trim()).toBe("ok");
    expect(existsSync(join(denied, "outside"))).toBe(false);
  });

  it("keeps HOME read-only while the turn's own folder stays writable", () => {
    const root = temp(), home = join(root, "home"), own = join(root, "data", "task-workspaces", "b1", "t1");
    mkdirSync(home, { recursive: true });
    mkdirSync(own, { recursive: true });
    const plan: BoxPlan = {
      mounts: [
        { kind: "bind", source: home, target: home },
        { kind: "bind", source: own, target: own },
      ],
      options: [],
      net: "shared",
      writable: [home, own],
      botId: "b1",
    };
    const command = `echo ok > ${own}/inside; echo no > ${home}/outside`;
    spawnSync("/usr/bin/sandbox-exec", seatbeltArgs(seatbeltProfile(plan, { readOnlyHome: home }), "/bin/sh", ["-c", command]), { encoding: "utf8" });
    expect(readFileSync(join(own, "inside"), "utf8").trim()).toBe("ok");
    expect(existsSync(join(home, "outside"))).toBe(false);
  });

  it("hides a sibling worktree from reads", () => {
    const root = temp(), own = join(root, "worker-a"), other = join(root, "worker-b");
    mkdirSync(own);
    mkdirSync(other);
    writeFileSync(join(own, "mine.txt"), "mine\n");
    writeFileSync(join(other, "secret.txt"), "other worker\n");
    const plan: BoxPlan = {
      mounts: [{ kind: "bind", source: own, target: own }],
      options: [],
      net: "shared",
      writable: [own],
      botId: null,
      readDeny: [other],
    };
    const read = (path: string) => spawnSync("/usr/bin/sandbox-exec", seatbeltArgs(seatbeltProfile(plan), "/bin/cat", [path]), { encoding: "utf8" });
    expect(read(join(own, "mine.txt")).stdout.trim()).toBe("mine");
    expect(read(join(other, "secret.txt")).stdout).toBe("");
  });

  it("hides the data folder and puts this turn's folder back", () => {
    const root = temp(), data = join(root, "data"), own = join(data, "task-workspaces", "b1", "t1");
    mkdirSync(own, { recursive: true });
    writeFileSync(join(data, "secret.txt"), "other conversations\n");
    writeFileSync(join(own, "deliverable.txt"), "this turn\n");
    const plan: BoxPlan = {
      mounts: [
        { kind: "bind", source: root, target: root },
        { kind: "tmpfs", target: data },
        { kind: "bind", source: own, target: own },
      ],
      options: [],
      net: "shared",
      writable: [root, own],
      botId: "b1",
    };
    const probe = (path: string) => spawnSync("/usr/bin/sandbox-exec", seatbeltArgs(seatbeltProfile(plan), "/bin/cat", [path]), { encoding: "utf8" });
    expect(probe(join(own, "deliverable.txt")).stdout.trim()).toBe("this turn");
    expect(probe(join(data, "secret.txt")).stdout).toBe("");
  });
});

describe("BotBox with Seatbelt", () => {
  const dirs: string[] = [];
  const boxes: BotBox[] = [];
  afterEach(async () => {
    for (const box of boxes.splice(0)) await box.stop();
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("starts without the Linux gates, reports the backend, and wraps turns", async () => {
    const dir = mkdtempSync(join(tmpdir(), "omb-seatbelt-box-"));
    dirs.push(dir);
    const box = new BotBox();
    boxes.push(box);
    const lines: string[] = [];
    const detection = await box.start({
      dataDir: join(dir, "data"),
      home: dir,
      port: 8799,
      denyEnv: new Set(),
      env: { OMB_BOT_BOX_HOME_READONLY: "1" },
      log: (line) => lines.push(line),
      detect: () => ({ box: "seatbelt", reason: null, tools: null, sandboxExec: "/usr/bin/sandbox-exec" }),
    });
    expect(detection.box).toBe("seatbelt");
    expect(lines).toEqual(["bot box: on (seatbelt filesystem sandbox, shared network)"]);
    // A read-only HOME cannot be used to plant a program, so the server may still resolve the engines installed there.
    expect(homeProgramsDistrusted()).toBe(false);
    expect(box.report()).toMatchObject({ box: "seatbelt", bridge: null, broker: { on: false }, checks: null });
    expect(box.broker()).toBeNull();
    expect(box.seccomp()).toBeNull();
    expect(await box.openRelay()).toBeNull();
    expect(box.browserBox(9, [])).toBeNull();
    const wrapped = box.wrap({ command: "/usr/bin/true", args: [], env: { PATH: "/usr/bin" } })!;
    expect(wrapped.command).toBe("/usr/bin/sandbox-exec");
    expect(wrapped.args).toContain("--");
    const canonicalDir = realpathSync(dir);
    expect(wrapped.args[1]).toContain(`(subpath "${canonicalDir}")`);
    expect(wrapped.args[1]).not.toContain(`file-write* (subpath "${canonicalDir}")`);
    expect(box.report().boxed).toBe(1);
  });
});
