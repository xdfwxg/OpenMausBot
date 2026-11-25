// The macOS half of the bot box: Seatbelt profiles from the same plan bubblewrap renders as mounts.
//
// bubblewrap builds a new filesystem and network namespace; Seatbelt can only allow or deny what the host already has.
// So the plan is read the other way: every read-only mount becomes a file-read grant, every bind a read-write grant, and a
// tmpfs over a folder (the data folder) becomes a deny placed after the grants it must carve out of. The last matching
// rule wins, which is how the data folder stays hidden while this turn's own folders are put back.
import { realpathSync } from "node:fs";
import { resolve } from "node:path";

import type { BoxPlan } from "./plan.ts";

const canonical = (path: string): string => {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
};

const quote = (path: string): string => `"${path.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;

/** Seatbelt matches the path the process opened, not the one it resolves to: grant `/tmp` and `/private/tmp` both. */
const both = (path: string): string[] => {
  const target = resolve(path), real = canonical(path);
  return target === real ? [target] : [target, real];
};

/** Device files a shell writes to; everything else under /dev is read-only. */
const WRITABLE_DEVICES = ["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/2"];

export interface SeatbeltOptions {
  /** `shared`: the host's network, as on a Mac without a network namespace. `isolated` currently has no gate here. */
  allowNetwork?: boolean;
  /** Make this folder readable but not writable (the server's HOME when a turn may write only its own folders). */
  readOnlyHome?: string;
}

/**
 * SBPL for one box. Rules are emitted in the plan's order: the HOME bind first, the data folder's tmpfs as a deny, then
 * the turn's own folders put back. A caller that only needs a filesystem check can pass a hand-made plan.
 */
export function seatbeltProfile(plan: BoxPlan, options: SeatbeltOptions = {}): string {
  const allowNetwork = options.allowNetwork ?? true;
  const rules: string[] = [
    "(version 1)",
    "(deny default)",
    "(allow process*)",
    "(allow signal)",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow ipc-posix*)",
    "(allow file-read-metadata)",
    // macOS has no mount namespace and the CLI reads too many system files to enumerate safely; reads stay open, and the
    // data folder is carved out by the deny below. A read allowlist needs a separate denyRead plan, not this backend.
    "(allow file-read*)",
    `(allow file-write* ${WRITABLE_DEVICES.map((path) => `(literal ${quote(path)})`).join(" ")})`,
  ];

  for (const mount of plan.mounts) {
    if (mount.kind === "symlink" || mount.kind === "proc" || mount.kind === "dev") continue;
    const targets = both(mount.target);
    const subpaths = targets.map((target) => `(subpath ${quote(target)})`).join(" ");
    if (mount.kind === "ro") {
      rules.push(`(allow file-read* ${subpaths})`);
      continue;
    }
    if (mount.kind === "bind") {
      const readOnly = options.readOnlyHome !== undefined && canonical(options.readOnlyHome) === canonical(mount.target);
      rules.push(`(allow file-read*${readOnly ? "" : " file-write*"} ${subpaths})`);
      continue;
    }
    if (mount.kind === "dir") {
      rules.push(`(allow file-read* file-write* ${subpaths})`);
      continue;
    }
    // tmpfs: /tmp and its friends are the host's temp on macOS, but the data folder is hidden with a deny.
    if (targets.includes("/tmp") || targets.includes("/var/tmp") || targets.includes("/run")) {
      rules.push(`(allow file-read* file-write* ${subpaths})`);
      continue;
    }
    rules.push(`(deny file-read* file-write* ${subpaths})`);
  }

  // Folders the plan hides from reads (a worker's sibling worktrees): a deny after every grant, because the last
  // matching rule wins.
  for (const path of plan.readDeny ?? []) {
    for (const target of both(path)) rules.push(`(deny file-read* (subpath ${quote(target)}))`);
  }

  // A worktree's .git is how candidates are submitted; the engine may read it, but a boxed turn never edits it.
  for (const root of plan.writable) {
    const git = both(resolve(root, ".git"));
    const literals = git.map((path) => `(literal ${quote(path)})`).join(" ");
    const subpaths = git.map((path) => `(subpath ${quote(path)})`).join(" ");
    rules.push(`(deny file-write* ${literals} ${subpaths})`);
  }
  if (allowNetwork) rules.push("(allow network*)");
  return rules.join("\n");
}

/** `sandbox-exec` argv for a profile and the command it wraps. */
export function seatbeltArgs(profile: string, command: string, args: readonly string[]): string[] {
  return ["-p", profile, "--", command, ...args];
}
