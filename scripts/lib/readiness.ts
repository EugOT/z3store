/**
 * Readiness gate bridge (readiness/v1). The canonical contract and validator
 * live in Eugene3dotdev/dotfiles readiness/; .readiness/readiness.nu is the
 * vendored copy pinned by .readiness/lock.yaml. This module only resolves a
 * Nushell runtime and runs that validator — no policy lives here.
 *
 * Runtime resolution mirrors lib/zig.ts: `mise x aqua:nushell/nushell@<pin>`
 * when mise is present (pin from .mise.toml), else bare `nu` on PATH, else a
 * structured failure. The gate is fail-closed: a missing runtime, a missing
 * LINEAR_API_KEY (unless Z3_READINESS_RECORD points at a saved issue
 * description), or any verdict other than `ready` fails the tier.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { repoRoot, type SpawnResult, spawnSync } from "./runtime.ts";

const NU_PIN = "0.109.1";
const VALIDATOR = ".readiness/readiness.nu";

function nuCommand(root: string): string[] | null {
	if (Bun.which("mise") !== null) {
		return ["mise", "x", `aqua:nushell/nushell@${NU_PIN}`, "--", "nu"];
	}
	if (Bun.which("nu") !== null) return ["nu"];
	void root;
	return null;
}

export type ReadinessOptions = {
	tier: "pr" | "release";
	requireEvidence?: boolean;
};

/**
 * Run the readiness check for the current change. Returns the spawn result
 * of `readiness.nu check`; callers fail the tier on a non-zero code.
 */
export function runReadinessCheck(opts: ReadinessOptions): SpawnResult {
	const root = repoRoot();
	const validator = join(root, VALIDATOR);
	if (!existsSync(validator)) {
		return {
			code: 1,
			stdout: "",
			stderr: `readiness: ${VALIDATOR} is missing; re-vendor it from Eugene3dotdev/dotfiles readiness/readiness.nu`,
		};
	}
	const nu = nuCommand(root);
	if (nu === null) {
		return {
			code: 127,
			stdout: "",
			stderr: `readiness: no Nushell runtime (install mise, or nu ${NU_PIN}); the gate fails closed`,
		};
	}
	const lock = spawnSync([...nu, "--no-config-file", validator, "lock"], {
		cwd: root,
	});
	if (lock.code !== 0) return lock;

	const args = [...nu, "--no-config-file", validator, "check"];
	const issue = process.env.Z3_READINESS_ISSUE;
	if (issue && issue.length > 0) args.push("--issue", issue);
	const record = process.env.Z3_READINESS_RECORD;
	if (record && record.length > 0) args.push("--record", record);
	const base = process.env.Z3_READINESS_BASE;
	if (base && base.length > 0) args.push("--base", base);
	if (opts.requireEvidence) {
		args.push("--require-evidence");
		const ref = process.env.Z3_READINESS_REF;
		if (ref && ref.length > 0) args.push("--ref", ref);
	}
	return spawnSync(args, { cwd: root });
}
