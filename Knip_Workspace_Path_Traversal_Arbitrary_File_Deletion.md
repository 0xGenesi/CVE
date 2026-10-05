# knip (main) Workspace Config Path Traversal — Arbitrary File Deletion/Tampering Outside the Project via `knip --fix`

### Summary

knip (`main` branch, https://github.com/webpro-nl/knip), the widely-used unused-code detector, does not validate that resolved workspace directories stay inside the project root (`cwd`). Workspace entries are accepted from `knip.json`'s `workspaces` key (including `../victim` relative paths) and from `package.json`/`pnpm-workspace.yaml` `workspaces` globs (including absolute paths). The pinned dependency tinyglobby 0.2.17 (independently tested) happily matches `../` and absolute glob patterns, so files outside the repository are pulled into the scan. Files not referenced by any entry are then reported as *Unused files*, and `knip --fix` feeds those out-of-repo absolute paths into three dangerous sinks in `packages/knip/src/IssueFixer.ts:52-93` with no path-boundary check: `rm(issue.filePath)` (permanent deletion), `join(cwd, filePath)` + `writeFile` (content tampering of external sources), and external `package.json` rewriting.

An attacker who commits a malicious workspace config to any repository can therefore delete or corrupt arbitrary JS/TS files (and `package.json` files) belonging to other projects on the machine of a developer or CI runner who executes `knip --fix` inside the malicious checkout — a supply-chain-shaped arbitrary file destruction primitive.

Dynamically verified 2026-10-05 with an end-to-end sandbox PoC (exit code 0): `join(cwd, dir) = /tmp/knip-poc/victim-external`, `dir escapes cwd? true`, external files scanned as `unused`, external `package.json` dependencies removed by default `--fix`.

This is CWE-22: Improper Limitation of a Pathname to a Restricted Directory (write/delete primitive), in a supply-chain context (CWE-1357-ish trust of repository content).

### Details

**Root cause.** knip treats repository content as trusted input to filesystem-modifying operations. The designed trust boundary is the project root — knip should only scan, write, or delete inside `cwd` — but no component enforces that boundary during workspace resolution or in the fixer's file operations.

**Source-to-sink path:**

1. **Source (attacker-controlled config).** `getAdditionalWorkspaceNames` (`packages/knip/src/ConfigurationChief.ts:250-257`) accepts `knip.json` `workspaces` entries verbatim (including `../victim`); `package.json`/`pnpm-workspace.yaml` entries are read at `packages/knip/src/util/create-options.ts:94-100`. Relative-path variants must use the `knip.json` key (the unanchored regex at `ConfigurationChief.ts:226` mangles relative manifest entries into `.x`); absolute-path globs work from either source.
2. **Workspace resolution escapes the root.** `ConfigurationChief.ts:196` `join(this.cwd, dir)` resolves `../victim-external` to an absolute path outside cwd (measured: `/tmp/knip-poc/victim-external`, `relative(cwd, dir) = "../victim-external"`).
3. **Out-of-repo manifests match.** `mapWorkspaces` (`packages/knip/src/util/map-workspaces.ts:21-31`) globs e.g. `../victim-data/personal/package.json` via tinyglobby 0.2.17, which returns cwd-external matches.
4. **Out-of-repo project scan.** The default project pattern `**/*.{js,ts,...}` is concatenated with the escaped workspace dir by `prependDirToPatterns` (`packages/knip/src/util/glob.ts:27-28`); `glob-core.ts:291-334` calls tinyglobby with `absolute: true` (`followSymbolicLinks: false` — symlinks are not the entry point here).
5. **Issue generation.** Unreferenced out-of-repo files are reported as unused files (`packages/knip/src/graph/analyze.ts:370-374`); `IssueCollector` (`packages/knip/src/IssueCollector.ts:136-157`) keeps `issue.filePath` as an absolute out-of-repo path keyed as `../victim-project/xxx.ts`.
6. **Sinks — `IssueFixer` (no boundary checks):**
   - `removeUnusedFiles` (lines 52-59): `await rm(issue.filePath)` — permanent deletion of out-of-repo files (`knip --fix --allow-remove-files`).
   - `removeUnusedExports` (lines 81-93): `join(this.options.cwd, filePath)` does not neutralize `../`; `writeFile(absFilePath, sourceFileText)` rewrites out-of-repo sources (strips unused exports, may append `export {};`) — triggered by default `knip --fix`.
   - `removeUnusedDependencies` (lines 106-134) with `packages/knip/src/util/package-json.ts:195-205` `save()` rewrites out-of-repo `package.json` (external dependencies removed — observed).

Core vulnerable code path:

```ts
// packages/knip/src/IssueFixer.ts:52-59
private async removeUnusedFiles(issues: Issues) {
  if (!this.options.isFixFiles) return;
  for (const issue of Object.values(issues.files).flatMap(Object.values)) {
    await rm(issue.filePath);              // absolute path, may be outside cwd
    issue.isFixed = true;
  }
}
// packages/knip/src/IssueFixer.ts:81-93 (default --fix)
const absFilePath = join(this.options.cwd, filePath);   // '../victim/x.ts' not contained
await writeFile(absFilePath, sourceFileText);
```

### PoC

Verified 2026-10-05 end-to-end in an isolated sandbox (exit code 0):

1. Victim project at `/tmp/knip-poc/victim-external` with `util.ts` and `package.json`.
2. Malicious repository at `/tmp/knip-poc/malicious-repo` with `knip.json`:

```json
{ "workspaces": ["../victim-external"] }
```

3. In `malicious-repo`: `npx knip --fix --allow-remove-files` (deletion) or plain `npx knip --fix` (export stripping + `package.json` rewrite).

Harness output:

```
[DETECTED] join(cwd, dir) = /tmp/knip-poc/victim-external
[DETECTED] dir escapes cwd? true
[DETECTED] relative(cwd, dir) = "../victim-external"
```

Observed: files under `/tmp/knip-poc/victim-external` were listed as unused and removed/rewritten by the fixer; external `package.json` dependencies were deleted by the default `--fix` run.

### Impact

A developer or CI runner executing `knip --fix` (or `--fix --allow-remove-files`) on any checkout containing a malicious workspace config suffers arbitrary deletion and content tampering of JS/TS files and `package.json` manifests **outside** the repository — including unrelated projects on the same machine. Deletion is unrecoverable (plain `rm`) and the tampering is stealthy (files are rewritten in place with no error). While this primitive does not directly execute code, silently destroying a sibling project's source/config — or corrupting a `package.json` to redirect future `npm install` resolution — is a realistic supply-chain attack vector. No npm install of the malicious repo is required; the config alone is sufficient.
