// Answers policy questions with the live commitments checker (ntaild decide-act), one process per question.
// Read-only use of an existing checkout; writes nothing but the answers file named on the command line.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
const [qFile, aFile, project] = process.argv.slice(2);
const qs = JSON.parse(readFileSync(qFile, "utf8"));
const out = existsSync(aFile) ? JSON.parse(readFileSync(aFile, "utf8")) : {};
for (const q of qs) {
  const key = JSON.stringify(q);
  if (key in out) continue;
  const r = spawnSync(process.env.HOME + "/.local/bin/uv", ["run", "--offline", "--frozen", "--quiet", "--project", project, "ntaild", "decide-act"], { input: key, encoding: "utf8", env: { PATH: process.env.PATH, HOME: process.env.HOME, GIT_CONFIG_GLOBAL: "/dev/null" } });
  if (r.status !== 0) throw new Error("decide-act failed: " + r.stderr.slice(-200));
  out[key] = JSON.parse(r.stdout);
}
writeFileSync(aFile, JSON.stringify(out, null, 1));
console.log("answered", Object.keys(out).length);
