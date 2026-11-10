// An isolated real backend serving the production dashboard. Never reuse user data.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const work = mkdtempSync(join(tmpdir(), "secretsentinel-browser-"));
const allowed = join(work, "repos");
mkdirSync(allowed);
const venvPython = join(root, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
const python = process.env.SECRETSENTINEL_PYTHON || (existsSync(venvPython) ? venvPython : "python");
const child = spawn(python, ["-m", "secretsentinel", "serve", "--host", "127.0.0.1", "--port", "8765"], {
  cwd: root,
  stdio: "inherit",
  shell: false,
  env: {
    ...process.env,
    PYTHONPATH: join(root, "backend"),
    DB_URL: `sqlite:///${join(work, "history.db").replaceAll("\\", "/")}`,
    SCAN_ROOT_ALLOWLIST: allowed,
    SECRETSENTINEL_RULES_DIR: join(root, "rules"),
    SECRETSENTINEL_FRONTEND_DIST: join(root, "frontend/dist"),
    APP_ENV: "development",
    API_TOKEN: "", INGEST_TOKEN: "", ALLOW_REMOTE: "false", ENABLE_BLOCKCHAIN: "false",
  },
});
child.on("error", (error) => {
  console.error(`Could not start the browser-test backend: ${error.message}`);
  rmSync(work, { recursive: true, force: true });
  process.exitCode = 1;
});
child.on("exit", (code) => {
  rmSync(work, { recursive: true, force: true });
  process.exitCode = code ?? 0;
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
