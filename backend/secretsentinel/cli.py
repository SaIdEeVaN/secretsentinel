"""SecretSentinel command-line interface.

Exit codes (stable, used by CI):
    0  scan completed and no unsuppressed blocking findings
    1  scan completed and at least one blocking finding
    2  usage or configuration error (bad arguments, invalid policy/ruleset)
    3  scan could not complete (scanner missing/crashed, timeout, cancelled,
       sanitization failure) - FAIL CLOSED, security status unknown

The CLI imports only the scanner core at startup; database and web modules are
imported lazily so ``secretsentinel check`` needs nothing beyond PyYAML.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .core.config import FAIL_ON_LEVELS, Settings, parse_env_file, set_settings
from .core.errors import ErrorCode, SecretSentinelError
from .core.log import configure_logging

EXIT_PASS = 0
EXIT_BLOCKING = 1
EXIT_USAGE = 2
EXIT_SCAN_ERROR = 3

_CONFIG_ERRORS = {ErrorCode.INVALID_POLICY.value, ErrorCode.INVALID_CONFIG.value, ErrorCode.INVALID_GIT_REF.value}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse plumbing
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _err(message: str) -> None:
    print(f"secretsentinel: {message}", file=sys.stderr)


def _write_output(text: str, output: str | None) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _settings_for(args) -> Settings:
    settings = Settings.from_env()
    overrides = {}
    if getattr(args, "gitleaks", None):
        overrides["gitleaks_path"] = args.gitleaks
    if getattr(args, "timeout", None):
        overrides["scanner_timeout_seconds"] = args.timeout
    if getattr(args, "max_file_mb", None):
        overrides["max_scan_file_mb"] = args.max_file_mb
    settings = settings.with_overrides(**overrides)
    set_settings(settings)
    return settings


def _run(args, mode: str, store: bool) -> int:
    from .core.security import canonicalize_existing_dir
    from .services.exporters import github_annotations, github_step_summary, to_csv, to_json, to_sarif, to_text
    from .services.policy import Policy, discover_policy
    from .services.scanner import ScanRequest, run_scan

    settings = _settings_for(args)
    try:
        target = canonicalize_existing_dir(args.path)
        if args.no_policy:
            policy = Policy.empty()
        else:
            policy = discover_policy(target, Path(args.policy).resolve() if args.policy else None)
    except SecretSentinelError as exc:
        _err(f"[{exc.code.value}] {exc.message}")
        return EXIT_USAGE

    fail_on = args.fail_on or policy.fail_on or settings.default_fail_on
    extra = []
    repo = None
    session_ctx = None
    if store:
        try:
            from .database import init_engine, session_scope
            from .services.store import dashboard_suppressions, get_or_create_repository

            init_engine(settings.db_url)
            session_ctx = session_scope
            with session_scope() as session:
                repo = get_or_create_repository(session, target)
                extra = dashboard_suppressions(session, repo.id)
                repo_id = repo.id
        except Exception:  # noqa: BLE001 - storage is optional for the CLI
            _err("warning: could not open the local database; results will not be stored")
            store = False

    req = ScanRequest(
        target=target,
        mode=mode,
        since_ref=getattr(args, "since", None),
        fail_on=fail_on,
        policy=policy,
        extra_suppressions=extra,
        timeout_seconds=settings.scanner_timeout_seconds,
        max_file_mb=settings.max_scan_file_mb,
        enforce_size_limit=not args.no_size_limit,
    )
    outcome = run_scan(req, settings)

    scan_id = None
    if store and session_ctx is not None:
        try:
            from .models import Repository
            from .services.store import record_outcome

            with session_ctx() as session:
                repo_row = session.get(Repository, repo_id)
                scan_id = record_outcome(session, repo_row, outcome, "cli", req.since_ref).id
        except Exception:  # noqa: BLE001
            _err("warning: failed to store scan results")

    name = target.name or "target"
    fmt = args.format
    if fmt == "json":
        payload = json.loads(to_json(outcome, name))
        if scan_id:
            payload["scan"]["id"] = scan_id
        _write_output(json.dumps(payload, indent=2) + "\n", args.output)
    elif fmt == "sarif":
        _write_output(to_sarif(outcome, name), args.output)
    elif fmt == "csv":
        _write_output(to_csv(outcome), args.output)
    else:
        _write_output(to_text(outcome, name, verbose=args.verbose), args.output)
    if args.output and fmt != "text":
        # Always give humans/CI a one-line, safe summary on stderr.
        from .services.exporters import result_line

        print(result_line(outcome), file=sys.stderr)
    if scan_id and fmt == "text" and not args.output:
        print(f"Stored as scan {scan_id} in the local database.")

    if args.github_annotations:
        for line in github_annotations(outcome):
            print(line)
    if args.github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(github_step_summary(outcome, name))

    if outcome.status != "completed":
        return EXIT_USAGE if outcome.error_code in _CONFIG_ERRORS else EXIT_SCAN_ERROR
    return EXIT_BLOCKING if outcome.policy_result == "fail" else EXIT_PASS


def cmd_scan(args) -> int:
    return _run(args, args.mode, store=not args.no_db)


def cmd_check(args) -> int:
    return _run(args, args.mode, store=args.store)


def cmd_baseline(args) -> int:
    from .core.security import canonicalize_existing_dir
    from .services.policy import Policy, build_baseline, discover_policy
    from .services.scanner import ScanRequest, run_scan

    settings = _settings_for(args)
    try:
        expires = date.fromisoformat(args.expires)
    except ValueError:
        _err("--expires must be an ISO date (YYYY-MM-DD)")
        return EXIT_USAGE
    try:
        target = canonicalize_existing_dir(args.path)
        policy = discover_policy(target, Path(args.policy).resolve() if args.policy else None)
    except SecretSentinelError as exc:
        _err(f"[{exc.code.value}] {exc.message}")
        return EXIT_USAGE
    # Baselines are built WITHOUT existing suppressions so every current finding is listed.
    scan_policy = Policy(exclude_paths=policy.exclude_paths)
    outcome = run_scan(
        ScanRequest(target=target, mode=args.mode, policy=scan_policy, timeout_seconds=settings.scanner_timeout_seconds,
                    max_file_mb=settings.max_scan_file_mb),
        settings,
    )
    if outcome.status != "completed":
        _err(f"scan failed: [{outcome.error_code}]; no baseline written")
        return EXIT_SCAN_ERROR
    try:
        baseline = build_baseline(outcome.findings, args.reason, args.reviewer, expires, outcome.ruleset_digest)
    except SecretSentinelError as exc:
        _err(exc.message)
        return EXIT_USAGE
    _write_output(json.dumps(baseline, indent=2) + "\n", args.output)
    print(
        f"Baseline with {len(baseline['entries'])} entr{'y' if len(baseline['entries']) == 1 else 'ies'} written. "
        "Reference it from .secretsentinel.yml (baseline: <file>) and review it like code.",
        file=sys.stderr,
    )
    return EXIT_PASS


def cmd_rules(args) -> int:
    from .services.remediation import get_remediation
    from .services.rules import load_ruleset

    try:
        ruleset = load_ruleset()
    except SecretSentinelError as exc:
        _err(exc.message)
        return EXIT_USAGE
    if args.rules_cmd == "digest":
        print(f"{ruleset.version} {ruleset.digest}")
        return EXIT_PASS
    if args.rules_cmd == "config":
        sys.stdout.write(ruleset.effective_config())
        return EXIT_PASS
    rules = ruleset.list_rules()
    if args.format == "json":
        out = [dict(r.as_dict(), remediation=get_remediation(r.remediation_key).as_dict()) for r in rules]
        print(json.dumps({"ruleset_version": ruleset.version, "ruleset_digest": ruleset.digest, "rules": out}, indent=2))
        return EXIT_PASS
    print(f"Ruleset {ruleset.version} ({ruleset.digest})")
    print("Custom Web3 rules plus mapped Gitleaks defaults; unmapped Gitleaks rules default to 'high'.\n")
    for r in rules:
        print(f"  {r.severity:<9} {r.confidence:<7} {r.rule_id:<36} {r.title}")
    return EXIT_PASS


def cmd_demo(args) -> int:
    from .services.demo import create_demo_repo

    settings = _settings_for(args)
    try:
        path = create_demo_repo(Path(args.path), settings.git_path)
    except SecretSentinelError as exc:
        _err(f"[{exc.code.value}] {exc.message}")
        return EXIT_USAGE
    print(f"Demo repository created at {path}")
    print("It contains SYNTHETIC leaks: one only in Git history, one in the working tree, one untracked.")
    print(f"Try:  secretsentinel scan both {path}")
    return EXIT_PASS


def cmd_doctor(args) -> int:
    from .services.rules import load_ruleset
    from .services.scanner import MIN_GITLEAKS, gitleaks_version, resolve_executable, version_tuple

    settings = _settings_for(args)
    ok = True
    print(f"SecretSentinel {__version__} on Python {sys.version.split()[0]} ({sys.platform})")
    try:
        gl = resolve_executable(settings.gitleaks_path, ErrorCode.SCANNER_NOT_FOUND)
        v = gitleaks_version(gl)
        status = "ok" if version_tuple(v) >= MIN_GITLEAKS else "too old (need >= 8.25.0)"
        ok &= status == "ok"
        print(f"  gitleaks  {v:<10} {status}  ({gl})")
    except SecretSentinelError as exc:
        ok = False
        print(f"  gitleaks  MISSING    {exc.message}")
    try:
        git = resolve_executable(settings.git_path, ErrorCode.GIT_NOT_FOUND)
        print(f"  git       found      ({git})")
    except SecretSentinelError as exc:
        print(f"  git       MISSING    {exc.message} (needed for git/both modes)")
    try:
        rs = load_ruleset()
        print(f"  ruleset   {rs.version:<10} ok  ({rs.digest[:23]}...)")
    except SecretSentinelError as exc:
        ok = False
        print(f"  ruleset   INVALID    {exc.message}")
    roots = ", ".join(str(r) for r in settings.scan_root_allowlist) or "(none in the environment)"
    print(f"  dashboard scan roots: {roots}")
    print("  note: doctor reads environment variables only; `serve --env-file .env` loads .env")
    print(f"  database: {settings.db_url}")
    return EXIT_PASS if ok else EXIT_SCAN_ERROR


def cmd_serve(args) -> int:
    if args.env_file:
        for key, value in parse_env_file(Path(args.env_file)).items():
            os.environ.setdefault(key, value)
    if args.host:
        os.environ["HOST"] = args.host
    if args.port:
        os.environ["PORT"] = str(args.port)
    settings = Settings.from_env()
    set_settings(settings)
    try:
        import uvicorn

        from .main import create_app, validate_startup
    except ImportError:
        _err("the web dashboard needs the server dependencies: pip install -e backend")
        return EXIT_USAGE
    try:
        validate_startup(settings)
    except SecretSentinelError as exc:
        _err(exc.message)
        return EXIT_USAGE
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level=settings.log_level.lower(),
                server_header=False, proxy_headers=False)
    return EXIT_PASS


def cmd_db(args) -> int:
    settings = _settings_for(args)
    from sqlalchemy.engine import make_url

    url = make_url(settings.db_url)
    if args.db_cmd == "path":
        print(url.database or settings.db_url)
        return EXIT_PASS
    if args.db_cmd == "reset":
        if not args.yes:
            _err("refusing to delete the database without --yes")
            return EXIT_USAGE
        if url.get_backend_name() != "sqlite" or not url.database:
            _err("reset is only supported for SQLite databases")
            return EXIT_USAGE
        for suffix in ("", "-wal", "-shm"):
            p = Path(url.database + suffix)
            if p.exists():
                p.unlink()
        print("Local database deleted.")
        return EXIT_PASS
    if args.db_cmd == "prune":
        from .database import init_engine, prune_old_scans, session_scope

        init_engine(settings.db_url)
        with session_scope() as session:
            n = prune_old_scans(session, args.days)
        print(f"Pruned {n} scan(s) older than {args.days} day(s).")
        return EXIT_PASS
    return EXIT_USAGE


def cmd_attest(args) -> int:
    from .services import attestation_cli

    settings = _settings_for(args)
    return attestation_cli.run(args, settings)


def _add_scan_options(p: argparse.ArgumentParser, include_mode: bool) -> None:
    if include_mode:
        p.add_argument("--mode", choices=("dir", "git", "both"), default="both", help="scan scope (default: both)")
    p.add_argument("path", help="local directory or repository root to scan")
    p.add_argument("--since", metavar="REF", help="git mode: only scan commits after REF (e.g. the PR base SHA)")
    p.add_argument("--fail-on", choices=FAIL_ON_LEVELS, help="minimum severity that blocks (default: policy file, FAIL_ON, or high)")
    p.add_argument("--format", choices=("text", "json", "sarif", "csv"), default="text")
    p.add_argument("--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--policy", metavar="FILE", help="policy file (default: <path>/.secretsentinel.yml if present)")
    p.add_argument("--no-policy", action="store_true", help="ignore any policy file")
    p.add_argument("--timeout", type=int, metavar="SECONDS", help="scan timeout (default: SCANNER_TIMEOUT_SECONDS or 120)")
    p.add_argument("--max-file-mb", type=int, metavar="MB", help="skip files larger than this")
    p.add_argument("--gitleaks", metavar="PATH", help="Gitleaks executable (default: GITLEAKS_PATH or PATH lookup)")
    p.add_argument("--no-size-limit", action="store_true", help="skip the MAX_REPO_MB pre-check")
    p.add_argument("--github-annotations", action="store_true", help="emit GitHub Actions ::error/::warning annotations")
    p.add_argument("--github-summary", action="store_true", help="append a Markdown summary to $GITHUB_STEP_SUMMARY")
    p.add_argument("-v", "--verbose", action="store_true", help="include remediation steps in text output")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="secretsentinel", description="Web3-aware secret leakage scanner built on Gitleaks.")
    parser.add_argument("--version", action="version", version=f"secretsentinel {__version__}")
    parser.add_argument("--log-level", default="WARNING", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    scan = sub.add_parser("scan", help="scan a directory, its Git history, or both (stores results locally)")
    scan_sub = scan.add_subparsers(dest="mode", required=True, parser_class=_Parser)
    for mode, help_text in (
        ("dir", "scan current file contents (catches uncommitted changes; not history)"),
        ("git", "scan Git history (catches committed and later-deleted leaks)"),
        ("both", "scan working tree and history, deduplicated"),
    ):
        p = scan_sub.add_parser(mode, help=help_text)
        _add_scan_options(p, include_mode=False)
        p.add_argument("--no-db", action="store_true", help="do not store results in the local database")
        p.set_defaults(func=cmd_scan)

    check = sub.add_parser("check", help="CI gate: scan and exit nonzero on blocking findings or errors")
    _add_scan_options(check, include_mode=True)
    check.add_argument("--store", action="store_true", help="also store results in the local database")
    check.set_defaults(func=cmd_check)

    baseline = sub.add_parser("baseline", help="manage reviewed baselines of pre-existing findings")
    bsub = baseline.add_subparsers(dest="baseline_cmd", required=True, parser_class=_Parser)
    bcreate = bsub.add_parser("create", help="scan and write a baseline file (metadata only, no secrets)")
    bcreate.add_argument("path")
    bcreate.add_argument("--mode", choices=("dir", "git", "both"), default="both")
    bcreate.add_argument("--reviewer", required=True)
    bcreate.add_argument("--reason", required=True)
    bcreate.add_argument("--expires", required=True, help="YYYY-MM-DD, at most 366 days ahead")
    bcreate.add_argument("--output", default=".secretsentinel-baseline.json")
    bcreate.add_argument("--policy", metavar="FILE")
    bcreate.add_argument("--gitleaks", metavar="PATH")
    bcreate.set_defaults(func=cmd_baseline)

    rules = sub.add_parser("rules", help="inspect the ruleset")
    rsub = rules.add_subparsers(dest="rules_cmd", required=True, parser_class=_Parser)
    rlist = rsub.add_parser("list", help="list mapped rules with severity and confidence")
    rlist.add_argument("--format", choices=("text", "json"), default="text")
    rsub.add_parser("digest", help="print ruleset version and digest")
    rsub.add_parser("config", help="print the effective Gitleaks config")
    rules.set_defaults(func=cmd_rules)

    demo = sub.add_parser("demo", help="create a disposable demo repository with synthetic leaks")
    dsub = demo.add_subparsers(dest="demo_cmd", required=True, parser_class=_Parser)
    dcreate = dsub.add_parser("create")
    dcreate.add_argument("path")
    demo.set_defaults(func=cmd_demo)

    doctor = sub.add_parser("doctor", help="check that Gitleaks, Git and the ruleset are usable")
    doctor.add_argument("--gitleaks", metavar="PATH")
    doctor.set_defaults(func=cmd_doctor)

    serve = sub.add_parser("serve", help="run the local API and dashboard (loopback only by default)")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--env-file", help="explicit env file to load (never auto-loaded)")
    serve.set_defaults(func=cmd_serve)

    db = sub.add_parser("db", help="local database maintenance")
    dbsub = db.add_subparsers(dest="db_cmd", required=True, parser_class=_Parser)
    dbsub.add_parser("path")
    dreset = dbsub.add_parser("reset")
    dreset.add_argument("--yes", action="store_true")
    dprune = dbsub.add_parser("prune")
    dprune.add_argument("--days", type=int, required=True)
    db.set_defaults(func=cmd_db)

    attest = sub.add_parser("attest", help="(optional P2) signed scan attestations")
    asub = attest.add_subparsers(dest="attest_cmd", required=True, parser_class=_Parser)
    acreate = asub.add_parser("create", help="sign an attestation for a stored scan")
    acreate.add_argument("scan_id")
    acreate.add_argument("--output", help="write attestation bundle JSON here")
    apublish = asub.add_parser("publish", help="register the attestation digest on Sepolia")
    apublish.add_argument("scan_id")
    averify = asub.add_parser("verify", help="verify an attestation bundle file")
    averify.add_argument("bundle")
    averify.add_argument("--onchain", action="store_true", help="also check the Sepolia registry")
    attest.set_defaults(func=cmd_attest)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(str(args.log_level).upper())
    try:
        return args.func(args)
    except SecretSentinelError as exc:
        _err(f"[{exc.code.value}] {exc.message}")
        return EXIT_USAGE if exc.code.value in _CONFIG_ERRORS else EXIT_SCAN_ERROR
    except KeyboardInterrupt:
        _err("interrupted")
        return EXIT_SCAN_ERROR
    except ValueError:
        _err("invalid configuration value (check environment variables)")
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
