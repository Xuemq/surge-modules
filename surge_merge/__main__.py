import argparse
from pathlib import Path
import sys
from .core import Invalid
from .converter import convert_qx
from .single import optimize_single
from .pipeline import atomic_write, audit, check_updates, fetch, json_write, load_manifest, read_json


def main(argv=None):
    p = argparse.ArgumentParser(description="Conservative Surge merger; static validation only")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("fetch", "audit", "build", "check-updates"):
        s = sub.add_parser(name)
        s.add_argument("--manifest", default="sources.json")
        s.add_argument("--cache", default=".cache")
        s.add_argument("--report", default="work/report.json")
        s.add_argument("--overrides", default="overrides.json")
        if name == "build":
            s.add_argument("--output", default="work/candidate.sgmodule")
    s = sub.add_parser("convert-qx")
    s.add_argument("input")
    s.add_argument("--output", default="work/moyu.sgmodule")
    s.add_argument("--report", default="work/conversion.json")
    s.add_argument("--policy", help="reviewed JSON conversion policy")
    s = sub.add_parser("optimize-base")
    s.add_argument("input")
    s.add_argument("--policy", default="fmz-policy.json")
    s.add_argument("--output", default="work/fmz200.optimized.sgmodule")
    s.add_argument("--report", default="work/fmz200-report.json")
    args = p.parse_args(argv)
    try:
        if args.command == "optimize-base":
            policy = read_json(args.policy)
            candidate, report = optimize_single(Path(args.input).read_bytes(), policy["source_id"], policy)
            json_write(args.report, report)
            atomic_write(Path(args.output), candidate.encode())
            print(report["status"])
            return 0
        if args.command == "convert-qx":
            candidate, report = convert_qx(Path(args.input).read_bytes(), read_json(args.policy) if args.policy else None)
            json_write(args.report, report)
            if candidate is not None:
                atomic_write(Path(args.output), candidate.encode())
            print(report["status"])
            return 0 if candidate is not None else 2
        manifest = load_manifest(args.manifest)
        if args.command == "fetch":
            report = fetch(manifest, args.cache)
        elif args.command == "check-updates":
            report = check_updates(manifest)
        else:
            candidate, report = audit(manifest, args.cache, read_json(args.overrides))
            if args.command == "build" and candidate is not None:
                # Candidate-only output. No publish/promote command exists.
                atomic_write(Path(args.output), candidate.encode())
        json_write(args.report, report)
        print(report["status"])
        return 0 if report["status"] in {"fetched_locked_sources", "unchanged", "candidate_static_pass"} else 2
    except (Invalid, OSError, ValueError, KeyError) as exc:
        # Local report contains only validator messages; fetched content is never echoed.
        json_write(args.report, {"schema_version": 1, "status": "blocked", "error": str(exc)})
        print("blocked: inspect the local report", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
