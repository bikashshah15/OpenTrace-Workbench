import argparse
import sys

from . import __version__
from .contract import validate_file
from .pipeline import canonical, run


def _validate(args):
    status = 0
    for path in args.files:
        kind, errors = validate_file(path)
        if errors:
            status = 1
            print(f"{path}: INVALID {kind}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"{path}: ok ({kind})")
    return status


def _assess(args):
    try:
        text = canonical(run(args.bundle))
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="bombridge",
        description="BOMBridge (Declare-Observe-Check). Implemented: validate, assess "
                    "(one rule: declared model digest vs observed artifact digest). "
                    "No collection or HTML rendering yet.")
    p.add_argument("--version", action="version", version=f"bombridge {__version__}")
    sub = p.add_subparsers(dest="command")
    v = sub.add_parser("validate", help="validate a bundle or repository manifest JSON file")
    v.add_argument("files", nargs="+")
    v.set_defaults(func=_validate)
    a = sub.add_parser("assess", help="validate a bundle, run rules, build the graph, export deterministic JSON")
    a.add_argument("bundle")
    a.add_argument("-o", "--output", help="write result JSON here (default: stdout)")
    a.set_defaults(func=_assess)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
