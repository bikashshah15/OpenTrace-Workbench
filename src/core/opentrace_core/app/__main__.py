"""Run the loopback Workbench: ``python -m opentrace_core.app [--port N] [--session-root DIR]``."""
import argparse
import os
import sys
import tempfile


def main(argv=None):
    from . import replay
    from .server import make_server
    parser = argparse.ArgumentParser(prog="opentrace_core.app")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--session-root", default=None)
    parser.add_argument("--host", default="127.0.0.1", help="127.0.0.1 only, except 0.0.0.0 inside the Compose container (OPENTRACE_CONTAINER_BIND=1)")
    args = parser.parse_args(argv)
    root = args.session_root or os.path.join(tempfile.gettempdir(), "opentrace-sessions-{}".format(os.getuid()))
    server = make_server(root, port=args.port, host=args.host, replay=replay.from_env(default=replay.BUNDLED_FIXTURE))
    print("OpenTrace Workbench listening on {}:{} (open http://127.0.0.1:{}/)".format(args.host, server.server_address[1], server.server_address[1]), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.app.close()
        server.server_close()


if __name__ == "__main__":
    main(sys.argv[1:])
