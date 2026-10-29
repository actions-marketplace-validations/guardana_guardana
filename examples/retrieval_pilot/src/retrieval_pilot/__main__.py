"""Run the reference application until interrupted."""

import argparse
import contextlib
import os
import signal
import sys
from pathlib import Path

from retrieval_pilot.app import ReferenceApplication, Switches, make_server


def main(argv: list[str] | None = None) -> None:
    """Parse the command line and serve the application it describes."""
    parser = argparse.ArgumentParser(prog="retrieval-pilot", description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--documents", type=Path, required=True, help="documents.jsonl")
    parser.add_argument("--trace", type=Path, required=True, help="a fresh path for the doubles")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--break-tenant-filter", action="store_true")
    parser.add_argument("--obey-documents", action="store_true")
    args = parser.parse_args(argv)
    application = ReferenceApplication(
        args.fixtures,
        args.documents,
        trace=args.trace,
        switches=Switches(
            break_tenant_filter=args.break_tenant_filter, obey_documents=args.obey_documents
        ),
        environ=os.environ,
    )
    server = make_server(application, args.host, args.port)
    # A terminated process skips `atexit`, so SIGTERM leaves through `finally` and the
    # trace gets its footer.
    signal.signal(signal.SIGTERM, _exit)
    sys.stderr.write(f"serving on http://{args.host}:{server.server_address[1]}\n")
    try:
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()
    finally:
        server.server_close()
        application.close()


def _exit(signum: int, frame: object) -> None:
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    main()
