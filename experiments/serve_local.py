"""Serve the existing Linen export and authenticated API on one loopback origin."""
import argparse
from pathlib import Path

import uvicorn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=3417)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('port must be between 1 and 65535')
    root = Path(__file__).resolve().parents[1]
    if not (root / 'frontend/out/index.html').exists():
        parser.error('Build frontend first: npm --prefix frontend run build')
    from aegisav.main import app, key_path
    print('Local access key file:', key_path, flush=True)
    print('Workbench: http://127.0.0.1:'+str(args.port)+'/linen/', flush=True)
    uvicorn.run(app, host='127.0.0.1', port=args.port, proxy_headers=False, access_log=False)


if __name__ == '__main__':
    main()
