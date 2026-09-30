#!/usr/bin/env bash
# Serve the live demo in a browser at http://localhost:7681 using ttyd.
# Bound to 127.0.0.1 only, so other machines cannot connect.
#   sudo apt install ttyd      (once)
#   bash scripts/web_demo.sh   (or: npm run dev from Windows)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=7681
URL="http://localhost:$PORT"

command -v ttyd >/dev/null || { echo "ttyd not installed: sudo apt install ttyd"; exit 1; }
make -s all

# Stop an earlier copy of this demo server so the port is free.
if pkill -f "ttyd -p $PORT" 2>/dev/null; then
  echo "Stopped the previous demo server on port $PORT."
  sleep 1
fi

echo
echo "  Secure Channel Lab is running at:  $URL"
echo "  Keep this window open. Press Ctrl+C to stop."
echo

# Open the Windows browser once the server is up (WSL interop; ignored elsewhere).
( sleep 2; cmd.exe /c start "" "$URL" >/dev/null 2>&1 || true ) &

exec ttyd -p "$PORT" -i 127.0.0.1 -W -t titleFixed="Secure Channel Lab" -t fontSize=15 \
     bash -c './secure_demo; echo; echo "Demo closed - shell is in the project folder (try: make test)"; exec bash'
