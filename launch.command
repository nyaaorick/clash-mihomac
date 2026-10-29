#!/bin/bash
# Double-click to start everything: builds Clash Mihomac if needed, installs
# Clash Verge Rev if it is missing, starts Clash Verge, starts the companion
# daemon, and opens the GUI. The daemon keeps running after this window
# closes; stop it with `bin/mihomac stop`.
cd "$(dirname "$0")" || exit 1

if ! command -v go >/dev/null 2>&1 && [ ! -x bin/mihomac ]; then
  echo "Go is not installed and bin/mihomac does not exist."
  read -r -p "Press Enter to close..."; exit 1
fi

if [ ! -x bin/mihomac ] || [ -n "$(find cmd internal go.mod -newer bin/mihomac -name '*.go' -o -newer bin/mihomac -name go.mod 2>/dev/null | head -1)" ]; then
  echo "Building..."
  make build || { read -r -p "Build failed. Press Enter to close..."; exit 1; }
fi

bin/mihomac up "$@" || { read -r -p "Start failed. Press Enter to close..."; exit 1; }
echo
echo "Done. Clash Mihomac keeps running in the background; stop it with: bin/mihomac stop"
