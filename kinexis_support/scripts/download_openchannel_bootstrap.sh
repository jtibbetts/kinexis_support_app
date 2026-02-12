#!/usr/bin/env bash
# download_openchannel_bootstrap.sh
#
# Bootstrap local OpenChannel dev artifacts from a remote Dokku host.
# Self-contained: includes scp_fetch helper function.

set -euo pipefail

# ------------------------------------------------------------
# scp_fetch — safe SCP download helper
# ------------------------------------------------------------
scp_fetch() {
  local REMOTE="$1"
  local REMOTE_PATH="$2"
  local DEST="$3"

  # ---- validation ----
  case "$REMOTE" in
    *@*) ;;
    *)
      echo "Error: remote must be in the form user@host" >&2
      return 2
      ;;
  esac

  echo "Fetching:"
  echo "  Remote: $REMOTE:$REMOTE_PATH"
  echo "  Local:  $DEST"
  echo

  # scp handles globbing on the remote side
  scp -- "$REMOTE:$REMOTE_PATH" "$DEST"

  echo
  echo "✔ Fetch completed"
}

# ------------------------------------------------------------
# main
# ------------------------------------------------------------
main() {
  local REMOTE="root@dokku2.kinexis.com"

  mkdir -p ~/.local/share/openchannel
  mkdir -p ~/.config/openchannel

  # ---- SQLite database ----
  rm -f ~/.local/share/openchannel/db.sqlite
  scp_fetch \
    "$REMOTE" \
    /var/lib/dokku/storage/openchannel/dev-client/db.sqlite \
    ~/.local/share/openchannel/db.sqlite

  # ---- env files ----
  rm -f ~/.config/openchannel/env.dev
  scp_fetch \
    "$REMOTE" \
    /var/lib/dokku/storage/openchannel/dev-client/env* \
    ~/.config/openchannel/.

  echo
  echo "✅ OpenChannel bootstrap download complete"
}

main "$@"
