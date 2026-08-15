#!/usr/bin/env bash
# Install sentry, and optionally run it 24/7.
#
#   ./install.sh              put `sentry` on PATH
#   ./install.sh --service    ...and run the daemon under systemd, always on
#   ./install.sh --windows    ...and print the one Windows command that keeps
#                             WSL itself alive across reboots
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
PORT="${SENTRY_PORT:-8787}"
mkdir -p "$BIN"

cat > "$BIN/sentry" <<EOF
#!/usr/bin/env bash
cd "$HERE" && exec python3 -m sentry "\$@"
EOF
chmod +x "$BIN/sentry"
echo "installed: $BIN/sentry"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "note: add $BIN to PATH — echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

want_service=false; want_windows=false
for arg in "$@"; do
  case "$arg" in
    --service) want_service=true ;;
    --windows) want_windows=true ;;
  esac
done

if $want_service; then
  UNIT="$HOME/.config/systemd/user"
  mkdir -p "$UNIT"
  cat > "$UNIT/sentry.service" <<EOF
[Unit]
Description=sentry — continuous process, network and control-surface monitoring
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m sentry serve --port $PORT
Restart=always
RestartSec=15
# The collectors shell out to powershell.exe, which is memory-hungry on the
# Windows side but cheap here; this cap only guards against a runaway in ours.
MemoryMax=512M

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now sentry.service
  echo "service:   systemctl --user status sentry"
  echo "logs:      journalctl --user -u sentry -f"
  echo "dashboard: http://127.0.0.1:$PORT"

  # Without linger, systemd tears down the user manager when the last shell
  # exits — which is exactly what happens when you close your terminal.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
    echo
    echo "IMPORTANT — the daemon will stop when you close your last shell."
    echo "To keep it running without a login session:"
    echo "    sudo loginctl enable-linger $USER"
  fi
fi

if $want_windows; then
  cat <<'EOF'

--------------------------------------------------------------------
Keeping it running across Windows reboots
--------------------------------------------------------------------
WSL only runs while Windows keeps it running. Enabling linger (above)
keeps sentry alive inside WSL; this task makes sure WSL itself starts
at logon, with no visible window.

Run this ONCE in Windows PowerShell (no elevation needed):

  $a = New-ScheduledTaskAction -Execute "wsl.exe" `
       -Argument "-d Ubuntu -u $env:USERNAME --exec /bin/true"
  $t = New-ScheduledTaskTrigger -AtLogOn
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
       -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -Hidden
  Register-ScheduledTask -TaskName "WSL sentry 24x7" -Action $a `
       -Trigger $t -Settings $s -Description "Starts WSL so sentry keeps running"

Starting WSL is enough: systemd then starts sentry.service on its own,
and linger keeps it up with no session attached.

To undo:  Unregister-ScheduledTask -TaskName "WSL sentry 24x7"
--------------------------------------------------------------------
EOF
fi
