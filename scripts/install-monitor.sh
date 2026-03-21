#!/bin/bash
# ClawGuard Background Monitor — macOS LaunchAgent Setup
# Run once to install ClawGuard as a background service
# No sudo required — runs as current user

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_SCRIPT="$SCRIPT_DIR/background-monitor.js"
NODE_PATH="$(which node)"
PLIST_DIR="$HOME/Library/LaunchAgents"

if [ -z "$NODE_PATH" ]; then
    echo "❌ Node.js not found. Install via: brew install node"
    exit 1
fi

mkdir -p "$PLIST_DIR"

# Soul check every 30 minutes
cat > "$PLIST_DIR/ai.clawguard.soul-check.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.clawguard.soul-check</string>
    <key>ProgramArguments</key>
    <array>
        <string>$NODE_PATH</string>
        <string>$MONITOR_SCRIPT</string>
        <string>--soul</string>
    </array>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.clawguard/monitor.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.clawguard/monitor-error.log</string>
</dict>
</plist>
EOF

# Skills scan every hour
cat > "$PLIST_DIR/ai.clawguard.skill-scan.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.clawguard.skill-scan</string>
    <key>ProgramArguments</key>
    <array>
        <string>$NODE_PATH</string>
        <string>$MONITOR_SCRIPT</string>
        <string>--scan</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.clawguard/monitor.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.clawguard/monitor-error.log</string>
</dict>
</plist>
EOF

launchctl load "$PLIST_DIR/ai.clawguard.soul-check.plist"
launchctl load "$PLIST_DIR/ai.clawguard.skill-scan.plist"

echo "✅ ClawGuard is now running in the background."
echo "   SOUL.md check: every 30 minutes"
echo "   Skills scan: every hour"
echo "   Zero API credits consumed."
echo ""
echo "Alerts delivered via Telegram."
