#!/bin/sh
# netcond.sh - inject "spotty wifi" (packet loss + latency) on the seed's provider traffic only,
# for the startup/reconnect resilience test. macOS dummynet (dnctl) + pf (pfctl). Run with sudo.
#
#   sudo sh tools/netcond.sh on  [loss] [delay_ms]   # default: 0.10 loss, 150 ms, 2 Mbit
#   sudo sh tools/netcond.sh off                      # restore
#   sudo sh tools/netcond.sh status
#
# Scope: ONLY TCP to/from the Cloudflare ranges api.openai.com uses, so the rest of your
# traffic is untouched. SAFETY: 'on' refuses if a pf firewall is already enabled (so it can
# never clobber your ruleset); 'off' flushes the pipe, reloads /etc/pf.conf, and disables pf
# (restoring the macOS default, where pf is off and the app firewall is separate).
set -e
PIPE=7
DSTS="{ 172.66.0.0/16, 162.159.0.0/16, 104.16.0.0/13 }"   # api.openai.com / Cloudflare (DNS RR); pf list
RULES=/tmp/seed-netcond.rules

case "${1:-}" in
  on)
    LOSS="${2:-0.10}"; DELAY="${3:-150}"
    if pfctl -s info 2>/dev/null | grep -qi 'Status: Enabled'; then
      echo "REFUSING: pf is already ENABLED (you have a pf firewall ruleset)."
      echo "I won't clobber it. Disable it first, or shape manually. No changes made."
      exit 2
    fi
    dnctl pipe $PIPE config bw 2Mbit/s delay "$DELAY" plr "$LOSS"
    printf 'dummynet out quick proto tcp from any to %s pipe %s\n' "$DSTS" "$PIPE"  > "$RULES"
    printf 'dummynet in  quick proto tcp from %s to any pipe %s\n' "$DSTS" "$PIPE" >> "$RULES"
    pfctl -f "$RULES" 2>/dev/null
    pfctl -e 2>/dev/null || true
    echo "netcond ON: loss=$LOSS delay=${DELAY}ms bw=2Mbit on provider ranges (pipe $PIPE)."
    ;;
  off)
    dnctl -q flush 2>/dev/null || true
    pfctl -f /etc/pf.conf 2>/dev/null || true
    pfctl -d 2>/dev/null || true
    echo "netcond OFF: dummynet flushed, /etc/pf.conf reloaded, pf disabled (macOS default)."
    ;;
  status)
    echo "--- dnctl pipe $PIPE ---"; dnctl pipe show 2>/dev/null | grep -A2 "$PIPE:" || echo "(no pipe)"
    echo "--- pf ---"; pfctl -s info 2>/dev/null | grep -i status || echo "(pf state needs sudo)"
    ;;
  *) echo "usage: sudo sh tools/netcond.sh on [loss] [delay_ms] | off | status"; exit 1;;
esac
