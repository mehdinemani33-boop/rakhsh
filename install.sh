#!/usr/bin/env bash
# =============================================================================
# Rakhsh installer — run on the Iran edge AND on each foreign server.
#   bash <(curl -fsSL https://raw.githubusercontent.com/mehdinemani33-boop/rakhsh/main/install.sh)
# Menu:  1) Iran edge   2) Foreign server   3) Node core (headless)
# Downloads the prebuilt binary from the latest GitHub release; if none is
# available it builds from source (installs Go automatically).
# =============================================================================
set -euo pipefail
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
say(){ echo -e "${G}==>${N} $*"; }
warn(){ echo -e "${Y}!! ${N} $*"; }
die(){ echo -e "${R}xx ${N} $*"; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"

OWNER="mehdinemani33-boop"
REPO="rakhsh"
DIR=/opt/rakhsh
BIN=$DIR/rakhsh
FRP_VER=0.61.1
ARCH=$(uname -m); case "$ARCH" in x86_64) GOARCH=amd64;; aarch64|arm64) GOARCH=arm64;; *) die "unsupported arch $ARCH";; esac

say "Installing dependencies…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl tar git iproute2 iptables ca-certificates wireguard-tools autossh unzip >/dev/null 2>&1 || \
  apt-get install -y curl tar git iproute2 iptables ca-certificates
mkdir -p "$DIR"/{conf,log,frp,xray,backhaul}

# ---- rakhsh binary: prebuilt from the latest release, else build from source ----
install_binary(){
  local url="https://github.com/$OWNER/$REPO/releases/latest/download/rakhsh_linux_${GOARCH}"
  say "Downloading rakhsh ($GOARCH)…"
  if curl -fsSL "$url" -o "$BIN.tmp" 2>/dev/null && [ -s "$BIN.tmp" ]; then
    mv "$BIN.tmp" "$BIN"; chmod +x "$BIN"
    if "$BIN" version >/dev/null 2>&1; then
      # fetch the latest web UI to disk so the panel is current without a rebuild
      local raw="https://raw.githubusercontent.com/$OWNER/$REPO/main/internal/panel/web"
      mkdir -p "$DIR/web/assets"
      curl -fsSL "$raw/index.html" -o "$DIR/web/index.html" 2>/dev/null || true
      curl -fsSL "$raw/assets/app.css" -o "$DIR/web/assets/app.css" 2>/dev/null || true
      say "Installed prebuilt binary."; return
    fi
  fi
  rm -f "$BIN.tmp"
  warn "No prebuilt binary — building from source."
  command -v go >/dev/null 2>&1 || apt-get install -y -qq golang-go >/dev/null 2>&1 || apt-get install -y golang-go
  rm -rf /tmp/rakhsh-src && git clone --depth 1 "https://github.com/$OWNER/$REPO" /tmp/rakhsh-src
  ( cd /tmp/rakhsh-src && GOFLAGS=-mod=mod CGO_ENABLED=0 GOARCH=$GOARCH go build -o "$BIN" ./cmd/rakhsh )
  # keep the web assets from source so the panel serves the latest UI
  cp -r /tmp/rakhsh-src/internal/panel/web "$DIR/" 2>/dev/null || true
  chmod +x "$BIN"
}

# ---- FRP binaries (frps + frpc) for the default engine ----
install_frp(){
  [ -x "$DIR/frp/frps" ] && [ -x "$DIR/frp/frpc" ] && return 0
  say "Fetching FRP $FRP_VER…"
  local t; t=$(mktemp -d)
  curl -fsSL "https://github.com/fatedier/frp/releases/download/v${FRP_VER}/frp_${FRP_VER}_linux_${GOARCH}.tar.gz" -o "$t/frp.tgz" \
    || { warn "FRP download failed; GRE+FRP inactive until $DIR/frp is filled"; return 0; }
  tar xzf "$t/frp.tgz" -C "$t"
  cp "$t"/frp_*/frps "$t"/frp_*/frpc "$DIR/frp/"; chmod +x "$DIR/frp/frps" "$DIR/frp/frpc"; rm -rf "$t"
}

# ---- Pro-engine binaries: Xray and Backhaul ----
install_engines(){
  if [ ! -x "$DIR/xray/xray" ]; then
    say "Fetching Xray…"
    local z="Xray-linux-64.zip"; [ "$GOARCH" = arm64 ] && z="Xray-linux-arm64-v8a.zip"
    local t; t=$(mktemp -d)
    if curl -fsSL "https://github.com/XTLS/Xray-core/releases/latest/download/$z" -o "$t/x.zip" 2>/dev/null; then
      unzip -o "$t/x.zip" xray -d "$DIR/xray" >/dev/null 2>&1 && chmod +x "$DIR/xray/xray"
    else warn "Xray download failed; the Xray engine stays inactive."; fi
    rm -rf "$t"
  fi
  if [ ! -x "$DIR/backhaul/backhaul" ]; then
    say "Fetching Backhaul…"
    local t; t=$(mktemp -d)
    if curl -fsSL "https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${GOARCH}.tar.gz" -o "$t/b.tgz" 2>/dev/null; then
      tar xzf "$t/b.tgz" -C "$DIR/backhaul" backhaul 2>/dev/null && chmod +x "$DIR/backhaul/backhaul"
    else warn "Backhaul download failed; the Backhaul engine stays inactive."; fi
    rm -rf "$t"
  fi
}

panel_service(){
  # make `rakhsh` a global command
  ln -sf "$BIN" /usr/local/bin/rakhsh
  cat >/etc/systemd/system/rakhsh-panel.service <<UNIT
[Unit]
Description=Rakhsh panel / node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now rakhsh-panel.service
}

echo
echo "  1) Iran edge  (public — users connect here)"
echo "  2) Foreign server  (runs your services behind the tunnel)"
echo "  3) Node core  (headless, joins a central panel)"
read -rp "Role [1]: " ROLE; ROLE=${ROLE:-1}
case "$ROLE" in 1) RNAME=iran;; 2|3) RNAME=foreign;; *) die "bad choice";; esac

read -rp "Admin username [admin]: " AU; AU=${AU:-admin}
read -rp "Admin password [random]: " AP || true
read -rp "Pro license key [none]: " LIC || true

install_binary
install_frp
install_engines

# pick the panel port: 7777 unless already in use, then the next free one
PORT=7777
if ss -tln 2>/dev/null | grep -q ":7777 "; then
  for p in 8777 9777 7000 7778 8181; do ss -tln 2>/dev/null | grep -q ":$p " || { PORT=$p; break; }; done
  warn "port 7777 is in use — the panel will run on $PORT instead."
fi

"$BIN" setup --role "$RNAME" --user "$AU" --port "$PORT" ${AP:+--pass "$AP"} ${LIC:+--license "$LIC"}
panel_service
sleep 2

echo
echo "============================================================"
say "Rakhsh installed as the $RNAME role."
"$BIN" show-panel-url | sed 's/^/   Panel: /'
echo "   Lost the URL later?  rakhsh show-panel-url"
echo "   New password:        rakhsh reset-password"
echo "   TLS:                 put caddy/nginx in front of :7777"
echo "============================================================"
[ "$RNAME" = iran ] && echo "Next: open the panel, create a tunnel, copy its rkh1_ bundle to the foreign server."
