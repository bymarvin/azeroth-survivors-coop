#!/bin/bash
# Download server for Azeroth Survivors Together updates (Debian 13, boot-log format, idempotent).
#
#   ssh -i <admin key> <admin>@<server> "sudo bash -s -- '<upload public key>'" < setup_server.sh
#   ssh -i <admin key> <admin>@<server> "sudo DOMAIN=azsurvivors-oce.duckdns.org MIRROR=0 bash -s" < setup_server.sh
#     (MIRROR=0: no download mirror and no upload user, the site only answers /healthz)
#
# - caddy (Debian package): https://azsurvivors.duckdns.org serves /srv/azsurvivors/files
#   (GET/HEAD only, Range, no directory listing, latest.json/.sig cached 60 s, the rest 1 h).
# - azdeploy: upload only, SFTP chroot /srv/azsurvivors (files/ writable), no shell, no sudo,
#   no forwarding; its key in /etc/ssh/azdeploy_authorized_keys (restrict).
# - unattended-upgrades for security updates.
# Touches nothing else on the server (other services keep running as they are).
set -euo pipefail

DOMAIN=${DOMAIN:-azsurvivors.duckdns.org}
MIRROR=${MIRROR:-1}
BASE=/srv/azsurvivors
FILES=$BASE/files
USER_NAME=azdeploy
KEYS=/etc/ssh/azdeploy_authorized_keys
MARK_BEGIN='# >>> azsurvivors upload (setup_server.sh)'
MARK_END='# <<< azsurvivors upload'
UPLOAD_KEY=${1:-}

step() { STEP=$1; STARTED=$(date +%s.%N); echo "[ .... ] $1"; }
ok() { printf '[  OK  ] %s (%.1f s%s)\n' "$STEP" "$(echo "$(date +%s.%N) - $STARTED" | bc)" "${1:+, $1}"; }
fail() { echo "[FAILED] $STEP: $1"; exit 1; }
trap 'echo "[FAILED] ${STEP:-setup}: command failed (line $LINENO)"' ERR

[ "$(id -u)" = 0 ] || { echo "[FAILED] run with sudo"; exit 1; }
[ "$MIRROR" = 0 ] || [[ "$UPLOAD_KEY" == ssh-ed25519\ * ]] || { echo "[FAILED] upload public key (ssh-ed25519 ...) as first argument"; exit 1; }
command -v bc >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -q bc >/dev/null; }

step "Pakete (caddy)"
if dpkg -s caddy >/dev/null 2>&1; then
    ok "caddy $(dpkg-query -W -f '${Version}' caddy) schon installiert"
else
    DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q caddy >/dev/null
    ok "caddy $(dpkg-query -W -f '${Version}' caddy) installiert"
fi

if [ "$MIRROR" != 0 ]; then
step "Upload-Nutzer $USER_NAME"
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$BASE" --shell /usr/sbin/nologin "$USER_NAME"
    made=angelegt
else
    usermod --shell /usr/sbin/nologin --home "$BASE" "$USER_NAME"
    made=vorhanden
fi
passwd -l "$USER_NAME" >/dev/null
install -d -o root -g root -m 755 "$BASE"           # chroot: root-owned, not writable by others
install -d -o "$USER_NAME" -g "$USER_NAME" -m 755 "$FILES"
printf 'restrict %s\n' "$UPLOAD_KEY" > "$KEYS.new"
chown root:root "$KEYS.new"; chmod 644 "$KEYS.new"; mv "$KEYS.new" "$KEYS"
ok "$made, Shell nologin, Passwort gesperrt, Schlüssel $(ssh-keygen -lf "$KEYS" | awk '{print $2}')"

step "sshd: SFTP-Chroot nur für $USER_NAME"
CONFIG=/etc/ssh/sshd_config
cp -n "$CONFIG" "$CONFIG.before-azsurvivors"
# Remove an earlier block, then append ours at the very end (a Match applies to the rest of the file).
sed -i "/^$MARK_BEGIN\$/,/^$MARK_END\$/d" "$CONFIG"
cat >> "$CONFIG" <<EOF
$MARK_BEGIN
Match User $USER_NAME
    AuthorizedKeysFile $KEYS
    ChrootDirectory $BASE
    ForceCommand internal-sftp -u 0022
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    PasswordAuthentication no
$MARK_END
EOF
sshd -t || { cp "$CONFIG.before-azsurvivors" "$CONFIG"; fail "sshd -t refused the config (restored)"; }
admin=$(sshd -T -C user=root,host=x,addr=127.0.0.1 | grep -E '^(chrootdirectory|forcecommand) ' | tr '\n' ' ')
deploy=$(sshd -T -C user=$USER_NAME,host=x,addr=127.0.0.1 | grep -E '^(chrootdirectory|forcecommand) ' | tr '\n' ' ')
[[ "$admin" == *"chrootdirectory none"* ]] || fail "the block would affect other users: $admin"
[[ "$deploy" == *"chrootdirectory $BASE"* ]] || fail "the block does not apply to $USER_NAME: $deploy"
systemctl reload ssh
ok "andere Nutzer: ${admin}; $USER_NAME: ${deploy}"
fi

step "Caddy: $DOMAIN -> $([ "$MIRROR" = 0 ] && echo /healthz || echo "$FILES")"
cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.debian-default 2>/dev/null || true
if [ "$MIRROR" = 0 ]; then
cat > /etc/caddy/Caddyfile.new <<EOF
# Azeroth Survivors Together region server without download mirror (setup_server.sh MIRROR=0).
$DOMAIN {
	respond /healthz "ok" 200
	respond 404
	header -Server
	header X-Content-Type-Options nosniff
}

# Further sites (e.g. the lobby relay) drop their own file here; this script never touches them.
import /etc/caddy/sites.d/*.caddy
EOF
else
cat > /etc/caddy/Caddyfile.new <<EOF
# Azeroth Survivors Together update downloads (setup_server.sh). HTTPS certificates: automatic.
$DOMAIN {
	root * $FILES
	@write not method GET HEAD
	respond @write 405
	@release path */latest.json */latest.json.sig
	header @release Cache-Control "public, max-age=60"
	@other not path */latest.json */latest.json.sig
	header @other Cache-Control "public, max-age=3600"
	header -Server
	header X-Content-Type-Options nosniff
	file_server
}

# Further sites (e.g. the US lobby relay) drop their own file here; this script never touches them.
import /etc/caddy/sites.d/*.caddy
EOF
fi
mkdir -p /etc/caddy/sites.d
caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile.new >/dev/null 2>&1 || fail "caddy validate refused the config"
mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
systemctl enable --now caddy >/dev/null 2>&1
systemctl reload caddy
ok "$(systemctl is-active caddy), Ports $(ss -ltn '( sport = :80 or sport = :443 )' | awk 'NR>1 {print $4}' | tr '\n' ' ')"

step "Sicherheitsupdates (unattended-upgrades)"
if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q unattended-upgrades >/dev/null
fi
if ! grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
fi
systemctl enable --now unattended-upgrades >/dev/null 2>&1
ok "$(systemctl is-active unattended-upgrades), $(grep -c '"1"' /etc/apt/apt.conf.d/20auto-upgrades)/2 Periodic aktiv"

step "Platz"
ok "$(df -h / | awk 'NR==2 {print $4 " frei von " $2}')$([ "$MIRROR" = 0 ] || echo ", $FILES: $(du -sh "$FILES" | cut -f1)")"
if [ "$MIRROR" = 0 ]; then echo "[ INFO ] Zusammenfassung: Server bereit (https://$DOMAIN/healthz, ohne Download-Spiegel)"
else echo "[ INFO ] Zusammenfassung: Server bereit (https://$DOMAIN/, Upload per sftp als $USER_NAME nach /files)"; fi
