#!/bin/bash
# US room directory (lobby) and relay for Azeroth Survivors Together (Debian 13, boot-log format, idempotent).
#
#   scp lobby_server.py lobby.py crash_reports.py server.py SHA256SUMS <admin>@<server>:/tmp/azsurvivors-lobby-src/
#   ssh <admin>@<server> "sudo bash -s" < setup_lobby_relay.sh
#
# - azsurvivors-lobby: reconstruction/lobby_server.py unchanged (as on dash2812.de) on
#   127.0.0.1:47770 as user azlobby; Caddy terminates HTTPS for lobby.azsurvivors.duckdns.org.
#   Crash reports: the lobby's own cap (1024 files / 256 MiB) plus deletion after 30 days.
# - azsurvivors-relay: relay/server.py unchanged on TCP 47771 as user azrelay. Clients verify it
#   with the system CA store for the directory's host name, so it uses Caddy's Let's Encrypt
#   certificate of that name; azsurvivors-relay-cert copies it (root, on change and daily) and
#   restarts the relay when it was renewed.
# - Both: restart on failure, memory/task/file limits, no access logs (no invitations or tokens).
# - journald capped at 150 MB / 14 days.
# - Caddy: one own file in /etc/caddy/sites.d/ plus (once) the line `import /etc/caddy/sites.d/*.caddy`
#   at the end of the Caddyfile, the same line setup_server.sh writes; the download site stays as
#   it is; validated before reload.
# The GCP firewall must allow TCP 47771 (done by the owner, not by this script).
set -euo pipefail

DOMAIN=lobby.azsurvivors.duckdns.org
SRC=${1:-/tmp/azsurvivors-lobby-src}
CODE=/opt/azsurvivors-coop
STATE=/var/lib/azsurvivors-lobby
TLS=/etc/azsurvivors-relay/tls
CADDY_SITE=/etc/caddy/sites.d/azsurvivors-lobby.caddy
CADDY_CERTS=/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory
IMPORT_LINE='import /etc/caddy/sites.d/*.caddy'  # Same line as setup_server.sh writes.

step() { STEP=$1; STARTED=$(date +%s.%N); echo "[ .... ] $1"; }
ok() { printf '[  OK  ] %s (%.1f s%s)\n' "$STEP" "$(echo "$(date +%s.%N) - $STARTED" | bc)" "${1:+, $1}"; }
info() { echo "[ INFO ] $1"; }
fail() { echo "[FAILED] $STEP: $1"; exit 1; }
trap 'echo "[FAILED] ${STEP:-setup}: command failed (line $LINENO)"' ERR

[ "$(id -u)" = 0 ] || { echo "[FAILED] run with sudo"; exit 1; }
command -v bc >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -q bc >/dev/null; }

step "Quelldateien prüfen ($SRC)"
for f in lobby_server.py lobby.py crash_reports.py server.py SHA256SUMS; do
    [ -f "$SRC/$f" ] || fail "$f fehlt"
done
(cd "$SRC" && sha256sum --quiet -c SHA256SUMS) || fail "SHA-256 stimmt nicht"
ok "4 Dateien, SHA-256 geprüft"

step "Dienstnutzer azlobby, azrelay"
for u in azlobby azrelay; do
    id "$u" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
    passwd -l "$u" >/dev/null
done
ok "ohne Shell, Passwort gesperrt"

step "Code nach $CODE (root, nur lesbar)"
install -d -o root -g root -m 755 "$CODE" "$CODE/reconstruction" "$CODE/relay"
install -o root -g root -m 644 "$SRC/lobby_server.py" "$SRC/lobby.py" "$SRC/crash_reports.py" "$CODE/reconstruction/"
install -o root -g root -m 644 "$SRC/server.py" "$CODE/relay/server.py"
install -o root -g root -m 644 "$SRC/SHA256SUMS" "$CODE/SHA256SUMS"
ok "$(cd "$CODE" && find . -name '*.py' | wc -l) Python-Dateien"

step "Crash-Berichte: Ablage und Rotation"
install -d -o azlobby -g azlobby -m 750 "$STATE" "$STATE/collected-logs"
cat > /etc/tmpfiles.d/azsurvivors-lobby.conf <<EOF
# Crash and completion reports of the US lobby: deleted after 30 days (the lobby caps 1024 files / 256 MiB).
d $STATE/collected-logs 0750 azlobby azlobby 30d
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/azsurvivors-lobby.conf
ok "30 Tage (systemd-tmpfiles-clean.timer, täglich)"

step "journald begrenzen"
install -d -m 755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/azsurvivors.conf <<EOF
[Journal]
SystemMaxUse=150M
MaxRetentionSec=14day
EOF
systemctl restart systemd-journald
ok "150 MB, 14 Tage"

step "Dienst azsurvivors-lobby"
cat > /etc/systemd/system/azsurvivors-lobby.service <<EOF
[Unit]
Description=Azeroth Survivors Together US room directory (lobby_server.py, behind Caddy)
After=network-online.target
Wants=network-online.target

[Service]
User=azlobby
Group=azlobby
WorkingDirectory=$CODE/reconstruction
ExecStart=/usr/bin/python3 -E -s $CODE/reconstruction/lobby_server.py --bind 127.0.0.1 --port 47770 --collected-logs $STATE/collected-logs
Environment=PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
Restart=always
RestartSec=2
MemoryMax=160M
TasksMax=96
LimitNOFILE=1024
CPUQuota=60%
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
ReadWritePaths=$STATE
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
ok

step "Zertifikatsübergabe Caddy -> Relay"
install -d -o root -g azrelay -m 750 /etc/azsurvivors-relay "$TLS"
cat > /usr/local/sbin/azsurvivors-relay-cert <<EOF
#!/bin/bash
# Copy Caddy's certificate for $DOMAIN to the relay; restart the relay only when it changed.
set -euo pipefail
src=$CADDY_CERTS/$DOMAIN
[ -f "\$src/$DOMAIN.crt" ] && [ -f "\$src/$DOMAIN.key" ] || { echo "[ WAIT ] no certificate for $DOMAIN yet"; exit 0; }
if ! cmp -s "\$src/$DOMAIN.crt" $TLS/fullchain.pem || ! cmp -s "\$src/$DOMAIN.key" $TLS/key.pem; then
    install -o root -g azrelay -m 640 "\$src/$DOMAIN.crt" $TLS/fullchain.pem
    install -o root -g azrelay -m 640 "\$src/$DOMAIN.key" $TLS/key.pem
    echo "[  OK  ] certificate updated, valid until \$(openssl x509 -enddate -noout -in $TLS/fullchain.pem | cut -d= -f2)"
    systemctl try-restart azsurvivors-relay.service
fi
EOF
chmod 755 /usr/local/sbin/azsurvivors-relay-cert
cat > /etc/systemd/system/azsurvivors-relay-cert.service <<EOF
[Unit]
Description=Copy the Let's Encrypt certificate of $DOMAIN from Caddy to the relay

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/azsurvivors-relay-cert
EOF
cat > /etc/systemd/system/azsurvivors-relay-cert.path <<EOF
[Unit]
Description=Watch Caddy's certificate of $DOMAIN

[Path]
PathChanged=$CADDY_CERTS/$DOMAIN/$DOMAIN.crt
Unit=azsurvivors-relay-cert.service

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/azsurvivors-relay-cert.timer <<EOF
[Unit]
Description=Daily check of the relay certificate (backup to the path unit)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
ok

step "Dienst azsurvivors-relay"
cat > /etc/systemd/system/azsurvivors-relay.service <<EOF
[Unit]
Description=Azeroth Survivors Together US relay (relay/server.py, TCP 47771)
After=network-online.target azsurvivors-lobby.service
Wants=network-online.target azsurvivors-lobby.service
ConditionPathExists=$TLS/fullchain.pem

[Service]
User=azrelay
Group=azrelay
WorkingDirectory=$CODE/relay
ExecStart=/usr/bin/python3 -E -s $CODE/relay/server.py --bind 0.0.0.0 --port 47771 --directory http://127.0.0.1:47770 --cert $TLS/fullchain.pem --key $TLS/key.pem
Environment=PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
Restart=always
RestartSec=2
MemoryMax=200M
TasksMax=96
LimitNOFILE=2048
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
ok

step "Caddy: eigene Site $DOMAIN"
install -d -o root -g root -m 755 /etc/caddy/sites.d
cat > "$CADDY_SITE.new" <<EOF
# US room directory for Azeroth Survivors Together (setup_lobby_relay.sh). HTTPS certificate: automatic.
# No access log: requests carry room memberships (Bearer) and invitations.
$DOMAIN {
	request_body {
		max_size 2MB
	}
	reverse_proxy 127.0.0.1:47770
	header -Server
	header X-Content-Type-Options nosniff
}
EOF
cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.before-azsurvivors-lobby
PREVIOUS=$(mktemp)
cp /etc/caddy/Caddyfile "$PREVIOUS"
[ -f "$CADDY_SITE" ] && cp "$CADDY_SITE" "$PREVIOUS.site" || rm -f "$PREVIOUS.site"
mv "$CADDY_SITE.new" "$CADDY_SITE"
grep -qxF "$IMPORT_LINE" /etc/caddy/Caddyfile || printf '\n%s\n' "$IMPORT_LINE" >> /etc/caddy/Caddyfile
if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    # Put everything back so a later Caddy restart still starts with the old, working config.
    cp "$PREVIOUS" /etc/caddy/Caddyfile
    if [ -f "$PREVIOUS.site" ]; then cp "$PREVIOUS.site" "$CADDY_SITE"; else rm -f "$CADDY_SITE"; fi
    fail "caddy validate (Caddyfile und Site-Datei zurückgesetzt)"
fi
rm -f "$PREVIOUS" "$PREVIOUS.site"
systemctl reload caddy
ok "validiert und neu geladen"

step "Dienste starten"
systemctl daemon-reload
systemctl enable --now azsurvivors-lobby.service >/dev/null 2>&1
for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:47770/rooms >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 http://127.0.0.1:47770/rooms >/dev/null || fail "Lobby antwortet nicht"
info "Lobby antwortet auf 127.0.0.1:47770"
for i in $(seq 1 90); do [ -f "$CADDY_CERTS/$DOMAIN/$DOMAIN.crt" ] && break; sleep 2; done
[ -f "$CADDY_CERTS/$DOMAIN/$DOMAIN.crt" ] || fail "Caddy hat noch kein Zertifikat für $DOMAIN (Port 80/443 erreichbar?)"
/usr/local/sbin/azsurvivors-relay-cert
systemctl enable --now azsurvivors-relay-cert.path azsurvivors-relay-cert.timer >/dev/null 2>&1
systemctl enable --now azsurvivors-relay.service >/dev/null 2>&1
sleep 2
systemctl is-active --quiet azsurvivors-relay.service || fail "Relay läuft nicht"
ok "Lobby, Relay, Zertifikatsübergabe aktiv"

step "Selbsttest"
curl -fsS -m 10 "https://$DOMAIN/rooms" >/dev/null || fail "https://$DOMAIN/rooms"
echo | timeout 10 openssl s_client -connect 127.0.0.1:47771 -servername "$DOMAIN" -verify_return_error >/dev/null 2>&1 \
    || fail "Relay-TLS für $DOMAIN"
ok "HTTPS-Lobby und Relay-TLS ($DOMAIN) gültig"
info "Speicher: $(systemctl show -p MemoryCurrent --value azsurvivors-lobby.service) B Lobby, $(systemctl show -p MemoryCurrent --value azsurvivors-relay.service) B Relay"
