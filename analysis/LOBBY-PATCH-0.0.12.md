# Optional directory patch for 0.0.12 (for the operator of dash2812.de)

The 0.0.12 client does **not** need this patch. It works with the unchanged
directory (`lobby.py` as in 0.0.7 / 0.95.0 Fix 7264): a host with a working
UPnP/PCP/NAT-PMP mapping publishes its public IP, otherwise the former
placeholder `127.0.0.1`, exactly like earlier clients. Guests use the relay
for the placeholder.

## What the patch changes and why

- `connection.address` accepts only a literal, globally routable IP
  (`public_address`): no hostnames, no LAN (10/8, 172.16/12, 192.168/16), no
  carrier-grade NAT (100.64/10), no link-local. The old check accepts any
  string from `[A-Za-z0-9.-:]`, so a room could point guests at any hostname
  or at an address inside the guest's own network.
- `null` is accepted as "no direct offer" (relay only); `127.0.0.1` stays
  accepted as the placeholder that all earlier clients send.
- Game port 1024-65535 (privileged ports are never a co-op game port).
- `Rooms(allow_loopback=...)` is set by `lobby_server.server()` for a
  loopback-bound test directory; it is kept for local acceptance runs.

Without the patch nothing breaks; the directory only keeps its looser
address check.

## Diff against the unchanged files

```diff
--- a/reconstruction/lobby.py
+++ b/reconstruction/lobby.py
@@ -1,15 +1,32 @@
 """Four-slot room state. Authentication identifies members, never client-sent slots."""
 from collections import deque
+import ipaddress
 import secrets
 import re
 import threading
 import time
 
 
+def public_address(text):
+    """True only for a literal, globally routable IP address (never a hostname, CGNAT or LAN)."""
+    if not isinstance(text, str) or not 2 <= len(text) <= 45:
+        return False
+    try:
+        address = ipaddress.ip_address(text)
+    except ValueError:
+        return False
+    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
+        address = address.ipv4_mapped
+    shared = ipaddress.ip_network('100.64.0.0/10')  # RFC 6598 carrier-grade NAT.
+    return address.is_global and not (address.version == 4 and address in shared)
+
+
 class Rooms:
-    def __init__(self):
+    def __init__(self, allow_loopback=False):
         self.rooms = {}
         self.lock = threading.RLock()
+        # Only a loopback-bound test directory may publish 127.0.0.1 hosts.
+        self.allow_loopback = allow_loopback
 
     def view(self, room, member=None):
         result = {key: room[key] for key in ('id', 'name', 'private', 'phase', 'revision', 'run', 'build', 'version')}
@@ -107,9 +124,13 @@
             return self.view(room, member)
 
     def connection(self, room_id, token, address, port, fingerprint):
-        if (not isinstance(address, str) or not 1 <= len(address) <= 253 or
-                any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:' for c in address) or
-                type(port) is not int or not 1 <= port <= 65535 or
+        # address None: no direct offer, guests use the relay. Otherwise only a
+        # literal public IP (UPnP/NAT-PMP mapped or manually forwarded). The
+        # 0.0.12 client still sends 127.0.0.1 for "no offer"; it is accepted
+        # as that placeholder so old and new clients keep working.
+        placeholder = address in ('127.0.0.1', '::1')
+        if (address is not None and not public_address(address) and not placeholder or
+                type(port) is not int or not 1024 <= port <= 65535 or
                 not isinstance(fingerprint, str) or len(fingerprint) != 64 or
                 any(c not in '0123456789abcdef' for c in fingerprint)):
             raise ValueError('Invalid game endpoint')
--- a/reconstruction/lobby_server.py
+++ b/reconstruction/lobby_server.py
@@ -88,7 +88,7 @@
 def server(address, *, collected_logs='collected-logs'):
     result = ThreadingHTTPServer(address, Handler)
     result.daemon_threads = True
-    result.rooms = Rooms()
+    result.rooms = Rooms(allow_loopback=address[0] in ('127.0.0.1', 'localhost', '::1'))
     result.reports = CrashReports(collected_logs)
     return result
 
```
