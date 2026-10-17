# Release mit dem Self-Updater (GitHub + externer Host)

Spieler brauchen nur einmal `Azeroth-Survivors-Together-Updater.exe` im Spielordner.
Die exe holt jede spätere Version selbst. Auf GitHub liegen nur die signierte Versionsdatei,
die Mod-Archive und die Updater-exe. Spieldateien (`AzerothSurvivors.exe`, `Data/*.MPQ`)
liegen nie auf GitHub, sondern auf einem externen Host (direkte HTTPS-Links). Ihre Echtheit
sichert die SHA-256 in der signierten Datei.

## Einmalig
- Signierschlüssel: `sign_release.py init` (ist schon erledigt).
  - Die Datei ist `%USERPROFILE%\.azcoop-signing\release-key.pem` und nur für dich lesbar.
  - Sie darf **nie** ins Repo, in ein Zip, ein Log oder eine Nachricht.
  - Sicherung: auf einen eigenen USB-Stick oder in einen Passwort-Safe.
  - Ohne diesen Schlüssel kann kein bestehender Updater ein neues Release annehmen.
- Öffentlicher Schlüssel: `KT0uZ26Iiq4BoCNZPNuYDOWFCMJJenW83dALTZFyMjc=`. Er steht in
  `reconstruction/self_update.py` (`TRUSTED_KEYS`).
- GitHub: öffentliches Repo `bymarvin/azeroth-survivors-together`, nur `README.md` (siehe
  `GITHUB-README.md`) und Releases, kein Quellcode.

## Pro Release
1. **Paket bauen:** wie bisher, Gesamtabnahme, `bind_active`, `make_package`. Ergebnis ist der Staging-Ordner,
   z. B. `Releases\stage\Azeroth Survivors Together 0.95.0`.
2. **Updater-exe bauen** (nur nötig, wenn sich `self_update.py` oder `online.rs` geändert hat):
   `cargo build --release --bin coop-updater` in `coop-lab/updater/exe`.
   - Mit `COOP_UPDATER_VERSION=<n>` gibst du eine neue Updater-Version vor.
   - Wenn ein Release eine neue Updater-Logik braucht, setzt du `--min-updater <n>`: Alte exes laden die neue
     dann zuerst und tauschen sich selbst.
3. **Spieldateien als Binär-Patches (Updater 2, ab 0.0.12):** Spieldateien liegen im zweiten Repo
   `bymarvin/azeroth-survivors-gamefiles`. Eine Takedown dort trifft nur diese Assets; der Updater fällt dann auf
   den Vollpaket-Link zurück.
   - Generator einmal bauen: `cargo build --release` in `coop-lab/updater/patchgen` (bsdiff auf divsufsort, nur
     bei uns). Spieler wenden die Patches in reinem Python an (`game_patch.py`, lzma, streamend).
   - Assets bauen: `coop-lab/updater/make_game_patches.py --target <Staging> --from <alter Paketordner> ...
     --out <Releases>\gamefiles-<Spiel-Hash>`.
     - Je alter Spielversion entsteht ein Patch (`.azp`), plus ein Vollasset (`.xz`) für jede Datei bis
       `--full-max-mb` (256).
     - Jeder Patch wird beim Bauen geprüft, mit Zeit und Spitzen-RAM im Log.
   - Assets als Release `game-<Spiel-Hash>` ins Gamefiles-Repo hochladen. `make_release.py` bekommt dazu
     `--gamefiles <Ordner> --gamefiles-url https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/game-<Spiel-Hash>/
     --min-updater 2 --updater-version 2` und die Updater-exe v2 (`COOP_UPDATER_VERSION=2`).
   - Updater 1 holt sich wegen `min_updater 2` zuerst selbst v2.
   - Die neue Logik steckt nur in der exe (`updater_v2.py` + `game_patch.py`). Das gebundene
     `reconstruction/self_update.py` bleibt unverändert, also ist keine neue Bindung nötig.
   - Probe: `e2e_release.py ... --gamefiles <Ordner>`. Die Assets laufen über einen lokalen Server
     (Umgebungsvariable `COOP_GAMEFILES_URL`, wie `--release-url`).
   **Ohne Spieldatei-Assets:** Ohne Direkt-Host (Stand 0.0.12) entfällt `--game-sources`.
   - Spieldateien ohne Adresse bekommen die GitHub-Release-Seite als Quelle. Ordner mit derselben Spielversion
     laden sie nie (gleicher Hash, z. B. 0.0.11 → 0.0.12 lädt nur das Mod-Archiv).
   - Ordner einer anderen Spielversion (0.92, 0.93.1) brechen sofort ab, ohne etwas zu ändern, und zeigen
     „Download the full package here: <Link>“. `--full-package-url` ist dann Pflicht.
   - Asset-Namen enthalten nur `[0-9A-Za-z._-]` (`+` wird zu `-`), weil GitHub andere Zeichen umbenennt.
   - Probe vor dem Hochladen mit lokalem Server und echter Updater-exe:
     `coop-lab/updater/e2e_release.py <Release-Ordner> <Staging> <Arbeitsordner> expect-update-<alt>=<Ordner>
     expect-full-<alt>=<Ordner>`
   Mit Direkt-Host: nur wenn sich die Spieldateien geändert haben.
   - Hochladen auf einen externen Host, der **direkte HTTPS-Links** liefert: Die Adresse gibt sofort die
     Datei zurück, ohne Download-Seite, Wartezeit oder Captcha.
   - **storage.to, uploadex und ähnliche Hoster gehen nicht.** Ihre Links führen auf eine Seite mit Captcha.
     Der Updater umgeht keine Captchas. Er erkennt die Seite (HTML, 401/403/404/410/429 oder falsche Größe)
     und bricht ab, bevor er etwas installiert.
     Der Spieler sieht dann: „neue Spieldateien nötig … Vollpaket hier laden: <URL>“.
   - Weiterleitungen folgt der Updater nur per HTTPS, höchstens 5, und nur zu GitHub oder zu den Hosts, die in
     `game-sources.json` stehen. Leitet ein Host auf ein eigenes CDN um, gilt das als „kein Direktlink“.
   - Die Adressen trägst du in `game-sources.json` ein:
     `{"AzerothSurvivors.exe": "https://...", "Data/patch.MPQ": "https://...", ...}`
4. **Release-Ordner bauen und signieren:**
   ```
   .coop-runtime\python.exe coop-lab\port-7264\make_release.py --target "<Staging-Ordner>"
       --game-sources game-sources.json --updater-exe <coop-updater.exe> [--min-updater 1]
       --full-package-url <HTTPS-Link zum Vollpaket>
   ```
   - `make_release` prüft jede Spieldatei-Adresse, indem es per HTTP Range das erste KiB lädt. Es bricht ab, wenn
     eine Adresse keine direkte Datei mit der signierten Größe liefert.
   - `--no-check-urls` schaltet diese Prüfung ab. Das ist nur sinnvoll, wenn du sicher bist, dass sich keine
     Spieldatei geändert hat und deshalb keine geladen wird.
   - `--full-package-url` wird mitsigniert. Das ist der Link, den Spieler sehen, wenn die Spieldateien nicht
     direkt ladbar sind. Hier darf eine Seite mit Captcha stehen, denn diesen Link öffnet ein Mensch.
   Der Ordner `Releases\github-<version>\` enthält `latest.json`, `latest.json.sig`,
   `manifest-<v>.json`, `mod-<v>.zip`, `runtime-<v>.zip`, die Updater-exe und `UPLOAD.txt`.
5. **GitHub:** neues Release anlegen, alle Dateien außer `UPLOAD.txt` als Assets hochladen und das Release
   als **Latest** markieren. Die feste Adresse lautet
   `https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/latest.json`.
6. **Prüfen:** in einer Kopie eines alten Spielordners die Updater-exe starten.

## Sicherheitsregeln (erzwingt der Updater)
- `latest.json` muss von einem vertrauten Schlüssel signiert sein. Alle anderen Dateien sind per SHA-256 darin
  festgelegt.
- Nur HTTPS, auch nach Weiterleitungen. Jede Anfrage hat eine Größengrenze und ein Timeout.
- Keine ältere Version als installiert und kein älteres signiertes Release als das zuletzt angenommene
  (`sequence`, `signed_at`). Die `sequence` ist standardmäßig die Unix-Zeit und steigt damit von Release zu
  Release.
- Spielstände, Profile, AddOns, WTF und Logs werden nie angefasst.
- Nur Pfade aus dem signierten Manifest werden geschrieben. Abgewiesen werden:
  - `..`, Laufwerke, `:` (Laufwerke und ADS), reservierte Namen (CON, NUL, COM1 …) und Punkt oder Leerzeichen
    am Namensende,
  - Ziele außerhalb des Spielordners, auch über eine Junction.
- Aus den Zips wird nur genau das signierte Mitglied übernommen: keine Links, Größe wie signiert und gedeckelt
  (keine Entpack-Bombe), danach die SHA-256-Prüfung.
- Ändert ein Release die `.coop-runtime`, kopiert der Updater sie zuerst nach `coop-update\runtime`, denn
  Windows sperrt die laufende python.exe und ihre DLLs.
  - Danach startet die exe den Updater aus der Kopie neu und ersetzt dann das Original. Am Ende wird die Kopie
    gelöscht.
  - Ohne die exe (direkter Python-Aufruf) bricht der Updater ab, bevor er etwas ändert.

## Schlüssel wechseln
1. `sign_release.py rotate` erzeugt einen neuen Schlüssel.
2. Nächstes Release: mit dem **alten** Schlüssel signieren und `--announce-key <neu>` mitgeben. Updater merken
   sich den neuen Schlüssel.
3. Danach mit dem neuen Schlüssel signieren und ihn in `TRUSTED_KEYS` aufnehmen. Später kann ein Release mit
   `--retire-key <alt>` den alten Schlüssel ausmustern.

## Automatisches Update in Start-Coop.cmd (ab 0.0.13)
- `Start-Coop.cmd` führt vor dem Launcher `coop_autoupdate.py` aus.
  - Es fragt höchstens etwa 3 s lang nach einer signierten Version, über das gebundene `self_update.check`.
  - Gibt es eine neuere: Meldung „Update X -> Y … (Enter = skip)“ und 5 s Countdown. Fehlt die Updater-exe oder ist
    sie anders als die signierte, wird sie geholt. Exit 10.
  - Danach, wenn Python beendet und die Runtime frei ist, startet `Start-Coop.cmd` die Updater-exe und immer
    anschließend den Launcher.
- Abschalten: `COOP_AUTO_UPDATE=0` oder die Datei `coop-update\no-auto-update`.
- Alles nach dem Update steht in **einem** Block `( … exit /b )`. cmd liest ihn vorab komplett ein, deshalb darf ein
  Update `Start-Coop.cmd` selbst ersetzen. Diesen Aufbau beibehalten.
- `Start-Coop.cmd`, `coop_launcher.py`, `coop_autoupdate.py` und `COOP-VERSION.txt` gehören nicht zur
  Quellidentität der Bindung. Änderungen daran brauchen keine neue Bindung.
  - `make_package.py` nimmt `coop_autoupdate.py` mit.
  - `make_package.py` schreibt `package-manifest.json` jetzt genau so, wie der Updater es schreibt (byte-gleich nach
    Updates).
- Probe: `coop-lab/updater/e2e_autostart.py --staging <0.0.12-Staging> --gamefiles <Ordner> --work <neuer Ordner>`.
  - Läuft mit Testschlüssel und Test-Updater-exe, über einen lokalen Server.
  - Prüft 0.0.12 → 0.0.13 per exe, dann über Start-Coop 0.0.13 → 0.0.14: mit exe, ohne exe, beschädigtes Release,
    offline und abgeschaltet.
  - Der Launcher läuft dabei nur mit `--help`.

## Updater-exe im Paket (ab 0.0.13, Updater 3)
- Jedes Paket enthält `Azeroth-Survivors-Together-Updater.exe` neben `Start-Coop.cmd`.
  - `make_package.py` verlangt die exe im Build-Ordner und nimmt sie mit.
  - In `mod-<ver>.zip` und im Manifest steht sie wie jede andere Mod-Datei.
- Reihenfolge:
  1. Updater bauen: `COOP_UPDATER_VERSION=3 cargo build --release --bin coop-updater`, ohne `COOP_UPDATER_TEST_KEY`.
  2. Die exe als `Azeroth-Survivors-Together-Updater.exe` in den Build-Ordner legen.
  3. `make_package`.
  4. `make_release` mit **derselben** exe als `--updater-exe` und `--min-updater 3`. make_release prüft beides.
- Ist die laufende exe selbst eine geänderte Datei, ersetzt Updater 3 sie nicht während des Laufs (sie ist von
  Windows gesperrt):
  - Nach erfolgreicher Installation liegt die neue exe als `.new` daneben, und der Lauf endet mit 3.
  - Die exe tauscht sich selbst aus und läuft noch einmal; dann ist nichts mehr zu tun.
  - Ältere exes (1/2) holen sich wegen `min_updater 3` vorher Updater 3.
- `coop_autoupdate.py` lädt die exe nur noch, wenn sie im Ordner fehlt (Rückfall). Eine vorhandene exe aktualisiert
  sich selbst.

## Updater 4, Web-Installer, eigener Server, --publish
- **Quellen der Spieldateien** (`--gamefiles-url` mehrfach, signiert): Der Updater versucht sie der Reihe nach. Eine
  Seite, 404/410/429, ein Abbruch (Teil-Download läuft weiter) oder ein falscher SHA-256 führen zur nächsten Quelle.
  - Entscheidung des Users (17.10.2026): „my server should handle the traffic“.
    - Erste Quelle ist `https://azsurvivors.duckdns.org/game-<hash>/` für alle Spieldateien (Patches und Vollassets
      inkl. `patch.MPQ`).
    - Das GitHub-Gamefiles-Repo ist nur Rückfall bei Ausfall oder 404.
    - Aufruf: `--gamefiles-url https://azsurvivors.duckdns.org/game-<hash>/ --gamefiles-url
      https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/game-<hash>/`.
    - Kosten: Server-Egress etwa 0,12 $/GB; eine Neuinstallation sind etwa 1,4 GB, also etwa 0,17 $. Patches sind
      wenige MB.
  - Mod, Runtime und Updater-exe bleiben im GitHub-Release, wie gehabt.
  - Die Reihenfolge steht in der signierten URL-Liste und lässt sich mit jedem Release ändern.
- **Assets für Neuinstallationen:**
  - `make_game_patches.py --full-for-all --full-max-mb 2047`: Vollassets für jede Spieldatei.
  - Vollassets packt `xz.exe` (aus Git: `C:\Program Files\Git\mingw64\bin`) mit `-9`, parallelen 64-MiB-Blöcken
    und `--threads=+N`. Die Bytes hängen nicht von der Thread-Anzahl ab (`test_xz_mt.py`).
    - `patch.MPQ`: 47 s statt 550 s, 483,7 statt 478,3 MiB, Spitze ~9,6 GB RAM bei 13 Threads.
    - Ohne xz.exe: einthreadig mit lzma, mit Warnung im Log.
    - Der Updater liest beides (ein normaler xz-Stream).
  - MPQ-Archive, die xz nicht verkleinert, gehen als `raw` (die Datei selbst), z. B. `patch.MPQ` mit 1,34 GB.
  - Mehrere Quellen oder raw verlangen `--min-updater 4` (make_release prüft das).
- **Web-Installer** (`coop-lab/installer`):
  - Bauen: `cargo build --release`. Ergebnis ist `azsurvivors-installer.exe`, hochladen als
    `Azeroth-Survivors-Together-Installer.exe`.
  - Er prüft latest.json mit Ed25519. Die Schlüssel kommen aus dem eingebetteten `self_update.py`, eine Quelle für
    beide.
  - Er lädt das Runtime-Archiv von GitHub (SHA-geprüft, fortsetzbar) und entpackt es mit Windows-`tar.exe`.
  - Danach installiert der eingebettete Updater 4 alles Weitere.
  - Bei einer vorhandenen Installation läuft deren Updater-exe (Update-Modus).
  - Downloads laufen über Windows-`curl.exe` aus System32.
  - Ein Schlüsselwechsel braucht einen neuen Installer.
  - Probe: `coop-lab/installer/e2e_installer.py` mit lokalen Servern, Testschlüssel und Test-Builds.
- **Veröffentlichen:** `make_release.py … --publish` (Probelauf: `--publish-dry-run`).
  - Vorprüfung: gh-Anmeldung, SFTP und der Platz nach dem Aufräumen.
  - Reihenfolge: Spieldateien zuerst auf alle Quellen (Server per SFTP als `azdeploy`, GitHub-Gamefiles-Repo), dann
    das GitHub-Release (neu als Entwurf, dann Latest; vorhanden: `latest.json` zuletzt), dann der Spiegel auf dem
    Server (`/releases/<tag>/`, `latest.json` zuletzt).
  - Aufräumen: auf dem Server bleiben die letzten 2 Spielversionen und Releases, nach `/files/published.json`.
  - Schlüssel: `%USERPROFILE%\.ssh\azsurvivors_upload`.
  - Server einrichten: `coop-lab/server/setup_server.sh`.
