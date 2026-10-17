# Azeroth Survivors Together – co-op mod

Source code of the Azeroth Survivors Together co-op mod: play Azeroth Survivors with up to 3 friends.

**Players:** you don't need anything from here. Get the updater from
[azeroth-survivors-together](https://github.com/bymarvin/azeroth-survivors-together/releases/latest).

## Layout
- `reconstruction/` – the mod: native hooks, world/combat replication, rooms and lobby, transport, updater core
- `relay/` – relay client/server for players without a direct connection
- `coop_launcher.py` – launcher (`Start-Coop.cmd` runs it with the bundled Python)
- `analysis/` – reverse-engineering notes and contracts for each supported game build
- `coop-lab/` – port tools for new game versions, acceptance tests, release and updater tooling (see `coop-lab/updater/RELEASING.md`)

The game itself (exe, MPQ files) and the bundled Python runtime are not part of this repository.

Current version: see `COOP-VERSION.txt`.

## License
MIT, see [LICENSE](LICENSE).

## Support
If you enjoy the mod, you can support the servers and updates here: https://buymeacoffee.com/flobo
