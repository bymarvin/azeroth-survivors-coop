# Game update compatibility — 2026-10-14

## Party markers and downed bodies: project-only follow-up

The exact 0.84.3 build listed below now renders host-owned persistent raid icons
through native `MSG_RAID_TARGET_UPDATE` (0x0321). Each recipient gets its own
SELF GUID plus translated remote GUIDs. The profile-local native Lua minimap
overlay uses distinct party dots, downed gravestones and character-name hover.
The local arrow is retained. Shared level-up health VALUES are held at zero
while native phase 4 is downed, preventing premature visible resurrection.
Observed deaths retain the same actor; no separate corpse or self destruction
was observed. The Lua probe's unavailable `print` call was removed.

Verification on 2026-10-14:

- Five new marker regressions pass under ordinary profile loading; the earlier
  marker/group/departure selection passed all 20 tests in candidate context.
- All nine source-bound four-client native suites / 18 cases pass. These include
  all four deaths/revivals, real native movement, departure, fresh sessions,
  progression, economy, menus and victory paths. Raid-board logs retain unique
  assignments through death/revival, remove only departed slots and clear at end.
- Four-client visual probes show a guest body with its circle on host and both
  other guests, and the host body with its star on all three guests. Both revived
  as one living actor. Bodies persisted across shared level-ups. Hover displayed
  the character name; zoom controls were exercised. Synthetic spacing in these
  visual probes is separate from the real-movement acceptance suite.
- Ordinary project launch passed with installed native hooks and candidate mode
  disabled. No distribution folder or external game installation was updated.

Limits and retained failures: indoor transitions and every zoom level have not
been visually swept; this build is north-up and exposes no rotation setting.
Broad unit discovery is not green: direct candidate-context discovery aborts in
an older executable reward fixture using hard-coded reviewed fields. A reviewed-
layout run completed 390 tests with 6 failures, 6 errors and 7 skips, including
candidate-context guards and multiprocessing harness setup. A corrected ordinary-
context focused rerun completed 50 tests with 48 passes and two fixture errors
(missing disposable EXE/save-lock cleanup and old automatic progression discovery).
No unrelated test or compatibility guard was weakened to obtain a green result.
The initial gear acceptance lacked a randomly awarded weapon; its retry used a
previous native-earned inventory. The first new-hero run timed out with a reserved
chest claim; an isolated retry passed. Both failures remain in acceptance `retries`.

Current source-bound evidence is in `analysis/native-adapter-acceptance.json` and
`analysis/active-hooks.json`. Raw logs, failed attempts, screenshots and runnable
local probes are in `.local-archive/party-markers/`; final visual trace:
`coop-lab/compatibility-tests/markers-probe-5o7zm8wb/events.jsonl`.

## 0.84.3: verified and activated

The supplied `Downloads/AzerothSurvivorsTogether 0.84.3` executable and Data files
are installed in the canonical `to_git` folder and match the source hashes.
Executable SHA-256:
`dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306`.
The previous 0.77.6 EXE, Data and `.version` are preserved in
`_Backup/0.77.6/`; all four files match `backup-manifest.json`.

`reconstruction/release-0.84.3.json` contains the reviewed exact-build mappings.
The port covers changed Game fields, native register/frame ownership, outgoing
queue ownership, dispatch guards and instruction spans, boss definitions,
gold/XP operands, and 160-byte talent-choice records. The menu destructor proof
checks cleanup for all 18 valid command tags. Gear observation retains its
19-slot record/stat-consumer checks while allowing this release's changed item
definitions; it never authorizes calling that diagnostic helper.

Normal launch checks the reviewed profile, executable bytes, source identity,
and all 18 native acceptance requirements. Unknown builds request a matching
co-op release. Automatic discovery is available only through the explicit
`developer_discovery=True` resolver option. The previous 0.77.6 cached-profile
validation path remains available, with its existing identity/acceptance checks.
Restoring game files alone does not make another version's adapter valid.

Original port verification (before the party-marker follow-up):

- Full reconstruction suite: 384 tests, 377 passed and 7 historical/optional
  checks skipped. Relay 7, maintenance 6, and both browser checks passed.
- Three economy regressions passed after the native fixture was changed to
  avoid an existing map chest. The original collision run is preserved; the
  exact-one-purchase assertions were not weakened.
- Final source-bound acceptance: all nine native four-player suites and all
  18 required cases passed, including the corrected economy fixture.
- Object lifecycle regression: 20,000 create/destroy pairs completed with 128
  objects remaining active; active-object and queue-backlog bounds stay enforced.
- Preferences, atomic-write failure, independent profiles, chained traceback
  logging, executable overrides, version rendering, server join/start rejection
  and HTML preference escaping have passing regressions. Independent review
  completed and both identified gaps were fixed.
- Ordinary native launch passed with verified hooks installed and candidate
  mode disabled.

Run unit tests and native acceptance sequentially because their analysis logs
are shared. `analysis/native-adapter-acceptance.json` records the final source
identity; `analysis/active-hooks.json` is the activated profile. Raw evidence
and the first failed fixture run are retained in
`.local-archive/session-followups/` and these disposable directories:

- `coop-lab/compatibility-tests/pause-revival-vokfj1de`
- `coop-lab/compatibility-tests/boss-rewards-v9hncbhv`
- `coop-lab/compatibility-tests/room-menus-3rz06i8x`
- `coop-lab/compatibility-tests/room-gear-jvno5iyv`
- `coop-lab/compatibility-tests/menu-departure-m8mar5pz`
- `coop-lab/compatibility-tests/movement-kkgd3b6l`
- `coop-lab/compatibility-tests/economy-yilt8dg7`
- `coop-lab/compatibility-tests/victory-continue-kv_t9stg`
- `coop-lab/compatibility-tests/victory-new-hero-jxg4xebx`

Verification used four local native processes and isolated saves. It does not
claim a fresh multi-machine Internet test or visual comparison of all rendered
views. Use the rebuilt sibling `player/` overlay with the matching 0.84.3 game.
The D: installation retains its original EXE and Data under `_Backup/0.77.6/`
and its overwritten co-op files under `_Backup/coop-before-0.84.3-session-followups/`.

## Previous 0.77.6 clean-install build: verified and activated

Executable SHA-256:
`72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743`.
The ordinary updater now activates this build as `verified_adapter`.

The adapter handles the 184-byte map records, moved name/boss fields, changed
Game members, and native map indexing/register changes. START has a reviewed
entry-only contract. Rewritten native instructions remain excluded from patch
mapping; ownership, native dependency checks, dispatch guards and source-bound
acceptance remain required. These reviewed layout exceptions require this exact
executable hash; unknown builds do not inherit its approval.

Validation on 2026-10-13:

- All 58 focused helper, boss-reward and runtime-mapping tests passed.
- Native entry/ownership, pause, progression, boss and damage observation passed.
- All nine four-player suites and all 18 required acceptance cases passed:
  combat, movement, shared XP/gold, independent talents/loot, bosses, pause,
  revival, saves/map progression, concurrent menus, host map, gear selection,
  departure/shutdown, keep fighting and new hero.
- The normal resolver activated the profile. Fresh resolver calls in both
  `to_git` and `AzerothSurvivors_Clean` returned `verified_adapter` without
  repeating compatibility tests. Copied Python files match the clean manifest.

The four-player runs used disposable saves in the development workspace.
`analysis/native-adapter-acceptance.json` records their results and evidence
locations; `analysis/active-hooks.json` binds acceptance to executable and source
hashes. The previous profile and pre-copy clean files are preserved. Historical
records below describe earlier builds and runs.

## Previous build: automatically verified and activated

The installed executable is now SHA-256
`bc6649e91f270bc424f8120955aa1de5a7f31b3ea909588ae34545d26928c548`.
It is **activated for co-op** after final fresh normal resolver run16672. No resulting
offsets were manually supplied and no new executable whitelist was introduced.
The dated failures below are historical checkpoints, superseded by this run.

All 84 required addresses, 63 typed fields and 35 patch preconditions passed
automatic static compilation and scoped native checks. All nine four-player
suites passed together against unchanged sources: 18 required acceptance cases,
including concurrent menus/host map, independent gear/talents/loot, all twelve
movement links, combat/bosses, XP/gold, revival/pause, saves/unlocks, guest and
host menu Quit, and both host-only victory choices. The full regression run
passed 329 tests, including relocation, ambiguity and incompatible-change
rejection; the subsequent publication fix passed all 24 discovery tests.

A fresh normal resolver launch revalidated the activated profile and reached
ready in 2.062 and 2.047 seconds on two consecutive launches without rerunning
discovery. Both left the previous verified profile byte-for-byte unchanged.
`analysis/final-cache-verification.json` records this check. The separate real X-button
test `window-close-tn8o43t7` passed: guest2 and host both produced native exit0,
the world advanced after guest2 left, and surviving guests received host departure.
Initial closing was slow. A read-only trace found the native main thread using
35.17 CPU seconds over 37.04 wall seconds during cleanup, with about 87.8 seconds
until it ended; the debugger was largely idle. An unmodified single-player
comparison exited in 0.703 seconds. A controlled four-player co-op comparison
with only `_NO_DEBUG_HEAP=1` added passed both X closures and measured host
shutdown at 0.939 seconds. The launcher now sets this documented Windows option
only in game child environments, retaining debugging and breakpoint checks.
Microsoft documents the debug-heap behavior and opt-out in
[The Old New Thing](https://devblogs.microsoft.com/oldnewthing/20130103-00/?p=5653)
and [debugger environment variables](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/general-environment-variables).
The final resolver run16672 passed all nine suites and 18 cases, superseding
the earlier activation only after verification completed. It preserved the
previous verified profile in `analysis/previous-verified-hooks.json`. A bug that
rotated backups when cached diagnostic metadata was omitted was corrected;
the final two real cache launches explicitly verified backup preservation.
Four-window visual boss checks were previously observed during run27732.

Evidence: `analysis/active-hooks.json` is the verified active profile;
`analysis/native-adapter-acceptance.json` lists all nine passing runs and all
18 cases. Its incremental journal status remains named `partial`; the final
activation decision is in the active profile. Each listed disposable directory
contains its logs and candidate snapshot. No report was edited to manufacture a pass.

These are local instrumented acceptance tests, with accelerated boss scenarios,
protective diagnostic health and native input diagnostics. They do not establish
WAN reliability, a full unassisted playthrough, or universal compatibility with
future semantic changes. Unmatched/ambiguous dependencies or failed native checks
still require investigation and remain inactive. Internet deployment is deferred
by the user. Unexpected native semantic changes, unsupported ownership/layout
changes, or ambiguous matches require manual reverse engineering; symbols/source
may help but are not available here. The paired baseline and retained acceptance
artifacts must remain available. This workspace is not a Git repository, so no
commit could be created. Original executable and personal saves were not edited
by these disposable tests.

### Earlier rerun42922: movement and corner layout verified; Quit input failed

The corrected startup-window selection placed all four real game windows at
their assigned corners: (0,0), (1444,0), (0,653), (1444,653), preserving the
1100x700 client viewport. Six layout regressions and ten shutdown tests passed.
Native run42922 passed pause/revival/combat, boss rewards and saved unlocks,
concurrent menus, mixed independent gear and the strict timed movement check
on all twelve directed links. Boss acceptance recorded 3,384 deliveries and
shared gold36. Native movement now demonstrably occurs during the gated key hold.

Menu departure failed: guest2 exited normally and the remaining world advanced,
but the host's single native Quit tap never produced a normal exit or began
saving. Guest3 also exited unexpectedly; its cause is unknown. The next fix
reuses the already verified held-touch handling for Quit and rejects extra
guest departures. The failed batch was stopped during economy; its interrupted
economy run is not acceptance. No profile was activated.

### Earlier rerun50864: eight suites passed; movement diagnostic corrected

Resolver50864 passed eight of nine required suites, including repaired ordered
shutdown, concurrent class selection, mixed independent equipment, native guest
and host menu Quit, shared economy, boss loot/unlock persistence and both victory
choices. Its movement test failed because the diagnostic W press finished before
all clients loaded. Earlier changing positions established relay behavior but
did not establish that the diagnostic press caused movement.

The revised diagnostic waits for all clients to load and enter the running phase;
acceptance now requires real displacement during its timed hold and matching poses
on all twelve directed links. Four-client tests also opt into verified corner
placement without resizing their viewports. All 325 regression tests passed.
Fresh resolver53153 passed scoped native checks but failed party startup because
window placement checked uniqueness before filtering temporary startup windows
by the configured viewport. That placement bug is being repaired; movement,
activation and X-button checks remain pending.

### Earlier rerun27732 failures (subsequently repaired)

Resolver27732 passed scoped native checks and boss rewards/save reloads. All four
boss windows visibly showed the model and matching HP bars at paused clock24;
pause was requested from one window and resumed from another. Boss acceptance
recorded 3,615 delivered updates, four victories and saved new unlocks for all four.
The pause/revival run delivered and acknowledged all 2,109 updates, but shutdown
still timed out: the host paused before a guest's final damage was settled,
while that guest waited for settlement before pausing. This ordering needs repair.
Class and mixed-gear tests each had one guest consume all 20 native Enter taps
without a corresponding menu command. The taps had correct coordinates and
host-map readiness; downstream native touch consumption remains under investigation.
The failed batch was stopped during the subsequent departure test; that interrupted
test is not acceptance. All owned game processes were confirmed closed.

The preceding full regression passed 310 tests. Fresh resolver run56346 passed
static/scoped native checks and boss rewards/save reloads, but exposed a shutdown
race and unreliable diagnostic Enter delivery. All pause/revival exercises and
all 2,001 world deliveries completed; the host had received only 1,974 final
acknowledgments when bounded cleanup began. Late resume requests could reopen
simulation during draining. The existing loop already polls networking
independently; polling starvation was investigated and ruled out as an explanation.

The class test loaded three correct classes into Duskwood, while the fourth
remained in the picker without a native Enter event. The mixed equipment test
also left guests in the picker. A longer startup delay is not justified by the
observations. Native tap delivery/readiness and acknowledgment need correction.
The failed batch and its waiting checker were ended, and their owned job
processes were confirmed closed. Its interrupted departure test is not evidence
of successful quitting. No compatibility profile was activated.

### What native acceptance establishes

These are instrumented, disposable native sessions over four real local TLS
peers. Tests accelerate encounters through verified native calls, use protective
player HP in boss tests, and drive menu/talent/pause actions. They check actual
native state, emitted messages, delivery, independent saves and process exits.
They are not an unassisted full-length playthrough or an Internet latency test.
Packet/model/HP evidence does not by itself establish pixel rendering; visual
checks are identified separately. Synthetic relocation/mutation tests complement
the installed-build tests and do not guarantee arbitrary future compatibility.

The original rejection came from the whole-image relocation proof: image size,
code, section layout and native object layouts changed. Five old masked hook
signatures still match; that alone cannot validate the adapter. Discovery now
runs inside the existing launch-time resolver using paired decoded instructions,
call references, typed data and native ownership observations. There is no new
executable whitelist or manually supplied candidate address set.

Verified so far on the installed executable:

- A fresh normal resolver invocation discovered bootstrap hooks and launched an
  isolated native process with a disposable save. Entry/HUD observations passed;
  unresolved gameplay dependencies still prevented activation.
- Field observation: 1,235 native batch writes matched the discovered connection,
  vector and frame layout; 46 Game operand sites passed ownership checks.
- A subsequent disposable run with a native talent choice reached combat and
  verified one changed DAMAGE pointer calculation; 47 operand sites were observed.
  Unobserved sites remain explicit; no global offset shift is inferred.
- A later single-process candidate-call test (`update-call-test-2.jsonl`)
  passed native PAUSE/RESUME returns, phase transitions and both serialized
  menu messages, then exited normally with code 0 after window closure.
  Executable and adapter source identity remained unchanged. Teardown was
  delayed; this does not establish four-player departure behavior.
- The isolated progression rerun (`update-progression-test-2.jsonl`) passed:
  native XP20 raised level1/XP0 to level3/XP6; two current native offer titles
  matched their UI choices; Battle Shout and Demoralizing Shout were added at
  rank1; pending talents decreased2→1→0 and native gameplay resumed. This was
  bounded cleanup, not another clean-quit test. The earlier run correctly
  rejected a stale repeated UI offer before its second choice.
- The isolated boss run (`update-boss-test.jsonl`) passed native pause/progression,
  including Cleave rank1→2, and discovered Hogger from the running Game's map.
  Native Enemy HP16974/model384 matched its CREATE packet and boss announcement;
  the model was also visually present. Native periodic HUD reported `hp`/`hpMax`.
  No manually supplied candidate addresses were used. Window closure was tried
  near the deadline, but bounded cleanup ran before a normal exit was recorded;
  this run is not clean-exit or multiplayer evidence.
- The isolated damage run (`update-damage-test.jsonl`) passed: the discovered
  boss started at HP16974, a native100-damage hit produced HP16874 and the
  matching world update, and a lethal hit produced native death, wireHP0,
  removal and `bossdown`. Boss kills increased0→1 and the native reward count
  increased0→2, without changing luck. Initial HUD `hp`/`hpMax` matched native
  floats. A persistent dispatch guard checked the actual source-tag load.
  This used bounded cleanup and does not establish shared combat or normal exit.
- `native-runtime-inputs.json` now inventories actual reviewed host/guest patch
  builders plus literal runtime dependencies and declared native fields. It
  contains87 requested addresses and explicit unresolved dynamic expressions;
  it is source-bound evidence for dependency coverage, never compatibility proof.
- Fresh normal resolver run32990 automatically discovered the current executable
  and passed its60-second native pause/progression/boss/damage test. It selected
  an actually offered Bloodrage talent so the guarded death path was exercised;
  source-tag0 was observed. Executable/source identity stayed unchanged. Evidence:
  `update-automatic-damage-verified-{events,result}.json`. The earlier87890 run
  produced damage/death but never hit that guard and correctly failed acceptance;
  its evidence is retained as `update-automatic-damage-first-{events,result}.json`.
  Both used bounded cleanup and neither establishes four-player acceptance.
- The typed profile compiler combines exact patch, field and address proofs and
  retains unresolved callees and caller conditions. Its isolated launch path
  requires complete static admission, source identity and disposable save folders;
  it cannot activate a candidate or run indefinitely. Full native acceptance
  remains required before activation.
- 233 offline tests passed at the recorded checkpoint. Later changes receive
  targeted checks and will require another full-suite run.

Evidence: `native-observation-result.json`, `native-observation-events.json`,
`update-field-observation.jsonl`, `update-pointer-observation.jsonl`,
`structural-hook-candidates.json`, and menu/helper/effect/enemy contract reports.
These observations do not establish four-player gameplay, save persistence or
party shutdown. Bounded process cleanup is not a successful quit test.

Still required: complete isolated four-player acceptance and atomic activation
after that acceptance. Static callable/interior/data ownership closure and
candidate adapter preparation now pass; earlier investigation notes above
describe the evidence that led there. Failed discovery preserves the last verified active profile;
the attempt report names unresolved dependencies. Arbitrary future semantic
changes cannot be guaranteed to resolve automatically.

## Previously reviewed build

The previous co-op port used the then-current root executable by default. Its reviewed
SHA-256 is `20d4ce5fb1232dac64bc00a4d8c9f2bcae43fb8373ea3fa95350ab8c4f20d618`.
The preserved legacy executable remains available through `COOP_BUILD=legacy`.
The updated port has passed native four-player and four-process loopback TLS
tests; consult `.agent/CONTINUITY.md` for feature-specific acceptance and failures.
These results do not establish compatibility with a future gameplay update.

## Automatic behavior

Before injection, the existing resolver checks executable identity and validates
the selected profile. Equivalent-runtime verification can automatically accept:

- The reviewed build, with every hook uniquely matching its reviewed RVA.
- Packaging-only changes, such as timestamps, checksum, or unmapped signing data.
- A coherent preferred-image-base change, where every Windows DIR64 loader
  relocation moves by the same base delta and all remaining mapped bytes match.
- Function-address moves whose complete code, references and mapped image pass
  the relocation proof described below; every native patch is translated too.

The canonical fingerprint retains code, object-field displacements, constants,
resources, data tables, imports, unwind information, relocation metadata,
section permissions and RVA layout. Only loader-equivalent base values and the
listed packaging fields are normalized. A changed pointer or gameplay byte
fails equivalence. Unsupported or overlapping loader relocations are rejected.

Changed runtimes enter structural dependency discovery, typed layout and calling
contract checks, followed by isolated native acceptance. A candidate is never
permission to inject into a personal game. Every required acceptance case and
every run must pass before activation; source and executable identities must
remain unchanged throughout. New failures retain their evidence and names.

The selected profile is written atomically to `analysis/active-hooks.json`.
An existing verified profile that differs from the new profile is preserved in
`analysis/previous-verified-hooks.json`; failure leaves the active file intact.
Every launch revalidates its executable and source binding, so retaining an old
profile does not authorize it for a changed executable. No original executable
is rewritten.

One workspace file lock covers discovery, test execution and publication.
Concurrent launchers wait, then validate the published result. A failed attempt
is shared only with callers already waiting for that same input identity;
a later explicit launch can retry. The offline patch inventory uses only a
validated reviewed snapshot and cannot publish a profile or launch a process.

## Changes requiring a verified adapter port

Unrecognized structure layouts, calling conventions or game logic remain blocked.
Supported changes can be derived and tested automatically. Matching function
prologues alone is insufficient: the adapter also contains interior patch
locations, machine-code jumps, stack offsets and data-table references. The
dependency inventory and typed contracts cover these consumers beyond the
named-hook list.

`analysis/updated-hook-discovery.json` retains unique, ambiguous and missing
instruction candidates. Relocation masking permits relative call/jump and
RIP-relative operands only; it keeps object-field offsets and other immediates.
`analysis/check_build_hooks.py --if-changed` additionally inventories embedded
code/data literals and compares legacy prefixes for reconstruction. Its cache
depends on both executable hashes, all adapter Python sources, the hook manifest
and scanner. Its nested `updated_runtime` result describes actual activation;
the legacy prefix report itself never authorizes injection.

`analysis/map_build_functions.py` remains an offline research aid. Its broad
matches may hide changed fields, so it reports `fixed_operands_match` separately
and never enables hooks. No amount of a few successful smoke tests proves every
new binary's layout or semantics. Universal self-porting across arbitrary future
game changes is **not implemented or guaranteed**.

The reviewed executable is preserved, with its original hash verified, under
`.coop-builds/<reviewed SHA-256>/AzerothSurvivors.exe`. Unsupported updates now
automatically produce `analysis/dependency-relocations.json` using that baseline.
The same check can be run manually with `map_build_functions.py --dependencies`.
It compares complete functions, maps interior patch locations only when instruction
lengths and fixed operands agree, and checks relative calls, branches and data
references against explicit mappings. Unmapped references remain unresolved;
matching the local instructions does not silently certify their dependencies.
The report includes both executable hashes. The source inventory is conservative
and includes literals in legacy branches; it is not a claim of complete coverage
of addresses encoded inside machine-code byte strings.

## Verified relocation profiles and runtime integration

`reconstruction/runtime_addresses.py` goes beyond candidates. Its candidate
profile validator reverses declared function moves, checks every changed caller,
implicit fallthrough edge, Windows loader pointer and exception-table entry, and
then requires the **entire** normalized mapped image to equal the reference.
This supports proven span permutations without section-layout or semantic changes.
Data moves additionally require reviewed complete-object extents; guessing a
short matching window could otherwise split an array. Unwind programs, imports,
resources, non-address instructions and unknown metadata remain exact.

`RuntimeAddresses(reference, candidate, moves)` performs that proof again against
fresh byte snapshots and exposes these explicit adapter operations:

- `rva(reviewed_rva)` translates current-reviewed addresses, including interior sites.
- `expected_bytes(reviewed_rva, expected)` verifies the old patch precondition and
  returns its proven candidate bytes, including updated relative operands.
- `pointer(image_base, reviewed_rva)` rebuilds generated absolute address operands.
- `relative_branch(source, target, opcode=..., size=...)` rebuilds generated rel32
  or rel8 branches from both translated endpoints; overflow requires a reviewed
  trampoline and never truncates a displacement.

`updated_layout.configure(runtime)` installs this map after profile verification.
Its existing `rva(legacy)` composes the legacy-to-reviewed mapping with runtime
translation. `reviewed_rva` is for explicit updated-build addresses;
`expected_bytes` / `reviewed_bytes` and `branch` / `reviewed_branch` provide the
corresponding guarded byte and generated-branch operations. Identity is the
default, so the reviewed build and explicit legacy mode retain their addresses.
The base visibility adapter now uses these operations for its generated native
addresses, damage-isolation sites and phase/pursuit/hazard preconditions.

The native adapter now enables resolver promotion through
`allow_runtime_relocation=True`. Its hook locations, patch preconditions, generated
branches and embedded native addresses use the verified translation helpers;
already-resolved hooks and pointers supplied by the running process are not
translated twice. Other resolver callers remain opt-in. The native adapter
revalidates the profile before configuration and checks the executable hash
before launching each client. A failed whole-image proof cannot be overridden by
this option. Arbitrary added functions, layout changes and new gameplay still
require a verified port.

## Verification

Runnable checks in `reconstruction/test_build_discovery.py` cover a coherent
rebase of the real reviewed executable, rejection of one altered rebased pointer,
packaging equivalence, changed mapped code, missing/ambiguous signatures,
changed object fields, cache invalidation and strict-versus-research matching.
Whole-function tests cover a moved function with relocated call/data targets,
missing dependency mappings, a wrong target and a changed structure field.
Real PE-format fixtures additionally verify moved functions and read-only pointer
tables, changed callers, loader sites, exception metadata, stale evidence hashes
and translated generated operands. The actual reviewed executable passes the
complete identity-profile proof. This is offline verification, not a native
game test of a fabricated moved executable.
The original executable remains unchanged during these tests.
`test_native_runtime_mapping.py` additionally runs the actual hook installation
and breakpoint-context emulation methods against a proven relocated PE fixture,
checking translated preconditions and the resumed instruction address. Generated
boss reward wrappers are CPU-tested with relocated native dependencies. These
checks do not constitute a live game test of a future build.

### Historical acceptance checkpoint (2026-10-13, 07:32 UTC)

The typed adapter compiler now resolves all 84 required addresses, 63 fields and
34 patch preconditions. This includes native effect dispatch and its bounded
runtime guard. Static completion alone cannot activate a profile.

The first automatic four-client run stopped at the connection ownership guard:
the native initial login serializer receives a stack-local connection before
that connection is published into the owned vector. The adapter now leaves
unowned serializer calls unchanged and keeps strict ownership checks for all
packet access. Live verification of this correction is pending.

The next scoped run rejected a multi-stat talent upgrade. Paired disassembly
shows that native rank increases once per selected stat tag; the displayed
next-rank title is not the resulting internal rank for multi-stat upgrades.
The test now checks the selected native vector and target ability and requires
the exact resulting ability dictionary. The rejection evidence is preserved in
`update-talent-mismatch-first-events.json` and its result file.

266 automated tests and 34 focused native-helper tests passed at this checkpoint.
A fresh normal resolver run is in progress. Four-player gameplay, clean party
exit and activation on the current executable remain unverified. The isolated
room loader and save staging test now use disposable candidate directories;
matching saved unlock tables alone will not count as newly awarded progression.

### Historical acceptance checkpoint (2026-10-13, 08:22 UTC)

Fresh normal resolver run 5622 independently rediscovered the installed build;
its scoped native call checks and four-player pause/revival suite passed.
`coop-lab/compatibility-tests/pause-revival-mwtzeq32` retains the evidence:
all eight pause/resume transitions, all four deaths and revivals, host plus
three guests attacking with authoritative HP changes and replicated attacks,
shared level/XP, and independent native talent spending. All four adapter
processes exited zero after the network drain fix. This bounded cleanup does
**not** establish clean native window/menu shutdown.

The same source-bound candidate passed a separate economy test in
`coop-lab/compatibility-tests/economy-diagnostic-c31tb3sb`: only player 4 paid
20 gold for the contested chest; the subsequent 48-gold credit reached every
player, preserving the personal chest deduction. No personal saves were used.

Movement acceptance rejected the native AUTOPLAY diagnostic: the clients did
not produce changing native movement packets. This is a failed input/test path,
not evidence that fabricated movement is acceptable. A real native input path
is being investigated. The boss test selected historical character names absent
from its fresh save and never entered gameplay; its setup now selects the native
fresh diagnostic Hero. Neither failure has been counted as a gameplay pass.

Current activation remains blocked. Bosses and loot, victory choices, real
movement, concurrent character/gear menus, host map enforcement, newly awarded
progression/save reload, and normal guest/host departures still require live
acceptance. Subsequent source changes invalidate prior acceptance automatically;
these retained runs are diagnostic evidence, not a shortcut to activation.


### Historical acceptance hardening checkpoint (2026-10-13, 09:25 UTC)

The latest completed full regression run passed 292 tests. Subsequent focused
checks cover the native input hold, gear observation, menu diagnostics and
verifier import-path correction. The Windows verifier job owns its process tree
before child imports, forces assertions on, and removes descendants on timeout.
Actual timeout cleanup and sibling-import regressions passed.

The previous native run verified shared gold after the startup-readiness fix:
all four players received 53 gold; only the chest opener paid 20. Its movement
input reached the native press and release paths but produced no changed
positions. A paired, live-checked two-second native key hold is now under test.
No generated movement packet can satisfy acceptance.

Boss and victory suites in that run were prevented from launching by a verifier
import-path error. That error is fixed and a fresh normal resolver run is in
progress. Concurrent native menus, nondefault gear selection, conflicting guest
map selection, native guest/menu/X departure and host shutdown remain pending.
A profile cannot activate with failed or missing runs or missing acceptance
cases. No current-build gameplay profile has been activated.

### Historical current-build boss/save milestone (run18714)

Fresh normal resolver run18714 passed `pause-revival-_nrhmvrf` and
`boss-rewards-2il7tfvh`. The latter verified four native victories, three
independent guest loot rolls,96shared gold,3633world deliveries, matching boss
model/attack inputs and changing authoritative HUD values. Every player's newly
earned Duskwood unlock survived two independent native picker reloads; original
reference saves were unchanged. A clear native screenshot showed the live Edwin
encounter, but all four rendered views have not been visually compared.

The same source-bound run is continuing with room menus, gear, native menu Quit,
movement, economy and victory-choice checks. No activation has occurred.


### Player metadata instead of a reference executable (2026-10-13)

The typed-adapter launch path now reads `reconstruction/reference-metadata.json`.
Its raw SHA-256 is pinned in runtime source and its contents join the source-bound
identity. This 2,534-byte file contains only reviewed x64 image bounds and exact
reference patch spans. Missing, modified, unknown or incomplete spans fail closed.
Current executable SHA, address/field/patch inventory, candidate patch bytes and
all 18 native acceptance requirements remain enforced. No sparse executable or
identity mapping fallback is constructed.

`dev_only/generate_reference_metadata.py` regenerates the file from the actual
hash-verified development reference and verifies each byte span. A changed pin or
source invalidates acceptance and requires normal revalidation. New-build discovery
and whole-image relocation analysis retain their real development reference;
player installations without it reject unsupported builds and request a verified
co-op update. Player bundles contain no game EXE, Data or archived reference EXE.

For a copied player installation, verify ordinary `native_probe` bootstrap without `.coop-builds`. The live test driver also accepts `--diagnostic-reference <development EXE>`: only its automated native-menu input comparison uses that external reference, with the existing hash and code checks. The reference is never copied into the player package.

Normal player launch must be exercised beyond import: run `dev_only/verify_player_launch.py <installed game folder>` using that folder's bundled Python. It starts an actual native process with disposable saves, installs verified hooks, and stops it, without candidate or diagnostic mode. Updated normal launches revalidate through the authoritative resolver; `check_build_hooks.py` remains a development-only legacy prefix audit and cannot authorize gameplay.
