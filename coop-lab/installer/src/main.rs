//! Azeroth Survivors Together web installer (no admin rights).
//!
//! Installs or updates the co-op game folder from the signed release:
//! 1. folder: --dir, a prompt, or %LOCALAPPDATA%\Azeroth Survivors Together;
//!    a folder that already holds an installation is updated instead (its own
//!    updater exe does that), never overwritten;
//! 2. at least 3 GiB free (downloads + temp);
//! 3. latest.json + latest.json.sig: the Ed25519 signature is checked here
//!    against the keys of the embedded reconstruction/self_update.py;
//! 4. the runtime archive named in it (GitHub; SHA-256 and size checked,
//!    interrupted downloads continue) is unpacked with Windows' tar.exe;
//! 5. the embedded updater (updater_v2.py on top of self_update.py and
//!    game_patch.py) installs everything else with that runtime: signed paths
//!    only, game files from the signed source list, SHA-256 checks, user areas
//!    untouched, resumable downloads;
//! 6. optional Start menu / desktop shortcut to Start-Coop.cmd.
//! Downloads use Windows' own curl.exe (System32, HTTPS only, at most 5 redirects).
//! Boot-log lines on the console and in <folder>\coop-update\install.log.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::time::Instant;

static SELF_UPDATE: &str = include_str!("../../../reconstruction/self_update.py");
static GAME_PATCH: &str = include_str!("../../updater/game_patch.py");
static UPDATER_V2: &str = include_str!("../../updater/updater_v2.py");
const RELEASE_URL: &str = "https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/";
const PRODUCT: &str = "azeroth-survivors-together";
const UPDATER_VERSION: &str = "4";
const UPDATER_ASSET: &str = "Azeroth-Survivors-Together-Updater.exe";
const NEEDED_SPACE: u64 = 3 << 30;
const RUNTIME_LIMIT: u64 = 512 << 20;
// Test builds only: an additional trusted key for signed test releases.
const TEST_KEY: Option<&str> = option_env!("COOP_INSTALLER_TEST_KEY");
static LOG: Mutex<Option<File>> = Mutex::new(None);

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    fn GetDiskFreeSpaceExW(dir: *const u16, free: *mut u64, total: *mut u64, total_free: *mut u64) -> i32;
}

fn log(tag: &str, text: &str) {
    let line = format!("[{:^6}] {}", tag, text);
    println!("{line}");
    let _ = io::stdout().flush();
    if let Some(file) = LOG.lock().unwrap().as_mut() {
        let _ = writeln!(file, "{line}");
    }
}

struct Step(&'static str, Instant);

fn step(name: &'static str) -> Step {
    log(" .... ", name);
    Step(name, Instant::now())
}

impl Step {
    fn ok(self, info: &str) {
        let seconds = self.1.elapsed().as_secs_f64();
        log("  OK  ", &format!("{} ({seconds:.1} s{}{})", self.0, if info.is_empty() { "" } else { ", " }, info));
    }
}

struct Options {
    dir: Option<PathBuf>,
    yes: bool,
    shortcuts: Option<bool>,
    release_url: String,
    allow_local_http: bool,
    no_pause: bool,
}

fn options() -> Result<Options, String> {
    let mut o = Options { dir: None, yes: false, shortcuts: None, release_url: RELEASE_URL.into(),
                          allow_local_http: false, no_pause: false };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => o.dir = Some(PathBuf::from(args.next().ok_or("--dir needs a folder")?)),
            "--yes" => o.yes = true,
            "--shortcuts" => o.shortcuts = Some(true),
            "--no-shortcuts" => o.shortcuts = Some(false),
            "--no-pause" => o.no_pause = true,
            // Diagnostics/tests, like the updater: another release address, local HTTP.
            "--release-url" => o.release_url = args.next().ok_or("--release-url needs an address")?,
            "--allow-local-http" => o.allow_local_http = true,
            "--help" | "-h" => {
                println!("Azeroth Survivors Together installer\n  --dir <folder>   install or update this folder\n  \
                          --yes            no questions (default folder, shortcuts as chosen)\n  \
                          --shortcuts / --no-shortcuts\n  --no-pause");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other} (--help lists them)")),
        }
    }
    if !o.release_url.ends_with('/') {
        o.release_url.push('/');
    }
    Ok(o)
}

/// A double-click gives this process its own console; a terminal shares its one.
fn own_console() -> bool {
    let mut list = [0u32; 4];
    unsafe { GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32) <= 1 }
}

fn finish(code: u8, no_pause: bool) -> ExitCode {
    if own_console() && !no_pause {
        print!("\nPress Enter to close this window . . . ");
        let _ = io::stdout().flush();
        let _ = io::stdin().lock().read_line(&mut String::new());
    }
    ExitCode::from(code)
}

fn ask(question: &str) -> String {
    print!("{question}");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    let _ = io::stdin().lock().read_line(&mut answer);
    answer.trim().to_string()
}

fn system32(tool: &str) -> PathBuf {
    let root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Path::new(&root).join("System32").join(tool)
}

fn free_space(dir: &Path) -> Option<u64> {
    let wide: Vec<u16> = dir.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free) };
    (ok != 0).then_some(free)
}

/// Download with Windows' curl.exe: HTTPS only (unless --allow-local-http), at most 5 redirects, resumable.
fn download(o: &Options, url: &str, target: &Path, resume: bool) -> Result<(), String> {
    let mut command = Command::new(system32("curl.exe"));
    command.args(["--fail", "--silent", "--show-error", "--location", "--max-redirs", "5", "--retry", "3",
                  "--retry-delay", "2", "--connect-timeout", "15", "--user-agent", "azsurvivors-installer/1"]);
    if !o.allow_local_http {
        command.args(["--proto", "=https", "--proto-redir", "=https"]);
    }
    if resume {
        command.args(["--continue-at", "-"]);
    }
    let status = command.arg("--output").arg(target).arg(url).status()
        .map_err(|e| format!("curl.exe could not be started ({e}); Windows 10 1803 or newer is needed"))?;
    if status.success() { Ok(()) } else { Err(format!("download of {url} failed (curl exit {:?})", status.code())) }
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The release keys of the embedded self_update.py (one source of truth), plus a test key in test builds.
fn trusted_keys() -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(start) = SELF_UPDATE.find("TRUSTED_KEYS = (") {
        let rest = &SELF_UPDATE[start + 16..];
        let end = rest.find(')').unwrap_or(0);
        keys.extend(rest[..end].split('\'').skip(1).step_by(2).map(str::to_string));
    }
    keys.extend(TEST_KEY.map(str::to_string));
    keys
}

fn verify(data: &[u8], signature: &[u8]) -> Option<String> {
    let signature = Signature::from_slice(signature).ok()?;
    trusted_keys().into_iter().find(|key| {
        base64::engine::general_purpose::STANDARD.decode(key).ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .and_then(|raw| VerifyingKey::from_bytes(&raw).ok())
            .is_some_and(|k| k.verify(data, &signature).is_ok())
    })
}

fn safe_asset(name: &str) -> bool {
    !name.is_empty() && name.len() <= 200 && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

fn is_installation(dir: &Path) -> bool {
    dir.join("package-manifest.json").is_file() && dir.join(".coop-runtime").join("python.exe").is_file()
}

/// Run the embedded updater with the folder's runtime (or a copy of it, like the updater exe).
fn run_updater(o: &Options, dir: &Path) -> Result<i32, String> {
    let work = dir.join("coop-update");
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    for (name, text) in [("self_update.py", SELF_UPDATE), ("game_patch.py", GAME_PATCH), ("updater_v2.py", UPDATER_V2)] {
        fs::write(work.join(name), text).map_err(|e| format!("cannot write {name}: {e}"))?;
    }
    let run = |python: &Path, runtime_free: bool| -> Result<i32, String> {
        let mut command = Command::new(python);
        command.args(["-I", "-B"]).arg(work.join("updater_v2.py"))
            .args(["--updater-version", UPDATER_VERSION, "--game"]).arg(dir)
            .args(["--release-url", &o.release_url]).current_dir(dir);
        if o.allow_local_http {
            command.arg("--allow-local-http");
        }
        if runtime_free {
            command.arg("--runtime-free");
        }
        if let Some(key) = TEST_KEY {
            command.args(["--extra-trusted-key", key]);
        }
        Ok(command.status().map_err(|e| format!("cannot start the co-op Python: {e}"))?.code().unwrap_or(1))
    };
    let mut code = run(&dir.join(".coop-runtime").join("python.exe"), false)?;
    if code == 5 {
        // The release changes the runtime this Python runs from: the script copied it, run from the copy.
        let copy = work.join("runtime");
        code = run(&copy.join("python.exe"), true)?;
        for _ in 0..20 {
            if fs::remove_dir_all(&copy).is_ok() || !copy.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    Ok(code)
}

fn shortcuts(dir: &Path) -> Result<(), String> {
    let quote = |p: &Path| p.display().to_string().replace('\'', "''");
    let target = quote(&dir.join("Start-Coop.cmd"));
    let icon = quote(&dir.join("AzerothSurvivors.exe"));
    let folder = quote(dir);
    let script = format!(
        "$w = New-Object -ComObject WScript.Shell; \
         $menu = Join-Path ([Environment]::GetFolderPath('Programs')) 'Azeroth Survivors Together.lnk'; \
         $desk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Azeroth Survivors Together.lnk'; \
         foreach ($p in @($menu, $desk)) {{ $s = $w.CreateShortcut($p); $s.TargetPath = '{target}'; \
         $s.WorkingDirectory = '{folder}'; $s.IconLocation = '{icon},0'; \
         $s.Description = 'Azeroth Survivors Together co-op'; $s.Save() }}");
    let status = Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .status().map_err(|e| e.to_string())?;
    if status.success() { Ok(()) } else { Err(format!("PowerShell exit {:?}", status.code())) }
}

fn install(o: &Options) -> Result<(), String> {
    let default = env::var("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Azeroth Survivors Together"))
        .map_err(|_| "LOCALAPPDATA is not set".to_string())?;
    let dir = match &o.dir {
        Some(dir) => dir.clone(),
        None if o.yes => default,
        None => {
            let answer = ask(&format!("Install folder [{}]: ", default.display()));
            if answer.is_empty() { default } else { PathBuf::from(answer.trim_matches('"')) }
        }
    };
    let dir = if dir.is_absolute() { dir } else { env::current_dir().map_err(|e| e.to_string())?.join(dir) };
    fs::create_dir_all(dir.join("coop-update")).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    *LOG.lock().unwrap() = OpenOptions::new().create(true).append(true).open(dir.join("coop-update").join("install.log")).ok();
    let existing = is_installation(&dir);
    log(" INFO ", &format!("Folder {} ({})", dir.display(),
                           if existing { "existing installation: update" } else { "new installation" }));

    if !existing {
        let s = step("Free disk space");
        let free = free_space(&dir).ok_or("cannot read the free disk space")?;
        if free < NEEDED_SPACE {
            return Err(format!("{:.1} GiB free on that drive, {:.1} GiB needed. Free some space or choose another folder.",
                               free as f64 / (1u64 << 30) as f64, NEEDED_SPACE as f64 / (1u64 << 30) as f64));
        }
        s.ok(&format!("{:.1} GiB free", free as f64 / (1u64 << 30) as f64));
    } else if dir.join(UPDATER_ASSET).is_file() {
        // An installation updates itself with its own updater exe (self-update, runtime copy, rollback).
        let s = step("Update with the installed updater");
        let mut command = Command::new(dir.join(UPDATER_ASSET));
        command.arg("--no-pause").args(["--release-url", &o.release_url]).current_dir(&dir);
        if o.allow_local_http {
            command.arg("--allow-local-http");
        }
        let status = command.status().map_err(|e| format!("cannot start {UPDATER_ASSET}: {e}"))?;
        if !status.success() {
            return Err(format!("the update failed (exit {:?}); the folder keeps its previous version", status.code()));
        }
        s.ok("done");
        return offer_shortcuts(o, &dir);
    }

    let work = dir.join("coop-update").join("install");
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let s = step("Read signed release description");
    download(o, &format!("{}latest.json", o.release_url), &work.join("latest.json"), false)?;
    download(o, &format!("{}latest.json.sig", o.release_url), &work.join("latest.json.sig"), false)?;
    let data = fs::read(work.join("latest.json")).map_err(|e| e.to_string())?;
    let signature = fs::read(work.join("latest.json.sig")).map_err(|e| e.to_string())?;
    if data.len() > 256 << 10 {
        return Err("latest.json is larger than allowed".into());
    }
    let key = verify(&data, &signature).ok_or("the release description is not signed by a trusted key; nothing was installed")?;
    let latest: serde_json::Value = serde_json::from_slice(&data).map_err(|e| format!("latest.json: {e}"))?;
    if latest["format"] != 1 || latest["product"] != PRODUCT {
        return Err("latest.json is not an Azeroth Survivors Together release description".into());
    }
    let version = latest["version"].as_str().unwrap_or("?").to_string();
    s.ok(&format!("co-op {version}, signed by {}...", &key[..12]));

    if !dir.join(".coop-runtime").join("python.exe").is_file() {
        let runtime = &latest["archives"]["runtime"];
        let (asset, digest, size) = (runtime["asset"].as_str().unwrap_or(""), runtime["sha256"].as_str().unwrap_or(""),
                                     runtime["size"].as_u64().unwrap_or(0));
        if !safe_asset(asset) || digest.len() != 64 || size == 0 || size > RUNTIME_LIMIT {
            return Err("latest.json lists an invalid runtime archive".into());
        }
        let s = step("Download the co-op runtime");
        let archive = work.join(asset);
        if !(archive.is_file() && sha256_file(&archive).ok().as_deref() == Some(digest)) {
            download(o, &format!("{}{asset}", o.release_url), &archive, true)?;
        }
        let got = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
        if got != size || sha256_file(&archive).map_err(|e| e.to_string())? != digest {
            let _ = fs::remove_file(&archive);
            return Err(format!("{asset} does not match its signed size/SHA-256 (removed); run the installer again"));
        }
        s.ok(&format!("{:.1} MiB, SHA-256 matches the release", size as f64 / (1u64 << 20) as f64));
        let s = step("Unpack the co-op runtime");
        let status = Command::new(system32("tar.exe")).arg("-xf").arg(&archive).arg("-C").arg(&dir).status()
            .map_err(|e| format!("tar.exe could not be started: {e}"))?;
        if !status.success() || !dir.join(".coop-runtime").join("python.exe").is_file() {
            return Err("unpacking the runtime failed".into());
        }
        s.ok("");
    }

    log(" INFO ", "Installing all files with the co-op updater (signed paths, SHA-256 checks)");
    let code = run_updater(o, &dir)?;
    if code != 0 {
        return Err(format!("the installation stopped (updater exit {code}); run the installer again to continue"));
    }
    offer_shortcuts(o, &dir)
}

fn offer_shortcuts(o: &Options, dir: &Path) -> Result<(), String> {
    let wanted = match o.shortcuts {
        Some(choice) => choice,
        None if o.yes => false,
        None => !ask("Create Start menu and desktop shortcuts? [Y/n]: ").to_lowercase().starts_with('n'),
    };
    if wanted {
        let s = step("Shortcuts");
        match shortcuts(dir) {
            Ok(()) => s.ok("Start menu and desktop"),
            Err(error) => log(" WARN ", &format!("Shortcuts: {error} (start Start-Coop.cmd in the folder instead)")),
        }
    }
    log("  OK  ", &format!("Azeroth Survivors Together is ready in {}. Start it with Start-Coop.cmd.", dir.display()));
    Ok(())
}

fn main() -> ExitCode {
    let o = match options() {
        Ok(o) => o,
        Err(error) => {
            log("FAILED", &error);
            return finish(2, false);
        }
    };
    log(" INFO ", "Azeroth Survivors Together installer (no admin rights needed)");
    match install(&o) {
        Ok(()) => finish(0, o.no_pause),
        Err(error) => {
            log("FAILED", &error);
            finish(2, o.no_pause)
        }
    }
}
