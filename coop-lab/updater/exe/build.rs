// Embed an application manifest: run as the invoking user (no admin prompt,
// no installer detection) and with the Windows 10/11 compatibility id.
fn main() {
    println!("cargo:rerun-if-env-changed=COOP_UPDATE_ZIP");
    println!("cargo:rerun-if-env-changed=COOP_UPDATER_VERSION");
    println!("cargo:rerun-if-env-changed=COOP_UPDATER_TEST_KEY");
    if let Ok(zip) = std::env::var("COOP_UPDATE_ZIP") {
        println!("cargo:rerun-if-changed={zip}");
    }
    let out = std::env::var("OUT_DIR").unwrap();
    let manifest = std::path::Path::new(&out).join("coop-update.manifest");
    std::fs::write(&manifest, r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="AzerothSurvivorsTogether.CoopUpdate" version="0.0.11.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
</assembly>
"#).unwrap();
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
}
