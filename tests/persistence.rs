mod common;

use std::{collections::BTreeMap, fs, path::Path};

use common::*;
use serde_json::Value;
use tangy_lib::{KeySource, TangyLib};

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "jwk") {
                return None;
            }
            Some((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(path).unwrap(),
            ))
        })
        .collect()
}

/// Assures: KEY-STORE-001
#[test]
fn generated_keys_are_persisted_and_stable_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let first = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    let before = snapshot(dir.path());
    assert_eq!(before.len(), 2);
    let mut ids = Vec::new();
    let mut recovery_id = None;
    for (file, bytes) in &before {
        let key = fixture_key(std::str::from_utf8(bytes).unwrap());
        let id = key.thumbprint().unwrap();
        assert_eq!(file, &format!("{id}.jwk"));
        key.to_p521_secret_key().unwrap();
        if key.alg.as_deref() == Some("ECMR") {
            recovery_id = Some(id.clone());
        }
        ids.push(id);
    }
    ids.sort();
    let request = vectors()[1]["request"].to_string();
    let response = first
        .rec(recovery_id.as_deref().unwrap(), &request)
        .unwrap();
    drop(first);
    let reopened = TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    assert_eq!(before, snapshot(dir.path()));
    let adv: Value = serde_json::from_str(&reopened.adv(None).unwrap()).unwrap();
    let mut advertised: Vec<_> = payload(&adv)["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| thumbprint(&k.to_string()))
        .collect();
    advertised.sort();
    assert_eq!(ids, advertised);
    assert_eq!(
        response,
        reopened
            .rec(recovery_id.as_deref().unwrap(), &request)
            .unwrap()
    );
}

/// Assures: KEY-LOAD-001, KEY-STORE-001
#[test]
fn invalid_existing_stores_fail_without_changing_files() {
    for files in [
        vec![("bad.jwk", "{")],
        vec![("sign.jwk", SIGNING)],
        vec![("rec.jwk", RECOVERY)],
        vec![
            ("sign.jwk", SIGNING),
            ("rec.jwk", RECOVERY),
            ("bad.jwk", "{"),
        ],
        vec![(
            "bad.jwk",
            r#"{"kty":"EC","crv":"P-521","x":"AA","y":"AA","alg":"unsupported"}"#,
        )],
    ] {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            fs::write(dir.path().join(name), content).unwrap();
        }
        let before = snapshot(dir.path());
        assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
        assert_eq!(before, snapshot(dir.path()));
    }
}

/// Assures: KEY-LOAD-001
#[test]
fn unreadable_key_entry_and_invalid_utf8_are_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("sign.jwk"), SIGNING).unwrap();
    fs::write(dir.path().join("rec.jwk"), RECOVERY).unwrap();
    // A directory cannot be read as a key file even when running as root.
    fs::create_dir(dir.path().join("unreadable.jwk")).unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("invalid.jwk"), [0xff, 0xfe]).unwrap();
    let before = snapshot(dir.path());
    assert!(TangyLib::init(KeySource::LocalDir(dir.path())).is_err());
    assert_eq!(before, snapshot(dir.path()));
}

/// Assures: KEY-LOAD-001
#[test]
fn nonexistent_directory_and_regular_file_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(&dir.path().join("missing"))).is_err());
    let path = dir.path().join("file");
    fs::write(&path, "").unwrap();
    assert!(TangyLib::init(KeySource::LocalDir(&path)).is_err());
}

/// Assures: KEY-PERM-001
#[cfg(unix)]
#[test]
fn generated_key_files_are_read_only_for_owner_and_group() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    let modes: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "jwk")
        })
        .map(|entry| entry.unwrap().metadata().unwrap().permissions().mode() & 0o777)
        .collect();
    assert_eq!(modes, [0o440, 0o440]);
}

/// Assures: KEY-PUBLISH-001, ERR-DIAG-001
#[cfg(unix)]
#[test]
fn read_only_empty_store_reports_the_create_failure_and_stays_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    use tangy_lib::{Error, WriteStep};
    // Root ignores directory permissions, so this failure cannot occur there.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), "not a key").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = TangyLib::init(KeySource::LocalDir(dir.path()));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        result,
        Err(Error::KeyWrite {
            operation: WriteStep::Create,
            ref path,
            ref source,
        }) if path.parent() == Some(dir.path())
            && source.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

/// Assures: KEY-PATH-001
#[test]
fn non_file_key_entries_are_rejected() {
    use tangy_lib::Error;
    for name in ["bad.jwk", ".bad.jwk"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::create_dir(&path).unwrap();
        assert!(
            matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::NotAFile { path: actual }) if actual == path)
        );
    }
}

/// Assures: KEY-PATH-001, KEY-STORE-001
#[cfg(unix)]
#[test]
fn symlinked_roots_and_keys_are_followed_like_tang() {
    use std::os::unix::fs::symlink;
    use tangy_lib::Error;
    let advertised = |lib: &TangyLib| {
        let adv: Value = serde_json::from_str(&lib.adv(None).unwrap()).unwrap();
        payload(&adv)["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| thumbprint(&key.to_string()))
            .collect::<std::collections::BTreeSet<_>>()
    };

    // A symlinked root, including spellings that resolve through the link.
    let parent = tempfile::tempdir().unwrap();
    let real = parent.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = parent.path().join("link");
    symlink(&real, &link).unwrap();
    let generated = advertised(&TangyLib::init(KeySource::LocalDir(&link)).unwrap());
    assert_eq!(snapshot(&real).len(), 2);
    for root in [link.join("."), format!("{}/", link.display()).into()] {
        assert_eq!(
            advertised(&TangyLib::init(KeySource::LocalDir(&root)).unwrap()),
            generated
        );
    }

    // A Kubernetes Secret volume: every key is a symlink through `..data`.
    let mount = tempfile::tempdir().unwrap();
    let version = mount.path().join("..2026_10_10");
    fs::create_dir(&version).unwrap();
    fs::write(version.join("sign.jwk"), SIGNING).unwrap();
    fs::write(version.join("rec.jwk"), RECOVERY).unwrap();
    fs::write(version.join(".old.jwk"), SECOND_SIGNING).unwrap();
    symlink("..2026_10_10", mount.path().join("..data")).unwrap();
    for name in ["sign.jwk", "rec.jwk", ".old.jwk"] {
        symlink(format!("..data/{name}"), mount.path().join(name)).unwrap();
    }
    let mounted = TangyLib::init(KeySource::LocalDir(mount.path())).unwrap();
    assert_eq!(
        advertised(&mounted),
        [thumbprint(SIGNING), thumbprint(RECOVERY)]
            .into_iter()
            .collect()
    );
    mounted.adv(Some(&thumbprint(SECOND_SIGNING))).unwrap();

    // Dangling key links fail to read rather than being skipped; links to
    // directories and FIFOs fail before opening or blocking.
    let dir = tempfile::tempdir().unwrap();
    let dangling = dir.path().join("dangling.jwk");
    symlink(parent.path().join("missing"), &dangling).unwrap();
    assert!(
        matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::KeyRead { path, .. }) if path == dangling)
    );
    let dir = tempfile::tempdir().unwrap();
    let to_directory = dir.path().join("directory.jwk");
    symlink(&real, &to_directory).unwrap();
    assert!(
        matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::NotAFile { path }) if path == to_directory)
    );
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo.jwk");
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(
        matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::NotAFile { path }) if path == fifo)
    );
}

/// Assures: KEY-PATH-001
#[cfg(windows)]
#[test]
fn windows_junctions_are_followed_like_symlinks() {
    use std::process::Command;
    use tangy_lib::Error;
    let junction = |link: &Path, target: &Path| {
        assert!(Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .unwrap()
            .success());
    };
    let parent = tempfile::tempdir().unwrap();
    let real = parent.path().join("real");
    fs::create_dir(&real).unwrap();
    let root = parent.path().join("root");
    junction(&root, &real);
    TangyLib::init(KeySource::LocalDir(&root)).unwrap();
    assert_eq!(snapshot(&real).len(), 2);
    TangyLib::init(KeySource::LocalDir(&root)).unwrap();
    fs::remove_dir(root).unwrap();

    // A key junction resolves to a directory, which is not a key file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.jwk");
    junction(&path, &real);
    assert!(
        matches!(TangyLib::init(KeySource::LocalDir(dir.path())), Err(Error::NotAFile { path: actual }) if actual == path)
    );
    fs::remove_dir(path).unwrap();
}

/// Assures: KEY-PERM-WINDOWS-001
#[cfg(windows)]
#[test]
fn windows_generated_keys_inherit_the_secured_directory_acl() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let powershell = |script: &str| {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            // Cargo/nextest can inherit PowerShell 7's module paths from CI.
            // Let Windows PowerShell rebuild its own paths so Set-Acl/Get-Acl
            // load the compatible Microsoft.PowerShell.Security module.
            .env_remove("PSModulePath")
            .env("TANGY_ACL_TEST_DIR", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $env:TANGY_ACL_TEST_DIR -AclObject $acl
    "#,
    );
    TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    powershell(
        r#"
        $ErrorActionPreference = 'Stop'
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $keys = @(Get-ChildItem -LiteralPath $env:TANGY_ACL_TEST_DIR -Filter '*.jwk')
        if ($keys.Count -ne 2) { throw 'Expected two keys' }
        foreach ($key in $keys) {
            $acl = Get-Acl -LiteralPath $key.FullName
            if ($acl.AreAccessRulesProtected) { throw 'Key inheritance disabled' }
            $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
            if ($rules.Count -ne 1) { throw 'Unexpected ACL entries' }
            if (-not $rules[0].IsInherited -or $rules[0].IdentityReference.Value -ne $sid -or $rules[0].FileSystemRights -ne 'FullControl') { throw 'Key did not inherit secured directory ACL' }
        }
    "#,
    );
}

/// Assures: KEY-STORE-001
#[test]
fn unrelated_files_are_preserved_when_an_empty_store_generates() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), "not a key").unwrap();
    fs::write(dir.path().join("ignored.JWK"), "not a key").unwrap();
    fs::write(dir.path().join(".tangy-interrupted.tmp"), "partial").unwrap();
    TangyLib::init(KeySource::LocalDir(dir.path())).unwrap();
    assert_eq!(snapshot(dir.path()).len(), 2);
    assert_eq!(
        fs::read_to_string(dir.path().join("notes.txt")).unwrap(),
        "not a key"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("ignored.JWK")).unwrap(),
        "not a key"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(".tangy-interrupted.tmp")).unwrap(),
        "partial"
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
}
