#![allow(dead_code)]
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use nt_hive2::{Hive, HiveParseMode, RegistryValue, SubPath};
use walkdir::WalkDir;

const FORMAT_DATE: &str = "%Y-%m-%d %H:%M:%S%.3f";

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct Persistence {
    timestamp: String,
    technique: String,
    classification: String,
    path: String,
    value: String,
    access_gained: String,
    reference: String,
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Clone, ValueEnum, Debug)]
enum Action {
    All,
    GetRun,
    GetRunOnce,
    GetRunEx,
    GetRunOnceEx,
    GetImageFileExecutionOptions,
    GetNldpDllOverridePath,
    GetAedebug,
    GetWerFaultHangs,
    GetCmdAutorun,
    GetExplorerLoad,
    GetWinlogonUserinit,
    GetWinlogonShell,
    GetTerminalProfileStartOnUserLogin,
    GetAppCertDlls,
    GetAppPaths,
    GetServiceDlls,
    GetGpExtensionDlls,
    GetWinlogonMpNotify,
    GetChmHelperDll,
    GetStartupPrograms,
    GetScheduledTasks,
    GetWindowsServices,
    GetUserInitMprScript,
    GetHhCtrlHijacking,
    GetAppInitDlls,
    GetLsaPackages,
    GetBootExecute,
    GetActiveSetup,
    GetScreensaver,
    GetSilentProcessExit,
    GetComHijacking,
}

#[derive(Parser, Debug)]
#[command(name = "boromir", version = "0.1", about = "Extract artifacts related with persistence")]
struct Args {
    /// Directory where the Windows machine was mounted
    #[arg(long)]
    source_evidence: Option<PathBuf>,

    /// Output CSV file path prefix
    #[arg(long)]
    csv_output: Option<PathBuf>,

    /// Action to perform
    action: Action,
}

// ─── Hive helpers ────────────────────────────────────────────────────────────

type HiveFile = Hive<BufReader<File>, nt_hive2::CleanHive>;

fn open_hive(path: &Path) -> Option<HiveFile> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    Hive::new(reader, HiveParseMode::NormalWithBaseBlock).ok()
}

fn fmt_ts(dt: &chrono::DateTime<Utc>) -> String {
    dt.format(FORMAT_DATE).to_string()
}

/// Try to navigate to `key_path` in the hive at `hive_path`.
/// Calls `f(key_node, &mut hive)` if found.
/// Returns Vec<Persistence> collected by `f`.
macro_rules! with_key {
    ($hive_path:expr, $key_path:expr, |$key:ident, $hive:ident| $body:expr) => {{
        let mut result: Vec<Persistence> = Vec::new();
        if let Some(mut $hive) = open_hive($hive_path) {
            if let Ok(root) = $hive.root_key_node() {
                if let Ok(Some(key_rc)) = root.subpath($key_path, &mut $hive) {
                    let $key = key_rc.borrow();
                    result.extend($body);
                }
            }
        }
        result
    }};
}

fn get_hives(source: &Path) -> Vec<PathBuf> {
    println!("+ Getting hives...");
    let system_hive_names = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
    let mut hives = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if system_hive_names.iter().any(|h| *h == name.as_str())
            || name.starts_with("NTUSER")
        {
            println!("\t{}", path.display());
            hives.push(path.to_path_buf());
        }
    }

    if hives.is_empty() {
        println!("No registry hives found.");
    }
    hives
}

// ─── Techniques ──────────────────────────────────────────────────────────────

fn run_key_entries(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)], // (path, access_gained)
    technique: &str,
    classification: &str,
    reference: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                key.values()
                    .iter()
                    .filter_map(|v| match v.value() {
                        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) => {
                            println!("\t{s}");
                            Some(Persistence {
                                timestamp: ts.clone(),
                                path: hive_path.to_string_lossy().to_string(),
                                access_gained: access.to_string(),
                                technique: technique.to_string(),
                                classification: classification.to_string(),
                                reference: reference.to_string(),
                                value: s.clone(),
                            })
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_run(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Run Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User"),
            (r"Microsoft\Windows\CurrentVersion\Run", "System"),
        ],
        "Registry Run Key",
        "MITRE ATT&CK T1547.001",
        "https://attack.mitre.org/techniques/T1547/001/",
    )
}

fn get_runonce(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunOnce Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunOnce", "System"),
        ],
        "Registry RunOnce Key",
        "MITRE ATT&CK T1547.001",
        "https://attack.mitre.org/techniques/T1547/001/",
    )
}

fn get_runex(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunEx Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunEx", "System"),
        ],
        "Registry RunEx Key",
        "MITRE ATT&CK T1547.001",
        "https://attack.mitre.org/techniques/T1547/001/",
    )
}

fn get_runonceex(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunOnceEx Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunOnceEx", "System"),
        ],
        "Registry RunOnceEx Key",
        "MITRE ATT&CK T1547.001",
        "https://attack.mitre.org/techniques/T1547/001/",
    )
}

fn get_image_file_execution_options(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Image File Execution Options");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for image_rc in subkeys.iter() {
                        let image = image_rc.borrow();
                        let ts = fmt_ts(image.timestamp());
                        for v in image.values() {
                            if v.name() == "Debugger" {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    println!("\t{s}");
                                    entries.push(Persistence {
                                        timestamp: ts.clone(),
                                        path: s.clone(),
                                        access_gained: "System/User".to_string(),
                                        technique: "Image file execution options".to_string(),
                                        classification: "MITRE ATT&CK T1546.012".to_string(),
                                        reference: "https://attack.mitre.org/techniques/T1546/012/".to_string(),
                                        value: s.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_nldp_dll_override_path(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Natural Language Development Platform DLL path override properties.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            // Read current control set number
            let current: u32 = if let Ok(Some(sel_rc)) = root.subpath("Select", &mut hive) {
                sel_rc
                    .borrow()
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("Current"))
                    .and_then(|v| {
                        if let RegistryValue::RegDWord(n) = v.value() {
                            Some(*n)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(1)
            } else {
                continue;
            };

            let lang_path = format!(r"ControlSet{current:03}\Control\ContentIndex\Language");
            let Ok(Some(langs_rc)) = root.subpath(lang_path.as_str(), &mut hive) else {
                continue;
            };
            let langs = langs_rc.borrow();
            let Ok(subkeys) = langs.subkeys(&mut hive) else { continue };
            for lang_rc in subkeys.iter() {
                let lang = lang_rc.borrow();
                let ts = fmt_ts(lang.timestamp());
                let stemmer = lang
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("StemmerDLLPathOverride"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                let wb = lang
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("WBDLLPathOverride"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                if stemmer.is_some() || wb.is_some() {
                    let val = wb.clone().unwrap_or_default();
                    println!("\t{val}");
                    result.push(Persistence {
                        timestamp: ts,
                        path: stemmer.unwrap_or_default(),
                        access_gained: String::new(),
                        technique: "Natural Language Development Platform 6 DLL Override Path"
                            .to_string(),
                        classification: "Hexacorn Technique N.98".to_string(),
                        reference: "https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/".to_string(),
                        value: val,
                    });
                }
            }
        }
    }
    result
}

fn aedebug_entries(hives: &[PathBuf], key_path: &str) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, key_path, |key, hive| {
            let mut entries = Vec::new();
            if let Ok(subkeys) = key.subkeys(&mut hive) {
                for sub_rc in subkeys.iter() {
                    let sub = sub_rc.borrow();
                    let ts = fmt_ts(sub.timestamp());
                    for v in sub.values() {
                        let path_str = format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: path_str,
                            access_gained: "System".to_string(),
                            technique: "AEDebug Custom Debugger".to_string(),
                            classification: "Hexacorn Technique N.4".to_string(),
                            reference: "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4".to_string(),
                            value: "AeDebug".to_string(),
                        });
                    }
                }
            }
            entries
        }));
    }
    result
}

fn get_aedebug(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AeDebug properties.");
    let mut result = Vec::new();
    result.extend(aedebug_entries(
        hives,
        r"Microsoft\Windows NT\CurrentVersion\AeDebug",
    ));
    result.extend(aedebug_entries(
        hives,
        r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug",
    ));
    result
}

fn werfault_entries(hives: &[PathBuf], key_path: &str) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, key_path, |key, hive| {
            let mut entries = Vec::new();
            if let Ok(subkeys) = key.subkeys(&mut hive) {
                for sub_rc in subkeys.iter() {
                    let sub = sub_rc.borrow();
                    let ts = fmt_ts(sub.timestamp());
                    for v in sub.values() {
                        let path_str = format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: path_str,
                            access_gained: "System".to_string(),
                            technique: "Windows Error Reporting Debugger".to_string(),
                            classification: "Hexacorn Technique N.116".to_string(),
                            reference: "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/".to_string(),
                            value: "werfaultDebuggger".to_string(),
                        });
                    }
                }
            }
            entries
        }));
    }
    result
}

fn get_wer_fault_hangs(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting WerFault Hangs registry key Debug property.");
    let mut result = Vec::new();
    result.extend(werfault_entries(
        hives,
        r"Microsoft\Windows\Windows Error Reporting\Hangs",
    ));
    result.extend(werfault_entries(
        hives,
        r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs",
    ));
    result
}

fn get_cmd_autorun(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Command Processor's AutoRun property.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"Software\Microsoft\Command Processor", "User"),
            (r"Microsoft\Command Processor", "User"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case("Autorun"))
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            let path_str = format!("Name: {s}");
                            println!("\t{path_str}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: path_str,
                                access_gained: access.to_string(),
                                technique: "Command Processor AutoRun key".to_string(),
                                classification: "Uncatalogued Technique N.1".to_string(),
                                reference: "https://persistence-info.github.io/Data/cmdautorun.html".to_string(),
                                value: "CmdAutoRun".to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn single_value_key(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)],
    value_name: &str,
    technique: &str,
    classification: &str,
    reference: &str,
    persistence_value: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case(value_name))
                    .map(|v| {
                        let path_str =
                            format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: access.to_string(),
                            technique: technique.to_string(),
                            classification: classification.to_string(),
                            reference: reference.to_string(),
                            value: persistence_value.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_explorer_load(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Explorer's Load property.");
    single_value_key(
        hives,
        &[
            (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Windows", "System"),
        ],
        "Load",
        "Explorer Load Property",
        "Uncatalogued Technique N.2",
        "https://persistence-info.github.io/Data/windowsload.html",
        "ExplorerLoad",
    )
}

fn get_winlogon_userinit(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Userinit property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "Userinit",
        "Winlogon Userinit Property",
        "MITRE ATT&CK T1547.004",
        "https://attack.mitre.org/techniques/T1547/004/",
        "WinLogonUserInit",
    )
}

fn get_winlogon_shell(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Shell property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "Shell",
        "Winlogon shell Property",
        "MITRE ATT&CK T1547.004",
        "https://attack.mitre.org/techniques/T1547/004/",
        "WinLogonShell",
    )
}

fn get_terminal_profile_start_on_user_login(settings_files: &[PathBuf]) -> Vec<Persistence> {
    println!(
        "+ Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value."
    );
    let mut result = Vec::new();
    for file in settings_files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        let Ok(data): Result<serde_json::Value, _> = serde_json::from_str(&content) else {
            continue;
        };
        let profiles = &data["profiles"];
        let list = if profiles.is_object() {
            profiles["list"].as_array().cloned().unwrap_or_default()
        } else if profiles.is_array() {
            profiles.as_array().cloned().unwrap_or_default()
        } else {
            continue;
        };
        for profile in &list {
            if profile.get("startOnUserLogin") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let commandline = profile
                .get("commandline")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
                .to_string();
            let ts = file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)?;
                    chrono::DateTime::from_timestamp(secs, 0)
                })
                .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                .unwrap_or_default();
            println!("\t{commandline}");
            result.push(Persistence {
                timestamp: ts,
                path: file.to_string_lossy().to_string(),
                access_gained: "User".to_string(),
                technique: "Windows Terminal startOnUserLogin".to_string(),
                classification: "Uncatalogued Technique N.3".to_string(),
                reference: "https://twitter.com/nas_bench/status/1550836225652686848".to_string(),
                value: commandline,
            });
        }
    }
    result
}

fn all_values_key(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)],
    technique: &str,
    classification: &str,
    reference: &str,
    persistence_value: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .map(|v| {
                        let path_str =
                            format!("{} {}", v.name(), v.value());
                        println!("\t{path_str}");
                        Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: access.to_string(),
                            technique: technique.to_string(),
                            classification: classification.to_string(),
                            reference: reference.to_string(),
                            value: persistence_value.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_app_cert_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AppCertDlls properties.");
    all_values_key(
        hives,
        &[
            (r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls", "User"),
            (r"CurrentControlSet\Control\Session Manager\AppCertDlls", "System"),
        ],
        "AppCertDlls properties.",
        "MITRE ATT&CK T1546.009",
        "https://attack.mitre.org/techniques/T1546/009/",
        "AppCertDlls",
    )
}

fn get_app_paths(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting App Paths inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "User"),
            (r"Microsoft\Windows\CurrentVersion\App Paths", "System"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(apps) = key.subkeys(&mut hive) {
                    for app_rc in apps.iter() {
                        let app = app_rc.borrow();
                        let exe_path = app
                            .values()
                            .iter()
                            .find(|v| v.name().is_empty() || v.name() == "(default)")
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            });
                        if let Some(path_str) = exe_path {
                            println!("\t{path_str}");
                            entries.push(Persistence {
                                timestamp: fmt_ts(app.timestamp()),
                                path: path_str,
                                access_gained: access.to_string(),
                                technique: "App Paths".to_string(),
                                classification: "Hexacorn Technique N.3".to_string(),
                                reference: "https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/".to_string(),
                                value: app.name().to_string(),
                            });
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_service_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Service DLLs inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let services_path = format!(r"ControlSet{current:03}\Services");
            let Ok(Some(services_rc)) = root.subpath(services_path.as_str(), &mut hive) else {
                continue;
            };
            let services = services_rc.borrow();
            let Ok(service_keys) = services.subkeys(&mut hive) else { continue };
            for svc_rc in service_keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                let dll = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("ServiceDll"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });

                // Also check Parameters subkey
                let params_dll = if let Ok(params) = svc.subkeys(&mut hive) {
                    params
                        .iter()
                        .find(|k| k.borrow().name().eq_ignore_ascii_case("Parameters"))
                        .and_then(|p_rc| {
                            p_rc.borrow()
                                .values()
                                .iter()
                                .find(|v| v.name().eq_ignore_ascii_case("ServiceDll"))
                                .and_then(|v| {
                                    if let RegistryValue::RegSZ(s)
                                    | RegistryValue::RegExpandSZ(s) = v.value()
                                    {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                        })
                } else {
                    None
                };

                let dll_path = params_dll.or(dll);
                if let Some(d) = dll_path {
                    println!("\t{d}");
                    result.push(Persistence {
                        timestamp: ts,
                        path: d.clone(),
                        access_gained: "System".to_string(),
                        technique: "ServiceDll Hijacking".to_string(),
                        classification: "Hexacorn Technique N.4".to_string(),
                        reference: "https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/".to_string(),
                        value: "ServiceDlls".to_string(),
                    });
                }
            }
        }
    }
    result
}

fn get_gp_extension_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Group Policy Extension DLLs inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "User"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "System"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for ext_rc in subkeys.iter() {
                        let ext = ext_rc.borrow();
                        let ts = fmt_ts(ext.timestamp());
                        for v in ext.values() {
                            if v.name().eq_ignore_ascii_case("DllName") {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    println!("\t{s}");
                                    entries.push(Persistence {
                                        timestamp: ts.clone(),
                                        path: s.clone(),
                                        access_gained: access.to_string(),
                                        technique: "Group Policy Extension DLL".to_string(),
                                        classification: "Uncatalogued Technique N.4".to_string(),
                                        reference: "https://persistence-info.github.io/Data/gpoextension.html".to_string(),
                                        value: "Group Policy Extension DLL".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_winlogon_mpnotify(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon MPNotify property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "User"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "mpnotify",
        "MPNotify",
        "Uncatalogued Technique N.5",
        "https://persistence-info.github.io/Data/mpnotify.html",
        "MPNotify",
    )
}

fn get_chm_helper_dll(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting CHM Helper DLL inside the registry.");
    all_values_key(
        hives,
        &[
            (r"Software\Microsoft\HtmlHelp Author", "User"),
            (r"Microsoft\HtmlHelp Author", "System"),
        ],
        "CHMHelperDll",
        "CHM Helper DLL",
        "https://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/",
        "CHMHelperDll",
    )
}

fn get_startup_programs(startup_files: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking if users' Startup folder contains interesting artifacts.");
    startup_files
        .iter()
        .map(|program| {
            let ts = program
                .metadata()
                .ok()
                .and_then(|m| m.created().ok())
                .and_then(|t| {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)?;
                    chrono::DateTime::from_timestamp(secs, 0)
                })
                .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                .unwrap_or_default();
            println!("\t{}", program.display());
            Persistence {
                timestamp: ts,
                path: program.to_string_lossy().to_string(),
                access_gained: "User".to_string(),
                technique: "Startup Folder".to_string(),
                classification: "MITRE ATT&CK T1547.001".to_string(),
                reference: "https://attack.mitre.org/techniques/T1547/001/".to_string(),
                value: "Startup Folder".to_string(),
            }
        })
        .collect()
}

fn get_scheduled_tasks(hives: &[PathBuf], source_evidence: Option<&Path>) -> Vec<Persistence> {
    println!("+ Getting scheduled tasks.");
    let mut result = Vec::new();

    // Registry
    for hive_path in hives {
        for (key_path, access) in &[
            (r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "System"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "User"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(tasks) = key.subkeys(&mut hive) {
                    for task_rc in tasks.iter() {
                        let task = task_rc.borrow();
                        let ts = fmt_ts(task.timestamp());
                        if let Some(path_val) = task
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("Path"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            })
                        {
                            println!("\t{path_val}");
                            entries.push(Persistence {
                                timestamp: ts,
                                path: path_val,
                                access_gained: access.to_string(),
                                technique: "Scheduled Task".to_string(),
                                classification: "MITRE ATT&CK T1053.005".to_string(),
                                reference: "https://attack.mitre.org/techniques/T1053/005/".to_string(),
                                value: "Scheduled Task".to_string(),
                            });
                        }
                    }
                }
                entries
            }));
        }
    }

    // XML files on filesystem — walk recursively, collect files inside any "Tasks" directory
    if let Some(source) = source_evidence {
        for entry in WalkDir::new(source).into_iter().flatten() {
            let path = entry.path();
            let in_tasks = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Tasks"))
                .unwrap_or(false);
            if !path.is_file() || !in_tasks {
                continue;
            }
            {
                let path = path;
                let Ok(content) = std::fs::read_to_string(path) else {
                    continue;
                };
                let Ok(doc) = roxmltree::Document::parse(&content) else {
                    continue;
                };
                let ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
                let command = doc
                    .descendants()
                    .find(|n| n.has_tag_name((ns, "Command")))
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if command.is_empty() {
                    continue;
                }
                let args = doc
                    .descendants()
                    .find(|n| n.has_tag_name((ns, "Arguments")))
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let full_cmd = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{command} {args}")
                };
                let ts = path
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| {
                        let secs = t
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs() as i64)?;
                        chrono::DateTime::from_timestamp(secs, 0)
                    })
                    .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                    .unwrap_or_default();
                println!("\t{full_cmd}");
                result.push(Persistence {
                    timestamp: ts,
                    path: path.to_string_lossy().to_string(),
                    access_gained: "System".to_string(),
                    technique: "Scheduled Task (XML)".to_string(),
                    classification: "MITRE ATT&CK T1053.005".to_string(),
                    reference: "https://attack.mitre.org/techniques/T1053/005/".to_string(),
                    value: full_cmd,
                });
            }
        }
    }
    result
}

fn get_windows_services(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking Windows Services.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let services_path = format!(r"ControlSet{current:03}\Services");
            let Ok(Some(services_rc)) = root.subpath(services_path.as_str(), &mut hive) else {
                continue;
            };
            let services = services_rc.borrow();
            let Ok(service_keys) = services.subkeys(&mut hive) else { continue };
            for svc_rc in service_keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                let image_path = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("ImagePath"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                let has_service_dll = svc
                    .values()
                    .iter()
                    .any(|v| v.name().eq_ignore_ascii_case("ServiceDll"));
                let display_name = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("DisplayName"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                if !has_service_dll {
                    if let Some(img) = image_path {
                        println!("\t{img}");
                        result.push(Persistence {
                            timestamp: ts,
                            path: img,
                            access_gained: "System".to_string(),
                            technique: "Windows Service".to_string(),
                            classification: "MITRE ATT&CK T1543.003".to_string(),
                            reference: "https://attack.mitre.org/techniques/T1543/003/".to_string(),
                            value: display_name,
                        });
                    }
                }
            }
        }
    }
    result
}

fn get_user_init_mpr_script(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting users' UserInitMprLogonScript property.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, "Environment", |key, _hive| {
            key.values()
                .iter()
                .filter(|v| v.name().eq_ignore_ascii_case("UserInitMprLogonScript"))
                .filter_map(|v| {
                    if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                        let path_str = format!("{} {s}", v.name());
                        println!("\t{path_str}");
                        Some(Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: "User".to_string(),
                            technique: "User Init Mpr Logon Script".to_string(),
                            classification: "MITRE ATT&CK T1037.001".to_string(),
                            reference: "https://attack.mitre.org/techniques/T1037/001/".to_string(),
                            value: s.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        }));
    }
    result
}

fn get_hhctrl_hijacking(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting the hhctrl.ocx library inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"Classes\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32",
            |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().is_empty() || v.name() == "(default)")
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            let path_str = format!("{} {s}", v.name());
                            println!("\t{path_str}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: path_str,
                                access_gained: "System".to_string(),
                                technique: "Hijacking of hhctrl.ocx".to_string(),
                                classification: "Hexacorn Technique N.77".to_string(),
                                reference: "https://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/".to_string(),
                                value: s.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }
        ));
    }
    result
}

fn get_app_init_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AppInit_DLLs property.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, technique) in &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit DLLs"),
            (r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit DLLs (Wow6432Node)"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                let load_flag = key
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("LoadAppInit_DLLs"))
                    .and_then(|v| {
                        if let RegistryValue::RegDWord(n) = v.value() {
                            Some(*n)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(1);
                if load_flag == 0 {
                    return vec![];
                }
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case("AppInit_DLLs"))
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            if s.trim().is_empty() {
                                return None;
                            }
                            println!("\t{s}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: key_path.to_string(),
                                access_gained: "System".to_string(),
                                technique: technique.to_string(),
                                classification: "MITRE ATT&CK T1546.010".to_string(),
                                reference: "https://attack.mitre.org/techniques/T1546/010/".to_string(),
                                value: s.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_lsa_packages(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting LSA Authentication, Security and Notification Packages.");
    let defaults = ["", "msv1_0", "scecli", "rassfm"];
    let lsa_values = [
        ("Authentication Packages", "System"),
        ("Security Packages", "System"),
        ("Notification Packages", "System"),
    ];
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                let mut entries = Vec::new();
                for (value_name, access) in &lsa_values {
                    if let Some(v) = key
                        .values()
                        .iter()
                        .find(|v| v.name().eq_ignore_ascii_case(value_name))
                    {
                        if let RegistryValue::RegMultiSZ(packages) = v.value() {
                            for pkg in packages {
                                let pkg = pkg.trim();
                                if pkg.is_empty()
                                    || defaults.iter().any(|d| d.eq_ignore_ascii_case(pkg))
                                {
                                    continue;
                                }
                                println!("\t{pkg}");
                                entries.push(Persistence {
                                    timestamp: ts.clone(),
                                    path: r"SYSTEM\CurrentControlSet\Control\Lsa".to_string(),
                                    access_gained: access.to_string(),
                                    technique: format!("LSA {value_name}"),
                                    classification: "MITRE ATT&CK T1547.002".to_string(),
                                    reference: "https://attack.mitre.org/techniques/T1547/002/".to_string(),
                                    value: pkg.to_string(),
                                });
                            }
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_boot_execute(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting BootExecute property.");
    let defaults = ["autocheck autochk *", "autocheck autochk*", ""];
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                let mut entries = Vec::new();
                if let Some(v) = key
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("BootExecute"))
                {
                    let items: Vec<String> = match v.value() {
                        RegistryValue::RegMultiSZ(list) => list.clone(),
                        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) => {
                            vec![s.clone()]
                        }
                        _ => vec![],
                    };
                    for entry in items {
                        let entry = entry.trim();
                        if defaults.iter().any(|d| d.eq_ignore_ascii_case(entry)) {
                            continue;
                        }
                        println!("\t{entry}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: r"SYSTEM\CurrentControlSet\Control\Session Manager".to_string(),
                            access_gained: "System".to_string(),
                            technique: "Boot Execute".to_string(),
                            classification: "MITRE ATT&CK T1542.003".to_string(),
                            reference: "https://attack.mitre.org/techniques/T1542/003/".to_string(),
                            value: entry.to_string(),
                        });
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_active_setup(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Active Setup Installed Components.");
    let mut result = Vec::new();
    for hive_path in hives {
        for key_path in &[
            r"SOFTWARE\Microsoft\Active Setup\Installed Components",
            r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for comp_rc in subkeys.iter() {
                        let comp = comp_rc.borrow();
                        let stub = comp
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("StubPath"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(stub_path) = stub {
                            println!("\t{stub_path}");
                            entries.push(Persistence {
                                timestamp: fmt_ts(comp.timestamp()),
                                path: format!(r"{key_path}\{}", comp.name()),
                                access_gained: "System".to_string(),
                                technique: "Active Setup StubPath".to_string(),
                                classification: "Hexacorn Technique N.54".to_string(),
                                reference: "https://www.hexacorn.com/blog/2014/07/16/beyond-good-ol-run-key-part-35/".to_string(),
                                value: stub_path,
                            });
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_screensaver(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Screensaver persistence.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, r"Control Panel\Desktop", |key, _hive| {
            key.values()
                .iter()
                .find(|v| v.name().eq_ignore_ascii_case("SCRNSAVE.EXE"))
                .and_then(|v| {
                    if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                        let s = s.trim().to_string();
                        if s.is_empty() { return None; }
                        println!("\t{s}");
                        Some(Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: hive_path.to_string_lossy().to_string(),
                            access_gained: "User".to_string(),
                            technique: "Screensaver".to_string(),
                            classification: "MITRE ATT&CK T1546.002".to_string(),
                            reference: "https://attack.mitre.org/techniques/T1546/002/".to_string(),
                            value: s,
                        })
                    } else { None }
                })
                .into_iter()
                .collect::<Vec<_>>()
        }));
    }
    result
}

fn get_silent_process_exit(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting SilentProcessExit persistence.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            |key, hive| {
                let mut entries = Vec::new();
                if let Ok(monitored_keys) = key.subkeys(&mut hive) {
                    for mon_rc in monitored_keys.iter() {
                        let mon = mon_rc.borrow();
                        let ts = fmt_ts(mon.timestamp());
                        let monitor_process = mon
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("MonitorProcess"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(proc) = monitor_process {
                            println!("\t{} -> {proc}", mon.name());
                            entries.push(Persistence {
                                timestamp: ts,
                                path: format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{}", mon.name()),
                                access_gained: "System".to_string(),
                                technique: "Silent Process Exit Monitor".to_string(),
                                classification: "Hexacorn Technique N.116".to_string(),
                                reference: "https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-registry-key-as-a-persistence-mechanism/".to_string(),
                                value: proc,
                            });
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_com_hijacking(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting COM Object hijacking (HKCU Classes).");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, r"Software\Classes\CLSID", |key, hive| {
            let mut entries = Vec::new();
            if let Ok(clsids) = key.subkeys(&mut hive) {
                for clsid_rc in clsids.iter() {
                    let clsid = clsid_rc.borrow();
                    let inproc = if let Ok(sub) = clsid.subkeys(&mut hive) {
                        sub.iter()
                            .find(|k| k.borrow().name().eq_ignore_ascii_case("InprocServer32"))
                            .cloned()
                    } else {
                        None
                    };
                    if let Some(inproc_rc) = inproc {
                        let inproc = inproc_rc.borrow();
                        let ts = fmt_ts(inproc.timestamp());
                        let dll = inproc
                            .values()
                            .iter()
                            .find(|v| v.name().is_empty() || v.name() == "(default)")
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(dll_path) = dll {
                            println!("\t{} -> {dll_path}", clsid.name());
                            entries.push(Persistence {
                                timestamp: ts,
                                path: format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid.name()),
                                access_gained: "User".to_string(),
                                technique: "COM Object Hijacking".to_string(),
                                classification: "MITRE ATT&CK T1546.015".to_string(),
                                reference: "https://attack.mitre.org/techniques/T1546/015/".to_string(),
                                value: dll_path,
                            });
                        }
                    }
                }
            }
            entries
        }));
    }
    result
}

// ─── Helper: current control set ─────────────────────────────────────────────

fn get_current_control_set(root: &nt_hive2::KeyNode, hive: &mut HiveFile) -> Option<u32> {
    let sel_rc = root.subpath("Select", hive).ok()??;
    let sel = sel_rc.borrow();
    let result = sel
        .values()
        .iter()
        .find(|v| v.name().eq_ignore_ascii_case("Current"))
        .and_then(|v| {
            if let RegistryValue::RegDWord(n) = v.value() {
                Some(*n)
            } else {
                None
            }
        });
    result
}

// ─── File discovery ──────────────────────────────────────────────────────────

fn get_settings_json_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for settings.json files...");
    let mut files = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if entry.file_name() != "settings.json" || !path.is_file() {
            continue;
        }
        // Only Windows Terminal settings files (parent dir is LocalState,
        // grandparent contains "Microsoft.WindowsTerminal")
        let is_terminal = path
            .ancestors()
            .any(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().contains("Microsoft.WindowsTerminal"))
                    .unwrap_or(false)
            });
        if is_terminal {
            println!("\tFound settings.json: {}", path.display());
            files.push(path.to_path_buf());
        }
    }

    if files.is_empty() {
        println!("No settings.json files found.");
    }
    files
}

fn get_startup_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for startup files...");
    let mut files = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // File must be inside a directory named exactly "Startup"
        let in_startup = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Startup"))
            .unwrap_or(false);
        if in_startup {
            println!("\tFound startup file: {}", path.display());
            files.push(path.to_path_buf());
        }
    }

    if files.is_empty() {
        println!("No startup files found.");
    }
    files
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn write_csv(persistences: &[Persistence], prefix: &Path) -> Result<()> {
    let out_path = prefix.join("boromir.output.csv");
    let mut wtr = csv::Writer::from_path(&out_path)?;
    wtr.write_record(["Timestamp", "Path", "AccessGained", "Technique", "Classification", "Value"])?;
    for p in persistences {
        wtr.write_record([
            &p.timestamp,
            &p.path,
            &p.access_gained,
            &p.technique,
            &p.classification,
            &p.value,
        ])?;
    }
    wtr.flush()?;
    println!("Output written to {}", out_path.display());
    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn run_all(hives: &[PathBuf], source: &Path) -> Vec<Persistence> {
    let mut all: Vec<Persistence> = Vec::new();
    all.extend(get_run(hives));
    all.extend(get_runonce(hives));
    all.extend(get_runex(hives));
    all.extend(get_runonceex(hives));
    all.extend(get_image_file_execution_options(hives));
    all.extend(get_nldp_dll_override_path(hives));
    all.extend(get_aedebug(hives));
    all.extend(get_wer_fault_hangs(hives));
    all.extend(get_cmd_autorun(hives));
    all.extend(get_explorer_load(hives));
    all.extend(get_winlogon_userinit(hives));
    all.extend(get_winlogon_shell(hives));
    let settings_files = get_settings_json_files(source);
    all.extend(get_terminal_profile_start_on_user_login(&settings_files));
    all.extend(get_app_cert_dlls(hives));
    all.extend(get_app_paths(hives));
    all.extend(get_service_dlls(hives));
    all.extend(get_gp_extension_dlls(hives));
    all.extend(get_winlogon_mpnotify(hives));
    all.extend(get_chm_helper_dll(hives));
    let startup_files = get_startup_files(source);
    all.extend(get_startup_programs(&startup_files));
    all.extend(get_scheduled_tasks(hives, Some(source)));
    all.extend(get_windows_services(hives));
    all.extend(get_user_init_mpr_script(hives));
    all.extend(get_hhctrl_hijacking(hives));
    all.extend(get_app_init_dlls(hives));
    all.extend(get_lsa_packages(hives));
    all.extend(get_boot_execute(hives));
    all.extend(get_active_setup(hives));
    all.extend(get_screensaver(hives));
    all.extend(get_silent_process_exit(hives));
    all.extend(get_com_hijacking(hives));
    all
}

fn main() -> Result<()> {
    let args = Args::parse();

    let source = args.source_evidence.as_deref();

    // For actions that need hives or source evidence, check source is provided
    match &args.action {
        Action::All => {
            let source = source.expect("--source-evidence required for 'all'");
            let hives = get_hives(source);
            let mut persistences = run_all(&hives, source);
            persistences.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            if let Some(prefix) = &args.csv_output {
                write_csv(&persistences, prefix)?;
            }
        }
        action => {
            let hives: Vec<PathBuf> = if let Some(src) = source {
                get_hives(src)
            } else {
                Vec::new()
            };

            let mut persistences = match action {
                Action::GetRun => get_run(&hives),
                Action::GetRunOnce => get_runonce(&hives),
                Action::GetRunEx => get_runex(&hives),
                Action::GetRunOnceEx => get_runonceex(&hives),
                Action::GetImageFileExecutionOptions => get_image_file_execution_options(&hives),
                Action::GetNldpDllOverridePath => get_nldp_dll_override_path(&hives),
                Action::GetAedebug => get_aedebug(&hives),
                Action::GetWerFaultHangs => get_wer_fault_hangs(&hives),
                Action::GetCmdAutorun => get_cmd_autorun(&hives),
                Action::GetExplorerLoad => get_explorer_load(&hives),
                Action::GetWinlogonUserinit => get_winlogon_userinit(&hives),
                Action::GetWinlogonShell => get_winlogon_shell(&hives),
                Action::GetTerminalProfileStartOnUserLogin => {
                    let files = source
                        .map(get_settings_json_files)
                        .unwrap_or_default();
                    get_terminal_profile_start_on_user_login(&files)
                }
                Action::GetAppCertDlls => get_app_cert_dlls(&hives),
                Action::GetAppPaths => get_app_paths(&hives),
                Action::GetServiceDlls => get_service_dlls(&hives),
                Action::GetGpExtensionDlls => get_gp_extension_dlls(&hives),
                Action::GetWinlogonMpNotify => get_winlogon_mpnotify(&hives),
                Action::GetChmHelperDll => get_chm_helper_dll(&hives),
                Action::GetStartupPrograms => {
                    let files = source
                        .map(get_startup_files)
                        .unwrap_or_default();
                    get_startup_programs(&files)
                }
                Action::GetScheduledTasks => get_scheduled_tasks(&hives, source),
                Action::GetWindowsServices => get_windows_services(&hives),
                Action::GetUserInitMprScript => get_user_init_mpr_script(&hives),
                Action::GetHhCtrlHijacking => get_hhctrl_hijacking(&hives),
                Action::GetAppInitDlls => get_app_init_dlls(&hives),
                Action::GetLsaPackages => get_lsa_packages(&hives),
                Action::GetBootExecute => get_boot_execute(&hives),
                Action::GetActiveSetup => get_active_setup(&hives),
                Action::GetScreensaver => get_screensaver(&hives),
                Action::GetSilentProcessExit => get_silent_process_exit(&hives),
                Action::GetComHijacking => get_com_hijacking(&hives),
                Action::All => unreachable!(),
            };

            persistences.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            if let Some(prefix) = &args.csv_output {
                write_csv(&persistences, prefix)?;
            }
        }
    }

    Ok(())
}
