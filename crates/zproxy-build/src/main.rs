/// zProxy build helper.
///
/// Automates cross-compilation and build configuration for zProxy-Engine.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::process::{Command, Stdio};

#[derive(Parser, Debug)]
#[command(name = "zproxy-build", about = "zProxy build helper tool")]
struct Cli {
    /// Compilation target (e.g. x86_64-pc-windows-gnu)
    #[arg(short, long)]
    target: Option<String>,

    /// Build in release mode (default: debug)
    #[arg(long)]
    release: bool,

    /// Build all workspace crates
    #[arg(long)]
    all: bool,

    /// Include the GUI crate
    #[arg(long)]
    gui: bool,

    /// Output directory for built artifacts
    #[arg(long)]
    output_dir: Option<String>,
}

fn is_windows_target(target: &Option<String>) -> bool {
    target.as_deref().map(|t| t.contains("windows")).unwrap_or(false)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("=== zProxy Build Helper ===");
    println!();

    // --- Check required tools ---
    check_tools()?;

    if is_windows_target(&cli.target) {
        print_windows_cross_instructions(cli.target.as_deref().unwrap_or("x86_64-pc-windows-gnu"));
    }

    // --- Build ---
    let built = build(&cli)?;

    // --- Copy artifacts ---
    if let Some(ref out_dir) = cli.output_dir {
        copy_artifacts(&built, out_dir)?;
    }

    // --- Summary ---
    println!();
    println!("=== Build Summary ===");
    for artifact in &built {
        println!("  Built: {}", artifact);
    }
    println!("Done.");

    Ok(())
}

fn check_tools() -> Result<()> {
    println!("Checking required tools...");

    let tools = [("cargo", &["--version"][..]), ("rustup", &["--version"])];
    for (tool, args) in &tools {
        match Command::new(tool).args(*args).output() {
            Ok(out) => {
                let ver = String::from_utf8_lossy(&out.stdout);
                println!("  ✓ {} – {}", tool, ver.trim());
            }
            Err(_) => {
                return Err(anyhow!("Required tool not found: {}. Install Rust from https://rustup.rs", tool));
            }
        }
    }

    // Check for `cross`
    match Command::new("cross").arg("--version").output() {
        Ok(out) => {
            let ver = String::from_utf8_lossy(&out.stdout);
            println!("  ✓ cross – {}", ver.trim());
        }
        Err(_) => {
            println!("  ℹ cross not found (optional, for Docker-based cross-compilation).");
            println!("    Install with: cargo install cross");
        }
    }

    println!();
    Ok(())
}

fn print_windows_cross_instructions(target: &str) {
    println!("Cross-compiling for Windows target: {}", target);
    println!();
    println!("Option 1 – MinGW (recommended on Linux):");
    println!("  sudo apt-get install gcc-mingw-w64-x86-64");
    println!("  rustup target add {}", target);
    println!("  cargo build --target {}", target);
    println!();
    println!("Option 2 – `cross` (Docker-based):");
    println!("  cargo install cross");
    println!("  cross build --target {}", target);
    println!();
}

fn build(cli: &Cli) -> Result<Vec<String>> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build");

    if cli.release {
        cmd.arg("--release");
    }

    if cli.all {
        if cli.gui {
            cmd.arg("--workspace");
        } else {
            cmd.args(["--workspace", "--exclude", "zproxy-gui"]);
        }
    } else if cli.gui {
        cmd.args(["-p", "zproxy-gui"]);
    } else {
        cmd.args(["-p", "zproxy-engine"]);
    }

    if let Some(ref target) = cli.target {
        cmd.args(["--target", target]);
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    println!("Running: {:?}", cmd);
    println!();

    let status = cmd.status().map_err(|e| anyhow!("Failed to run cargo: {}", e))?;

    if !status.success() {
        return Err(anyhow!("Build failed with exit code {:?}", status.code()));
    }

    // Collect artifact paths
    let profile = if cli.release { "release" } else { "debug" };
    let target_dir = match &cli.target {
        Some(t) => format!("target/{}/{}", t, profile),
        None => format!("target/{}", profile),
    };

    #[cfg(target_os = "windows")]
    let ext = ".exe";
    #[cfg(not(target_os = "windows"))]
    let ext = if is_windows_target(&cli.target) { ".exe" } else { "" };

    let mut artifacts = Vec::new();
    if cli.all || !cli.gui {
        artifacts.push(format!("{}/zproxy{}", target_dir, ext));
    }
    if cli.all || cli.gui {
        artifacts.push(format!("{}/zproxy-gui{}", target_dir, ext));
    }

    Ok(artifacts)
}

fn copy_artifacts(artifacts: &[String], output_dir: &str) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| anyhow!("Failed to create output dir '{}': {}", output_dir, e))?;

    for artifact in artifacts {
        let path = std::path::Path::new(artifact);
        if path.exists() {
            let filename = path.file_name().ok_or_else(|| anyhow!("Invalid artifact path"))?;
            let dest = std::path::Path::new(output_dir).join(filename);
            std::fs::copy(path, &dest)
                .map_err(|e| anyhow!("Failed to copy '{}' to '{}': {}", artifact, dest.display(), e))?;
            println!("  Copied {} → {}", artifact, dest.display());
        } else {
            println!("  Warning: artifact not found: {}", artifact);
        }
    }
    Ok(())
}
