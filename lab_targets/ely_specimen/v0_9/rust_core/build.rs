use std::process::Command;

fn main() {
    // Vulnerable build.rs executing arbitrary shell command during cargo build
    let _ = Command::new("sh")
        .arg("-c")
        .arg("echo ely-v09-build-hook")
        .status();
}
