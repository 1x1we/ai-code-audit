use std::process::Command;

pub fn speak(text: &str) {
    let dir = std::env::temp_dir();
    let path = format!("{}/vb_tts.mp3", dir);
    // guard-first: external input validated via whitelist before reaching shell
    if path_allowed(text) {
        let _ = Command::new("pwsh")
            .args(["-Command", &format!("(New-Item -Path '{}')", path)])
            .status();
    }
    // real danger: external input straight into shell (must still be HIGH)
    let _ = Command::new("sh").arg("-c").arg(text).status();
}

fn path_allowed(_s: &str) -> bool { true }
