//! Embeds a Windows VERSIONINFO resource and an assembly manifest into the DLL.
//!
//! A DLL carrying no resources at all is an "anonymous binary" to Defender's ML
//! heuristics, which is one of the few things about this mod we can change: the
//! memory scan and the 5-byte patch are inherently what a game hack looks like.
//! The metadata below is the same information the README carries, in the form
//! Windows expects. See the README's "Antivirus false positives" section.
//!
//! Non-Windows targets are skipped, so `cargo test --lib` still works anywhere.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Naming any file above disables Cargo's default tracking, and every string
    // below comes from Cargo.toml.
    println!("cargo:rerun-if-changed=Cargo.toml");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    /// `VFT_DLL` from `verrsrc.h`. Besides labelling the file correctly, this
    /// is what makes `winresource` emit the manifest as resource ID 2, the ID
    /// the loader reads for a DLL (ID 1 is the executable's manifest).
    const VFT_DLL: u64 = 2;

    let repository = std::env::var("CARGO_PKG_REPOSITORY").unwrap();
    let description = std::env::var("CARGO_PKG_DESCRIPTION").unwrap();
    let license = std::env::var("CARGO_PKG_LICENSE").unwrap();
    // Cargo separates authors with ':' and allows a "Name <email>" form. These
    // strings ship inside a binary handed to strangers, so keep the names and
    // drop the addresses. CompanyName names the publisher, and CI treats it as
    // the "resources were embedded" sentinel, so an empty one would surface as
    // a puzzling workflow failure instead of a clear error.
    let authors = std::env::var("CARGO_PKG_AUTHORS")
        .unwrap()
        .split(':')
        .map(|author| {
            author
                .split('<')
                .next()
                .unwrap_or(author)
                .trim()
                .to_string()
        })
        .filter(|author| !author.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(!authors.is_empty(), "Cargo.toml must declare `authors`");
    let copyright = if license.is_empty() {
        format!("Copyright (C) 2026 {authors}")
    } else {
        format!("Copyright (C) 2026 {authors}, {license}")
    };

    // An assembly identity version must be four numbers. Building it from the
    // components (rather than CARGO_PKG_VERSION) keeps a pre-release version
    // like "1.2.0-rc.1" from producing an identity SxS rejects, which would
    // fail the activation context and make the game unable to load the DLL.
    let assembly_version = format!(
        "{}.{}.{}.0",
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_MINOR").unwrap(),
        std::env::var("CARGO_PKG_VERSION_PATCH").unwrap(),
    );
    let architecture = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "amd64",
        "x86" => "x86",
        "aarch64" => "arm64",
        // Legal wildcard identity: better than claiming the wrong one.
        _ => "*",
    };

    // No `<?xml?>` prolog: the resource compiler emits each line as a quoted,
    // space-padded string, and a declaration preceded by whitespace is not a
    // well-formed document. The prolog is optional, leading whitespace before
    // the root element is not an error, so dropping it keeps SxS happy.
    //
    // Identity only. With no <dependentAssembly> there is nothing for the
    // loader to resolve, so building the activation context cannot fail.
    let manifest = format!(
        r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity type="win32" name="MenuInputDelayFix" version="{assembly_version}" processorArchitecture="{architecture}"/>
</assembly>"#
    );

    // FileVersion and ProductVersion are filled from Cargo.toml by
    // `WindowsResource::new()`. FileDescription defaults to the package name,
    // but it is what Windows shows in the file's Details tab, so give it the
    // sentence that actually explains the file.
    let mut res = winresource::WindowsResource::new();
    res.set("FileDescription", &description)
        .set("ProductName", "MenuInputDelayFix")
        .set("InternalName", "MenuInputDelayFix.dll")
        .set("OriginalFilename", "MenuInputDelayFix.dll")
        .set("CompanyName", &authors)
        // Hardcoded year: deriving it at build time would change the binary
        // every January for no reason. The license is empty when Cargo.toml
        // uses `license-file` instead of `license`.
        .set("LegalCopyright", &copyright)
        .set(
            "Comments",
            &format!("Free software, source at {repository}"),
        )
        .set_version_info(winresource::VersionInfo::FILETYPE, VFT_DLL)
        .set_language(0x0409) // en-US
        .set_manifest(&manifest);

    res.compile()
        .expect("failed to embed Windows resources: is rc.exe from the Windows SDK on PATH?");
}
