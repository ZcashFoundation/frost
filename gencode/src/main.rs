//! Generate documentation for a ciphersuite based on another ciphersuite implementation.
//!
//! This is an internal tool used for development.
//!
//! The documentation for each ciphersuite is very similar, with the only difference being
//! the ciphersuite name.
//!
//! To make it easier to update all ciphersuite documentation when a change is needed,
//! this binary allows updating all of them based on a single one. This binary
//! uses frost-ristretto255 as the "canonical" one, so:
//!
//! - Change any documentation of a public function or struct in `frost-ristretto255/src/lib.rs`
//! - Run `cargo run --manifest-path gencode/Cargo.toml` to update the documentation
//!   of the other ciphersuites.
//!
//! This tool is also used to automatically generate similar files in each
//! ciphersuite, such as:
//! - README.md
//! - The dkg.rs module and the dkg.md docs
//! - The repairable.rs module (it uses the frost-core docs as canonical)

use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    iter::zip,
    process::{Command, ExitCode, Stdio},
};

use regex::Regex;

/// Read the public documentation of public items (functions, types, etc.) in the given file.
///
/// This identifiers snippets in the given file with the format:
///
/// ```
/// /// Some documentation
/// pub [kind] [identifier][rest of the line...]
/// ```
///
/// It will return details for each match:
/// - the item identifier
/// - the entire documentation string
/// - the start and end position of the documentation string in the code, which allows
///   replacing it later
///
/// # Parameters
///
/// filename: the name of the file to read.
/// suite_strings: strings that reference the specific suite in code
///     inside `fn` and should be ignore when using for replacements.
///
/// # Returns
///
/// A list with data for each item, see above.
fn read_docs(filename: &str, suite_strings: &[&str]) -> Vec<(String, String, usize, usize)> {
    let mut docs = Vec::new();
    let code = fs::read_to_string(filename).unwrap();
    let re = Regex::new(concat!(
        // Enable multi-line (makes "^" match start of line)
        r"(?m)",
        // Matches multiple comment lines: whitespace, three slashes, anything else.
        // Captures the entire comment in the "doc" group.
        r"(?P<doc>(^[ ]*///.*\n)+)",
        // Matches zero or more attributes: whitespace, "#", anything else.
        // Captures all attributes in the "attrs" group
        r"(?P<attrs>(\s*#.*\n)*)",
        // Matches the item declaration: whitespace, "pub", kind, identifier
        // (captured in the "name" capture group), anything else
        r"\s*pub \w+ (?P<name>\w+).*"
    ))
    .unwrap();

    for m in re.captures_iter(code.as_str()) {
        let (name, doc) = (
            m.name("name").unwrap().as_str(),
            m.name("doc").unwrap().as_str(),
        );
        let mut name = name.to_string();
        // Replacing ciphersuite-specific names with a fixed string allows
        // comparing item "names" to check later if we're working on the
        // same item.
        for n in suite_strings.iter() {
            name = name.replace(n, "SuiteName");
        }
        docs.push((
            name,
            doc.to_string(),
            m.name("doc").unwrap().start(),
            m.name("doc").unwrap().end(),
        ))
    }
    docs
}

/// Write the documentation for the given file, using a previously-read documentation
/// from another file as a base, replacing ciphersuite-specific references as needed.
/// Returns 1 if the file was modified or 0 otherwise.
///
/// # Parameters
///
/// docs: the documentation from another file which will be used as a base.
/// filename: the name of the file to write documentation for.
/// original_suite_strings: ciphersuite-specific references in the base file
/// new_suite_strings: replacements to use in the documentation of the given file
///     for each reference in `original_suite_strings`.
fn write_docs(
    docs: &[(String, String, usize, usize)],
    filename: &str,
    original_suite_strings: &[&str],
    new_suite_strings: &[&str],
) -> u8 {
    let old_docs = read_docs(filename, new_suite_strings);
    let mut code = fs::read_to_string(filename).unwrap();
    let original_code = code.clone();

    // Map documentations by their identifiers
    let docs: BTreeMap<String, (String, String, usize, usize)> =
        docs.iter().map(|x| (x.0.clone(), x.clone())).collect();

    // To be able to replace the documentation properly, start from the end, which
    // will keep the string positions consistent
    for (old_name, _, old_start, old_end) in old_docs.iter().rev() {
        let new_doc = docs
            .get(old_name)
            .unwrap_or_else(|| {
                panic!(
                    "documentation for {} is not available in base file",
                    old_name
                )
            })
            .1
            .clone();

        // Replaces ciphersuite-references in documentation
        let mut new_doc = new_doc.to_string();
        for (old_n, new_n) in zip(original_suite_strings.iter(), new_suite_strings.iter()) {
            new_doc = new_doc.replace(old_n, new_n)
        }
        code.replace_range(old_start..old_end, &new_doc);
    }
    fs::write(filename, &code).unwrap();
    u8::from(original_code != code)
}

/// Copy a file into a new one, replacing the strings in `original_strings`
/// by the respective one in `replacement_strings` in the process.
fn copy_and_replace(
    origin_filename: &str,
    destination_filename: &str,
    original_strings: &[&str],
    replacement_strings: &[&str],
    format: bool,
) -> u8 {
    let mut text = fs::read_to_string(origin_filename).unwrap();
    let original_text = fs::read_to_string(destination_filename).unwrap_or_else(|_| "".to_string());

    for (from, to) in std::iter::zip(original_strings, replacement_strings) {
        text = text.replace(from, to)
    }
    if format {
        text = rustfmt(text);
    }

    let folder = std::path::Path::new(destination_filename).parent().unwrap();
    let _ = fs::create_dir_all(folder);
    fs::write(destination_filename, &text).unwrap();
    u8::from(original_text != text)
}

pub fn rustfmt(source: String) -> String {
    let mut child = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process. Is 'rustfmt' available?");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    std::thread::spawn(move || {
        stdin
            .write_all(source.as_bytes())
            .expect("Failed to write to stdin");
    });

    let output = child.wait_with_output().expect("Failed to read stdout");
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut replaced = 0;
    let check = args.len() == 2 && args[1] == "--check";

    // Copy the frost-core repairable docs into ristretto255.
    // This will then be copied later down into the other ciphersuites.
    let repairable_docs = read_docs("frost-core/src/keys/repairable.rs", &[]);
    replaced |= write_docs(
        &repairable_docs,
        "frost-ristretto255/src/keys/repairable.rs",
        &[],
        &[],
    );

    // Generate code or copy docs for other ciphersuites, using
    // ristretto255 as the canonical base.

    let original_folder = "frost-ristretto255";
    let mut original_strings: Vec<String> = [
        "Ristretto255Sha512",
        "Ristretto group",
        "Ristretto",
        "FROST(ristretto255, SHA-512)",
        "FROST-RISTRETTO255-SHA512-v1",
        "ristretto255_sha512",
        "ristretto255",
        "<R>",
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();

    // Some test use "sample" values. To make these tests work for another ciphersuites,
    // these values must be replaced. To make it cleaner, the strings are
    // specified in JSON files, and appended here to original_strings.
    let samples: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{original_folder}/tests/helpers/samples.json")).unwrap(),
    )
    .unwrap();
    for key in &["identifier", "element1", "element2", "scalar1"] {
        original_strings.push(samples[key].as_str().unwrap().to_owned());
    }
    let original_strings: Vec<&str> = original_strings.iter().map(|s| s.as_ref()).collect();

    let docs = read_docs("frost-ristretto255/src/lib.rs", &original_strings);

    // To add a new ciphersuite, just copy a tuple and replace the required strings.
    for (folder, replacement_strings) in [
        (
            // The folder where the ciphersuite crate is
            "frost-p256",
            // String replacements for the strings in `original_strings`
            &[
                "P256Sha256",
                "P-256 curve",
                "P256",
                "FROST(P-256, SHA-256)",
                "FROST-P256-SHA256-v1",
                "p256_sha256",
                "p256",
                "<P>",
            ],
        ),
        (
            "frost-ed25519",
            &[
                "Ed25519Sha512",
                "Ed25519 curve",
                "Ed25519",
                "FROST(Ed25519, SHA-512)",
                "FROST-ED25519-SHA512-v1",
                "ed25519_sha512",
                "ed25519",
                "<E>",
            ],
        ),
        (
            "frost-ed448",
            &[
                "Ed448Shake256",
                "Ed448 curve",
                "Ed448",
                "FROST(Ed448, SHAKE256)",
                "FROST-ED448-SHAKE256-v1",
                "ed448_shake256",
                "ed448",
                "<E>",
            ],
        ),
        (
            "frost-secp256k1",
            &[
                "Secp256K1Sha256",
                "secp256k1 curve",
                "Secp256K1",
                "FROST(secp256k1, SHA-256)",
                "FROST-secp256k1-SHA256-v1",
                "secp256k1_sha256",
                "secp256k1",
                "<S>",
            ],
        ),
    ] {
        // Some test use "sample" values. To make these tests work for another ciphersuites,
        // these values must be replaced. To make it cleaner, the strings are
        // specified in JSON files, and appended here to replacement_strings.
        let mut replacement_strings: Vec<String> =
            replacement_strings.iter().map(|x| x.to_string()).collect();
        let samples: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{folder}/tests/helpers/samples.json")).unwrap(),
        )
        .unwrap();
        for key in &["identifier", "element1", "element2", "scalar1"] {
            replacement_strings.push(samples[key].as_str().unwrap().to_owned());
        }
        let replacement_strings: Vec<&str> =
            replacement_strings.iter().map(|s| s.as_ref()).collect();

        let lib_filename = format!("{folder}/src/lib.rs");
        // Copy the documentation of public items in Rust code, replacing ciphersuite-specific strings inside
        // them in the process.
        replaced |= write_docs(
            &docs,
            &lib_filename,
            &original_strings,
            &replacement_strings,
        );

        // Generate files based on a template with simple search & replace.
        for filename in [
            "README.md",
            "dkg.md",
            "src/keys/dkg.rs",
            "src/keys/refresh.rs",
            "src/keys/repairable.rs",
            "src/tests/batch.rs",
            "src/tests/coefficient_commitment.rs",
            "src/tests/proptests.rs",
            "src/tests/vss_commitment.rs",
            "tests/common_traits_tests.rs",
            "tests/integration_tests.rs",
            "tests/recreation_tests.rs",
            "tests/rerandomized_tests.rs",
            "tests/serde_tests.rs",
            "tests/serialization_tests.rs",
            "tests/helpers/samples.rs",
        ] {
            replaced |= copy_and_replace(
                format!("{original_folder}/{filename}").as_str(),
                format!("{folder}/{filename}").as_str(),
                &original_strings,
                &replacement_strings,
                filename.ends_with(".rs"),
            );
        }
    }

    // If --check was specified, return 0 if no replacements were made
    // and 1 if some were made. This allows checking in CI whether
    // gencode-generated files are up to date.
    if check {
        ExitCode::from(replaced)
    } else {
        ExitCode::SUCCESS
    }
}
