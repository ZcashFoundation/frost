//! Generate documentation for a ciphersuite based on another ciphersuite implementation.
//!
//! The documentation for each ciphersuite is very similar, with the only difference being
//! the ciphersuite name.
//!
//! To make it easier to update all ciphersuite documentation when a change is needed,
//! this binary allows updating all of them based on a single one. This binary
//! uses frost-ristretto255 as the "canonical" one, so:
//!
//! - Change any documentation of a public function or struct in `frost-ristretto255/src/lib.rs`
//! - Run `cargo run --manifest-path gendoc/Cargo.toml` to update the documentation
//!   of the other ciphersuites.

use std::{fs, iter::zip};

use regex::Regex;

/// Read the public documentation of public items (functions, types, etc.) in the given file.
///
/// This identifiers snippets in the given file with the format:
///
/// ```
/// /// Some documentation
/// pub [rest of the line...]
/// ```
///
/// It will return details for each match:
/// - the item "name" ("[rest of the line...]" above, but after replacing
///   any string in `suite_names_code` with "SuiteName")
/// - the entire documentation string
/// - the start and end position of the documentation string in the code, which allows
///   replacing it later
///
/// # Parameters
///
/// filename: the name of the file to read.
/// suite_names_code: strings that reference the specific suite in code
///     inside `fn` and should be ignore when using for replacements.
///
/// # Returns
///
/// A list with data for each item, see above.
fn read_docs(filename: &str, suite_names_code: &[&str]) -> Vec<(String, String, usize, usize)> {
    let mut docs = Vec::new();
    let code = fs::read_to_string(filename).unwrap();
    let re = Regex::new(r"(?m)((^[ ]*///.*\n)+)\s*pub (.*)").unwrap();

    for m in re.captures_iter(code.as_str()) {
        // Captures: 0 - the whole match; 1: documentation;
        // 2: internal capture group; 3: the item "name" as described above
        let (name, doc) = (m.get(3).unwrap().as_str(), m.get(1).unwrap().as_str());
        let mut name = name.to_string();
        // Replacing ciphersuite-specific names with a fixed string allows
        // comparing item "names" to check later if we're working on the
        // same item.
        for n in suite_names_code.iter() {
            name = name.replace(n, "SuiteName");
        }
        docs.push((
            name,
            doc.to_string(),
            m.get(1).unwrap().start(),
            m.get(1).unwrap().end(),
        ))
    }
    docs
}

/// Write the documentation for the given file, using a previously-read documentation
/// from another file as a base, replacing ciphersuite-specific references as needed.
///
/// # Parameters
///
/// docs: the documentation from another file which will be used as a base.
/// filename: the name of the file to write documentation for.
/// suite_names_code: ciphersuite-specific references for code in `fn`, see read_docs
/// old_suite_names_doc: ciphersuite-specific references in the documentation of
///     the base file
/// new_suite_names_doc: replacements to use in the documentation of the given file
///     for each reference in `old_suite_names_doc`.
fn write_docs(
    docs: &[(String, String, usize, usize)],
    filename: &str,
    suite_names_code: &[&str],
    old_suite_names_doc: &[&str],
    new_suite_names_doc: &[&str],
) {
    let old_docs = read_docs(filename, suite_names_code);
    let mut code = fs::read_to_string(filename).unwrap();

    // To be able to replace the documentation properly, start from the end, which
    // will keep the string positions consistent
    for ((_old_name, _, old_start, old_end), (_new_name, new_doc, _, _)) in
        zip(old_docs.iter().rev(), docs.iter().rev())
    {
        // This is a sanity check to test if we're replacing the right comment.
        // It was commented out due to an exception (Ed25519 scalar is defined
        // as the Ristretto25519 scalar instead of its own struct)
        // assert_eq!(old_name, new_name, "source code does not match");

        // Replaces ciphersuite-references in documentation
        let mut new_doc = new_doc.to_string();
        for (old_n, new_n) in zip(old_suite_names_doc.iter(), new_suite_names_doc.iter()) {
            new_doc = new_doc.replace(old_n, new_n)
        }
        code.replace_range(old_start..old_end, &new_doc);
    }
    fs::write(filename, code).unwrap();
}

/// Copy a file into a new one, replacing the strings in `original_strings`
/// by the respective one in `replacement_strings` in the process.
fn copy_and_replace(
    origin_filename: &str,
    destination_filename: &str,
    original_strings: &[&str],
    replacement_strings: &[&str],
) {
    let mut text = fs::read_to_string(origin_filename).unwrap();

    for (from, to) in std::iter::zip(original_strings, replacement_strings) {
        text = text.replace(from, to)
    }

    fs::write(destination_filename, text).unwrap();
}

fn main() {
    let docs = read_docs(
        "frost-ristretto255/src/lib.rs",
        &["Ristretto255Sha512", "Ristretto", "<R>"],
    );
    let old_suite_names_doc = &["FROST(ristretto255, SHA-512)"];

    let original_basename = "frost-ristretto255/";
    let original_strings = &["frost_ristretto255", "Ristretto group"];

    // To add a new ciphersuite, just copy this call and replace the required strings.

    write_docs(
        &docs,
        "frost-p256/src/lib.rs",
        &["P256Sha256", "P256", "<P>"],
        old_suite_names_doc,
        &["FROST(P-256, SHA-256)"],
    );
    for filename in ["README.md", "dkg.md"] {
        copy_and_replace(
            format!("{}/{}", original_basename, filename).as_str(),
            format!("frost-p256/{}", filename).as_str(),
            original_strings,
            &["frost_p256", "P-256 curve"],
        );
    }

    write_docs(
        &docs,
        "frost-ed25519/src/lib.rs",
        &["Ed25519Sha512", "Ed25519", "<E>"],
        old_suite_names_doc,
        &["FROST(Ed25519, SHA-512)"],
    );
    for filename in ["README.md", "dkg.md"] {
        copy_and_replace(
            format!("{}/{}", original_basename, filename).as_str(),
            format!("frost-ed25519/{}", filename).as_str(),
            original_strings,
            &["frost_ed25519", "Ed25519 curve"],
        );
    }
    
    write_docs(
        &docs,
        "frost-secp256k1/src/lib.rs",
        &["Secp256K1Sha556", "Secp256K1", "<E>"],
        old_suite_names_doc,
        &["FROST(secp256k1, SHA-256)"],
    );
    for filename in ["README.md", "dkg.md"] {
        copy_and_replace(
            readme_filename,
            "frost-secp256k1/README.md",
            original_strings,
            &["frost_secp256k1", "secp256k1 curve"],
        );
    }
}
