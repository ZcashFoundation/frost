"""
Generate documentation for a ciphersuite based on another ciphersuite implementation.

The documentation for each ciphersuite is very similar, with the only difference being
the ciphersuite name.

To make it easier to update all ciphersuites documentations when a change is needed,
this script allows updating all of them based on a single one. This script
uses frost-ristretto255 as the "canonical" one, so:

- Change any documentation of a public function or struct in `frost-ristretto255/src/lib.rs`
- Run `python3 gendoc.py` to update the documentation of the other ciphersuites.
"""

import re

def read_docs(fn, suite_names_code):
    """Read the public documentation of public symbols in the given file.

    This identifiers snippets in the given file with the format:

    ```
    /// Some documentation
    pub [rest of the line...]
    ```

    It will return details for each match:
    - the symbol "name" ("[rest of the line...]" above, but after replacing
      any string in `suite_names_code` with "SuiteName")
    - the entire documentation string
    - the start and end position of the documentation string in the code, which allows
      replacing it later

    Args:
        fn (str): the name of the file to read.
        suite_names_code (list[str]): strings that reference the specific suite in code
            inside `fn` and should be ignore when using for replacements.

    Returns:
        list[tuple[str, str, int, int]]: a list with data for each symbol, see above.
    """
    docs = []
    with open(fn, 'r') as f:
        code = f.read()
    for m in re.finditer(r'((^[ ]*///.*\n)+)\s*pub (.*)', code, re.MULTILINE):
        name, doc = m[3], m[1]
        for n in suite_names_code:
            name = name.replace(n, 'SuiteName')
        docs.append((name, doc, m.start(1), m.end(1)))
    return docs

def write_docs(docs, fn, suite_names_code, old_suite_names_doc, new_suite_names_doc):
    """Write the documentation for the given file, using a previously-read documentation
    from another file as a base, replacing ciphersuite-specific references as needed.

    Args:
        docs (list[tuple[str, str, int, int]]): the documentation from another file
            which will be used as a base.
        fn (str): the name of the file to write documentation for
        suite_names_code (list[str]): ciphersuite-specific references for code in `fn`,
            see read_docs
        old_suite_names_doc (list[str]): ciphersuite-specific references for documentation
            in the base file
        new_suite_names_doc (_type_): replacements to use in the documented file
            for each reference in `old_suite_names_doc`
    """
    old_docs = read_docs(fn, suite_names_code)
    with open(fn, 'r') as f:
        code = f.read()
    # To be able to replace the documentation properly, start from the end, which
    # will keep the string positions consistent
    for ((old_name, old_doc, old_start, old_end), (new_name, new_doc, _, _)) in zip(reversed(old_docs), reversed(docs)):
        assert old_name == new_name, "source code does not match"
        # Replaces ciphersuite-references in documentation
        for old_n, new_n in zip(old_suite_names_doc, new_suite_names_doc):
            new_doc = new_doc.replace(old_n, new_n)
        # print('Replacing\n-----\n{}-----\n{}-----'.format(old_doc, new_doc))
        code = ''.join((code[:old_start], new_doc, code[old_end:]))
    with open(fn, 'w') as f:
        f.write(code)

if __name__ == '__main__':
    docs = read_docs('frost-ristretto255/src/lib.rs', ('Ristretto255Sha512', 'Ristretto', '<R>'))
    old_suite_names_doc = ('FROST(ristretto255, SHA-512)',)

    # To add a new ciphersuite, just copy this call and replace the required strings.

    write_docs(docs, 'frost-p256/src/lib.rs', ('P256Sha256', 'P256', '<P>'),
        old_suite_names_doc, ('FROST(P-256, SHA-256)',))
