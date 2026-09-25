//! Static analysis tests that catch drift between layers.
//!
//! These tests scan source code to verify that the proto service,
//! backend trait, gRPC handlers, and client all stay in sync.
//! They prevent silent feature gaps where a new RPC is added to one
//! layer but not wired through all layers.

use std::collections::BTreeSet;

/// Extract method names from the Pkcs11Backend trait source.
fn backend_trait_methods() -> Vec<String> {
    parse_backend_trait_methods(include_str!("../../backend/src/traits.rs"))
}

/// Extract RPC names from the proto service definition.
fn proto_rpc_names() -> Vec<String> {
    parse_proto_rpc_names(include_str!("../../../proto/pkcs11-proxy-ng/v1/service.proto"))
}

/// Method names declared in the `Pkcs11Backend` trait body of `src`.
fn parse_backend_trait_methods(src: &str) -> Vec<String> {
    // W1-L10-15: token parse inside the brace-matched trait body — immune to
    // commented-out methods, `fn` inside strings, helpers in inherent impls,
    // and attribute/wrapping drift that line-prefix scans miss or misread.
    let cleaned = strip_rust_code(src);
    let body =
        keyword_block(&cleaned, 0, &["trait", "Pkcs11Backend"]).expect("trait Pkcs11Backend body");
    fn_idents_in(&cleaned[body.0..body.1])
}

/// RPC names declared in the proto `service` block of `src`.
fn parse_proto_rpc_names(src: &str) -> Vec<String> {
    // W1-L10-15: token parse inside every brace-matched `service` block.
    let cleaned = strip_proto_code(src);
    let mut rpcs = Vec::new();
    let mut search_from = 0;
    while let Some((body, next)) = keyword_block_from(&cleaned, search_from, &["service"]) {
        rpcs.extend(rpc_idents_in(&cleaned[body.0..body.1]));
        search_from = next;
    }
    assert!(!rpcs.is_empty(), "no service block found in service.proto");
    rpcs
}

/// `fn <ident>(...)` declaration names in `text` (comment/string-stripped).
/// Skips fn-pointer types (`fn(` with no name), `Fn(...)` bounds, and macro
/// placeholders; tolerates `async`/`unsafe`/`const` prefixes, attributes, and
/// wrapped signatures.
fn fn_idents_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(idx) = find_keyword(text, from, "fn") {
        from = idx + 2;
        let Some((name, after)) = read_ident(text, from) else { continue };
        // A declaration has `(` (possibly after `<...>` generics) after the
        // name; anything else (`fn(`, `fn name =`, ...) is not one.
        let mut cursor = skip_ws(text, after);
        if text.as_bytes().get(cursor) == Some(&b'<') {
            cursor = skip_balanced(text, cursor, b'<', b'>').unwrap_or(text.len());
            cursor = skip_ws(text, cursor);
        }
        if text.as_bytes().get(cursor) == Some(&b'(') {
            names.push(name);
        }
        from = after;
    }
    names
}

/// `rpc <Name>(...)` names in a proto `service` body (comment-stripped).
fn rpc_idents_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(idx) = find_keyword(text, from, "rpc") {
        from = idx + 3;
        if let Some((name, after)) = read_ident(text, from) {
            let cursor = skip_ws(text, after);
            if text.as_bytes().get(cursor) == Some(&b'(') {
                names.push(name);
            }
            from = after;
        }
    }
    names
}

/// `async fn <ident>` names in `text` (comment/string-stripped), skipping
/// macro-template placeholders (`async fn $name`). Preserves the historical
/// lowercase-first rule: only concrete handler names count.
fn async_fn_idents_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(idx) = find_keyword(text, from, "async") {
        from = idx + 5;
        let cursor = skip_ws(text, from);
        if !text[cursor..].starts_with("fn")
            || (cursor > 0 && is_ident_char(text.as_bytes()[cursor - 1]))
            || text.as_bytes().get(cursor + 2).is_some_and(|b| is_ident_char(*b))
        {
            continue;
        }
        if let Some((name, after)) = read_ident(text, cursor + 2) {
            if name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
                names.push(name);
            }
            from = after;
        }
    }
    names
}

/// Inner span + end offset of the first `{ ... }` block following the keyword
/// sequence `words` (adjacent idents, in order: `impl Pkcs11Proxy for`, not a
/// far-apart `impl` + `for` loop) at or after `from`.
/// Returns `(inner_start, inner_end), after_close`.
fn keyword_block_from(text: &str, from: usize, words: &[&str]) -> Option<((usize, usize), usize)> {
    let mut cursor = from;
    loop {
        let idx = find_keyword(text, cursor, words[0])?;
        let mut probe = idx + words[0].len();
        let mut matched = true;
        for word in &words[1..] {
            match read_ident(text, probe) {
                Some((name, after)) if name == *word => probe = after,
                _ => {
                    matched = false;
                    break;
                }
            }
        }
        cursor = idx + 1;
        if !matched {
            continue;
        }
        probe = skip_ws_and_attrs(text, probe);
        let Some(rel) = text[probe..].find('{') else { continue };
        // The `{` must arrive before any `;` (a declaration, not a block) or
        // a nested `}` (ran past the item): otherwise keep scanning.
        let between = &text[probe..probe + rel];
        if between.contains([';', '}']) {
            continue;
        }
        if let Some((start, end, after)) = brace_span(text, probe + rel) {
            debug_assert_eq!(start, probe + rel + 1);
            return Some(((start, end), after));
        }
    }
}

/// `keyword_block_from` from the start of `text`, dropping the end offset.
fn keyword_block(text: &str, from: usize, words: &[&str]) -> Option<(usize, usize)> {
    keyword_block_from(text, from, words).map(|(span, _)| span)
}

/// Skip whitespace and Rust attributes (`#[...]`, including `#![...]`-style
/// doc shapes after blanking) starting at `cursor`.
fn skip_ws_and_attrs(text: &str, mut cursor: usize) -> usize {
    loop {
        cursor = skip_ws(text, cursor);
        if text.as_bytes().get(cursor) == Some(&b'#') {
            let mut end = cursor + 1;
            if text.as_bytes().get(end) == Some(&b'!') {
                end += 1;
            }
            if text.as_bytes().get(end) == Some(&b'[') {
                cursor = skip_balanced(text, end, b'[', b']').unwrap_or(text.len());
                continue;
            }
        }
        return cursor;
    }
}

/// Inner span + closing offset of the `{ ... }` block opening at `open`.
fn brace_span(text: &str, open: usize) -> Option<(usize, usize, usize)> {
    debug_assert_eq!(text.as_bytes().get(open), Some(&b'{'));
    let mut depth = 0usize;
    for (i, b) in text.bytes().enumerate().skip(open) {
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some((open + 1, i, i + 1));
            }
        }
    }
    None
}

/// Offset just past the balanced `open..close` pair starting at `start`
/// (which must hold `open`), or `None` when unbalanced.
fn skip_balanced(text: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(start) {
        if *b == open {
            depth += 1;
        } else if *b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
    }
    None
}

/// Next word-boundary occurrence of keyword `kw` at or after `from`.
/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn find_keyword(text: &str, from: usize, kw: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = from.min(bytes.len());
    while let Some(rel) = text[cursor..].find(kw) {
        let idx = cursor + rel;
        let before_ok = idx == 0 || !is_ident_char(bytes[idx - 1]);
        let after_ok = bytes.get(idx + kw.len()).is_none_or(|b| !is_ident_char(*b));
        if before_ok && after_ok {
            return Some(idx);
        }
        cursor = idx + 1;
    }
    None
}

/// Identifier starting at the first non-whitespace char at or after `from`.
/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn read_ident(text: &str, from: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut start = skip_ws(text, from);
    if bytes.get(start).is_none_or(|b| !is_ident_start(*b)) {
        return None;
    }
    start += 1;
    let mut end = start;
    while bytes.get(end).is_some_and(|b| is_ident_char(*b)) {
        end += 1;
    }
    Some((text[start - 1..end].to_string(), end))
}

/// First offset at or after `from` holding a non-whitespace byte.
/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn skip_ws(text: &str, mut cursor: usize) -> usize {
    let bytes = text.as_bytes();
    while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
        cursor += 1;
    }
    cursor
}

/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Rust source with comments (`//`, nested `/* */`), strings (`"..."`, raw
/// and byte forms), and char literals blanked to spaces; newlines and byte
/// offsets are preserved so brace matching sees code structure only.
/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn strip_rust_code(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let mut end = i + 2;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            blank_span(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let mut end = i + 2;
            let mut depth = 1;
            while end + 1 < bytes.len() && depth > 0 {
                if bytes[end..].starts_with(b"/*") {
                    depth += 1;
                    end += 2;
                } else if bytes[end..].starts_with(b"*/") {
                    depth -= 1;
                    end += 2;
                } else {
                    end += 1;
                }
            }
            let end = end.min(bytes.len());
            blank_span(&mut out, i, end);
            i = end;
        } else if let Some(len) = raw_string_len(rest) {
            blank_span(&mut out, i, i + len);
            i += len;
        } else if rest.starts_with(b"\"") || rest.starts_with(b"b\"") {
            let mut end = i + usize::from(rest.starts_with(b"b\"")) + 1;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 2;
                } else if bytes[end] == b'"' {
                    end += 1;
                    break;
                } else {
                    end += 1;
                }
            }
            let end = end.min(bytes.len());
            blank_span(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"'") || rest.starts_with(b"b'") {
            // A char literal only (`'x'`, `'\n'`); a lifetime (`'a`) is left
            // alone — lifetimes carry no braces, strings, or keywords.
            let start = i + usize::from(rest.starts_with(b"b'"));
            let mut end = start + 1;
            if end < bytes.len() && bytes[end] == b'\\' {
                end += 2;
            } else if end < bytes.len() {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b'\'' {
                blank_span(&mut out, i, end + 1);
                i = end + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

/// Shared with the session PIN gates (`session::tests`).
pub(crate) fn strip_rust_comments_only(src: &str) -> String {
    // Like `strip_rust_code`, but blanks COMMENTS only: string contents are
    // preserved (log-macro `{ident}` interpolation lives inside string
    // literals) while comment text cannot forge a match. Newlines and byte
    // offsets are preserved, so spans located on fully-stripped text line up.
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let mut end = i + 2;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            blank_span(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let mut end = i + 2;
            let mut depth = 1;
            while end + 1 < bytes.len() && depth > 0 {
                if bytes[end..].starts_with(b"/*") {
                    depth += 1;
                    end += 2;
                } else if bytes[end..].starts_with(b"*/") {
                    depth -= 1;
                    end += 2;
                } else {
                    end += 1;
                }
            }
            let end = end.min(bytes.len());
            blank_span(&mut out, i, end);
            i = end;
        } else if let Some(len) = raw_string_len(rest) {
            i += len;
        } else if rest.starts_with(b"\"") || rest.starts_with(b"b\"") {
            let mut end = i + usize::from(rest.starts_with(b"b\"")) + 1;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 2;
                } else if bytes[end] == b'"' {
                    end += 1;
                    break;
                } else {
                    end += 1;
                }
            }
            i = end.min(bytes.len());
        } else if rest.starts_with(b"'") || rest.starts_with(b"b'") {
            let start = i + usize::from(rest.starts_with(b"b'"));
            let mut end = start + 1;
            if end < bytes.len() && bytes[end] == b'\\' {
                end += 2;
            } else if end < bytes.len() {
                end += 1;
            }
            i = if end < bytes.len() && bytes[end] == b'\'' { end + 1 } else { i + 1 };
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

/// Proto source with `//` and `/* */` comments and `"..."`
/// (`'...'`-quoted too) option strings blanked to spaces.
fn strip_proto_code(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let mut end = i + 2;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            blank_span(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let mut end = i + 2;
            while end + 1 < bytes.len() && !bytes[end..].starts_with(b"*/") {
                end += 1;
            }
            let end = (end + 2).min(bytes.len());
            blank_span(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"\"") || rest.starts_with(b"'") {
            let quote = bytes[i];
            let mut end = i + 1;
            while end < bytes.len() {
                if bytes[end] == b'\\' {
                    end += 2;
                } else if bytes[end] == quote {
                    end += 1;
                    break;
                } else {
                    end += 1;
                }
            }
            let end = end.min(bytes.len());
            blank_span(&mut out, i, end);
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

fn blank_span(out: &mut [u8], from: usize, to: usize) {
    let len = out.len();
    for b in &mut out[from..to.min(len)] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// Length of the raw string (`r"..."`, `r#"..."#`, `br"..."`) at the start
/// of `rest`, or `None` when `rest` does not start with one.
fn raw_string_len(rest: &[u8]) -> Option<usize> {
    let mut i = 0;
    if rest.first() == Some(&b'b') {
        i += 1;
    }
    if rest.get(i) != Some(&b'r') {
        return None;
    }
    i += 1;
    let mut hashes = 0;
    while rest.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if rest.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < rest.len() {
        if rest[i] == b'"' && rest.get(i + 1..).is_some_and(|t| t.starts_with(&vec![b'#'; hashes]))
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(rest.len())
}

/// List protobuf source files that should feed code generation.
fn proto_source_paths() -> Vec<String> {
    let proto_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/pkcs11-proxy-ng/v1");
    let mut paths: Vec<String> = std::fs::read_dir(&proto_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", proto_dir.display()))
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("proto")).then(|| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                format!("../../proto/pkcs11-proxy-ng/v1/{name}")
            })
        })
        .collect();
    paths.sort();
    paths
}

/// Extract handler delegation lines from the gRPC service implementation.
fn grpc_handler_rpcs() -> Vec<String> {
    parse_grpc_handler_rpcs(include_str!("server/grpc_service/mod.rs"))
}

/// Handler names from the `impl Pkcs11Proxy` block plus the
/// `impl_proxy_service!` invocation tuples of `src`.
fn parse_grpc_handler_rpcs(src: &str) -> Vec<String> {
    // W1-L10-15: brace-matched block + balanced top-level tuple split. The old
    // scan never left the trait impl once triggered, so any `async fn` placed
    // after it (e.g. a later test module) counted as a handler; the block
    // match closes that placement footgun structurally.
    let cleaned = strip_rust_code(src);
    let mut handlers = Vec::new();
    // Only methods inside the `impl Pkcs11Proxy for ...` trait block are RPC
    // handlers. Inherent helpers on the service (e.g. `check_context_owner`)
    // are also `async fn` but must not be counted as handlers.
    if let Some(body) = keyword_block(&cleaned, 0, &["impl", "Pkcs11Proxy", "for"]) {
        for name in async_fn_idents_in(&cleaned[body.0..body.1]) {
            push_unique(&mut handlers, name);
        }
    }
    for name in macro_tuple_first_idents(&cleaned, "impl_proxy_service") {
        push_unique(&mut handlers, name);
    }
    assert!(!handlers.is_empty(), "no gRPC handlers found");
    handlers
}

/// First identifier of each top-level `(name, ...)` group in the last
/// `macro_name!(...)` invocation of `text` (comment/string-stripped).
/// Only lowercase-first idents count, matching the historical rule.
fn macro_tuple_first_idents(text: &str, macro_name: &str) -> Vec<String> {
    // Last invocation (same anchor the old `rsplit_once` used).
    let mut cursor = 0;
    let mut last_open = None;
    while let Some(idx) = find_keyword(text, cursor, macro_name) {
        let mut probe = skip_ws(text, idx + macro_name.len());
        if text.as_bytes().get(probe) == Some(&b'!') {
            probe = skip_ws(text, probe + 1);
            if text.as_bytes().get(probe) == Some(&b'(') {
                last_open = Some(probe);
            }
        }
        cursor = idx + 1;
    }
    let Some(open) = last_open else {
        panic!("{macro_name}! invocation missing");
    };
    let close = skip_balanced(text, open, b'(', b')').expect("balanced macro invocation");
    let inner = &text[open + 1..close - 1];
    let mut names = Vec::new();
    for group in split_top_level(inner) {
        let group = group.trim().trim_start_matches('(');
        if let Some((name, _)) = read_ident(group, 0)
            && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        {
            names.push(name);
        }
    }
    names
}

/// Split `text` on commas at nesting depth 0 (all of `()`, `[]`, `{}` nest).
fn split_top_level(text: &str) -> Vec<&str> {
    let mut groups = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                groups.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        groups.push(tail);
    }
    groups
}

fn push_unique(handlers: &mut Vec<String>, name: String) {
    if !handlers.contains(&name) {
        handlers.push(name);
    }
}

/// Convert snake_case to PascalCase for name comparison.
fn snake_to_pascal(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

/// Convert PascalCase to snake_case.
///
/// Handles acronyms correctly: `AsyncGetID` becomes `async_get_id` (not `async_get_i_d`).
fn pascal_to_snake(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_uppercase() && i > 0 {
            let prev_upper = chars[i - 1].is_uppercase();
            let next_lower = chars.get(i + 1).is_some_and(|c| c.is_lowercase());
            // Insert '_' before an uppercase letter if:
            // - previous char was lowercase (normal word boundary), OR
            // - previous char was uppercase AND next char is lowercase (end of acronym)
            if !prev_upper || next_lower {
                result.push('_');
            }
        }
        result.push(ch.to_lowercase().next().unwrap());
    }
    result
}

/// Scan shim dispatch directory for all `pub unsafe extern "C" fn c_*` functions.
fn shim_dispatch_functions() -> Vec<String> {
    // W1-L10-15: recursive walk of the whole dispatch tree (not just
    // `general/*.rs`), so exports in a new nested module cannot bypass the
    // layer-sync gates.
    let dispatch_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../shim/src/dispatch");
    let mut fns = Vec::new();
    collect_shim_dispatch_fns(&dispatch_dir, &mut fns);
    assert!(!fns.is_empty(), "no shim dispatch functions found");
    fns
}

fn collect_shim_dispatch_fns(dir: &std::path::Path, fns: &mut Vec<String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_shim_dispatch_fns(&path, fns);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            fns.extend(parse_shim_dispatch_fns(&content));
        }
    }
}

/// `c_*` export names declared in one shim dispatch source file: token
/// matches of `extern "C" fn c_<name>(`, tolerant to wrapping and immune to
/// commented-out declarations.
fn parse_shim_dispatch_fns(src: &str) -> Vec<String> {
    let cleaned = strip_rust_code_except_extern_abi(src);
    let mut fns = Vec::new();
    let mut cursor = 0;
    while let Some(idx) = find_keyword(&cleaned, cursor, "extern") {
        cursor = idx + 6;
        // The ABI string is preserved by the stripper: it must read `"C"`.
        let probe = skip_ws(&cleaned, cursor);
        if cleaned[probe..].starts_with("\"C\"") {
            let after_abi = skip_ws(&cleaned, probe + 3);
            if cleaned[after_abi..].starts_with("fn")
                && cleaned.as_bytes().get(after_abi + 2).is_none_or(|b| !is_ident_char(*b))
                && let Some((name, after)) = read_ident(&cleaned, after_abi + 2)
                && name.starts_with("c_")
                && !name.starts_with("c_not_supported")
            {
                let paren = skip_ws(&cleaned, after);
                if cleaned.as_bytes().get(paren) == Some(&b'(') {
                    fns.push(name);
                }
            }
        }
    }
    fns
}

/// Like `strip_rust_code`, but preserves the two bytes of the `"C"` ABI
/// string in `extern "C"` declarations (blanked to a sentinel-free `"C"`);
/// every other comment/string/char is blanked as usual.
fn strip_rust_code_except_extern_abi(src: &str) -> String {
    let mut cleaned = strip_rust_code(src);
    // Restore: find `extern` idents in the ORIGINAL source whose ABI string
    // reads exactly `"C"`, and write it back over the blank at the same
    // offsets (blanking preserves offsets, so positions line up).
    let mut cursor = 0;
    while let Some(idx) = find_keyword(src, cursor, "extern") {
        cursor = idx + 6;
        let probe = skip_ws(src, cursor);
        if src[probe..].starts_with("\"C\"") {
            // SAFETY of indexing: `probe` sits at a `"` (ASCII) by the check.
            cleaned.replace_range(probe..probe + 3, "\"C\"");
        }
    }
    cleaned
}

fn client_method_names() -> Vec<String> {
    fn collect_methods(dir: &std::path::Path, methods: &mut Vec<String>) {
        for entry in
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_methods(&path, methods);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            methods.extend(src.lines().filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("pub async fn ") {
                    let name = trimmed.strip_prefix("pub async fn ")?.split('(').next()?.trim();
                    Some(name.to_string())
                } else {
                    None
                }
            }));
        }
    }

    let client_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/client");
    let mut methods = Vec::new();
    collect_methods(&client_dir, &mut methods);
    methods.sort();
    methods
}

/// Strip `//` comments and `"..."` string contents from one source line so
/// brace counting and keyword detection see code only, not prose.
/// (Hand-written RPC bodies contain comments naming `client_context_id` and
/// `begin_operation`; without stripping, those would misclassify bodies.)
fn code_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    while let Some(ch) = chars.next() {
        if in_string {
            if ch == '\\' {
                chars.next(); // skip escaped char (keeps `\"` from ending the string)
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            break; // line comment: ignore the rest
        }
        out.push(ch);
    }
    out
}

/// One hand-written RPC method: its name plus its source lines (signature
/// through the closing brace). Each line carries the brace depth at line
/// start so nesting checks can tell "inside the scoped block" from "hoisted
/// outside it".
struct HandWrittenRpc {
    name: String,
    /// (raw trimmed line, comment/string-stripped line, brace depth at line start)
    lines: Vec<(String, String, i32)>,
}

/// Extract the hand-written `async fn` methods from the `impl Pkcs11Proxy`
/// block in grpc_service/mod.rs: everything between the trait-impl line and
/// the `$(` line that starts the macro-generated repetition.
fn hand_written_rpcs() -> Vec<HandWrittenRpc> {
    let src = include_str!("server/grpc_service/mod.rs");
    let lines: Vec<&str> = src.lines().collect();
    let mut rpcs = Vec::new();
    let mut i = 0;
    while i < lines.len() && !lines[i].trim().starts_with("impl Pkcs11Proxy for ") {
        i += 1;
    }
    assert!(i < lines.len(), "impl Pkcs11Proxy block not found in grpc_service/mod.rs");
    i += 1;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed == "$(" {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("async fn ") {
            let name = rest.split('(').next().unwrap().trim().to_string();
            let mut body = Vec::new();
            let mut depth: i32 = 0;
            let mut entered = false;
            while i < lines.len() {
                let raw = lines[i].trim().to_string();
                let code = code_only(&raw);
                body.push((raw, code.clone(), depth));
                depth += code.chars().filter(|&c| c == '{').count() as i32;
                depth -= code.chars().filter(|&c| c == '}').count() as i32;
                i += 1;
                if depth > 0 {
                    entered = true;
                }
                if entered && depth == 0 {
                    break;
                }
            }
            assert!(entered, "hand-written RPC {name} has no body block");
            rpcs.push(HandWrittenRpc { name, lines: body });
            continue;
        }
        i += 1;
    }
    assert!(!rpcs.is_empty(), "no hand-written RPCs found in grpc_service/mod.rs");
    rpcs
}

/// A hand-written RPC is context-carrying when its code (comments stripped)
/// touches `client_context_id`. Pre-context RPCs (`initialize`,
/// `get_backend_interfaces`) never do.
fn is_context_carrying(rpc: &HandWrittenRpc) -> bool {
    rpc.lines.iter().any(|(_, code, _)| code.contains("client_context_id"))
}

/// Parse the `HAND_WRITTEN_RPCS` string list from the scoped-dispatch test
/// module in grpc_service/mod.rs. Entries must stay bare `"name",` literals
/// (see that const's doc comment) so this parser keeps working.
fn test_enumerated_rpc_names() -> Vec<String> {
    let src = include_str!("server/grpc_service/mod.rs");
    let mut names = Vec::new();
    let mut in_list = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const HAND_WRITTEN_RPCS") {
            in_list = true;
            continue;
        }
        if in_list {
            if trimmed.starts_with("];") {
                break;
            }
            let entry = trimmed.trim_end_matches(',').trim();
            if let Some(name) = entry.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                names.push(name.to_string());
            } else if !entry.is_empty() {
                panic!("HAND_WRITTEN_RPCS entry is not a bare string literal: {entry:?}");
            }
        }
    }
    assert!(!names.is_empty(), "HAND_WRITTEN_RPCS list not found in grpc_service/mod.rs");
    names
}

#[test]
fn trait_parser_ignores_comments_strings_and_impl_helpers() {
    // W1-L10-15 negative control: formatting drift (commented-out method,
    // `fn` inside a string, helper in an inherent impl, fn-pointer type)
    // must not pollute the trait method set; an attribute-prefixed and a
    // wrapped declaration must still be found.
    let fixture = r#"
pub trait Pkcs11Backend: Send + Sync {
    fn initialize(&self) -> CkResult<()>;
    // fn phantom_disabled(&self);
    #[cfg(unix)] fn single_line_attr(&self);
    fn wrapped
        (&self, slot_id: CkSlotId) -> CkResult<()>;
    fn docs(&self) -> &'static str {
        "fn not_a_method("
    }
}
struct Helper;
impl Helper {
    pub fn impl_helper(&self) {}
}
type Callback = Box<dyn Fn(&str)>;
"#;
    assert_eq!(
        parse_backend_trait_methods(fixture),
        vec!["initialize", "single_line_attr", "wrapped", "docs"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
    );
}

#[test]
fn proto_parser_ignores_comments_options_and_wrapping() {
    // W1-L10-15 negative control: a commented-out RPC, an option string
    // mentioning `rpc`, and a wrapped declaration must parse exactly.
    let fixture = r#"
syntax = "proto3";
service Pkcs11Proxy {
  rpc Initialize(InitializeRequest) returns (InitializeResponse);
  // rpc Phantom(PhantomRequest) returns (PhantomResponse);
  /*
  rpc BlockCommented(BlockRequest) returns (BlockResponse);
  */
  rpc Wrapped(
    WrappedRequest) returns (WrappedResponse);
  option (audit) = "rpc Fake;";
}
"#;
    assert_eq!(
        parse_proto_rpc_names(fixture),
        vec!["Initialize".to_string(), "Wrapped".to_string()],
    );
}

#[test]
fn macro_parser_ignores_comment_parens_and_wrapping() {
    // W1-L10-15 negative control: parens inside comments/strings and
    // multi-line tuples must not confuse the invocation parser; a test
    // `async fn` AFTER the impl block must not count as a handler (the
    // placement footgun documented at grpc_service/mod.rs:263-267).
    let fixture = r#"
macro_rules! impl_proxy_service {
    ($(($name:ident, $request:ident, $response:ident, $module:path)),+ $(,)?) => {
        impl Pkcs11Proxy for Pkcs11ProxyService {
            async fn initialize(&self) -> Status {
                Status::ok(") (")
            }
            $(
                async fn $name(&self) -> Status { Status::ok() }
            )*
        }
    };
}
impl_proxy_service!(
    // comment with (parens) must not shift the parse
    (finalize, FinalizeRequest, FinalizeResponse, general::finalize),
    (
        get_info,
        GetInfoRequest,
        GetInfoResponse,
        general::get_info
    ),
);
#[cfg(test)]
mod later_tests {
    async fn test_helper_after_impl() {}
}
"#;
    assert_eq!(
        parse_grpc_handler_rpcs(fixture),
        vec!["initialize".to_string(), "finalize".to_string(), "get_info".to_string()],
    );
}

#[test]
fn dispatch_parser_tolerates_wrapping_and_recurses() {
    // W1-L10-15 negative control: an `extern "C"` declaration wrapped across
    // lines must still be found; a commented-out export must not.
    let fixture = "pub unsafe extern \"C\"\n    fn c_split(\n        arg: u64,\n    ) -> u64 {\n    arg\n}\n// pub unsafe extern \"C\" fn c_commented() {}\n";
    assert_eq!(parse_shim_dispatch_fns(fixture), vec!["c_split".to_string()]);
}

#[test]
fn proto_build_script_tracks_all_proto_sources() {
    let build_rs = include_str!("../../proto/build.rs");
    for path in proto_source_paths() {
        assert!(
            build_rs.contains(&format!("cargo:rerun-if-changed={path}")),
            "crates/proto/build.rs must rerun when {path} changes"
        );
        assert!(
            build_rs.contains(&format!("\"{path}\"")),
            "crates/proto/build.rs must pass {path} to tonic_prost_build::compile_protos"
        );
    }
}

#[test]
fn backend_methods_have_proto_rpcs() {
    let backend = backend_trait_methods();
    let rpcs = proto_rpc_names();
    let rpc_pascal: Vec<String> = rpcs.iter().map(|r| r.to_lowercase()).collect();

    // Methods exempt from the "must have a matching proto RPC" check, each
    // with its per-item justification (W1-L10-15). The table shrank from 68:
    // `initialize`, `finalize`, `encapsulate_key_exact`, and
    // `get_attribute_value_exact` have same-named proto RPCs, so the mapping
    // check now covers them directly instead of exempting them.
    let exempt: &[(&str, &str)] = &[
        (
            "get_interface_capabilities",
            "provider capability probe served from GetBackendInterfaces, not a PKCS#11 function; no wire method",
        ),
        // ABI advertisement metadata (ADR-0011 D2/D6): carried inside the
        // GetBackendInterfaces response, not PKCS#11 functions.
        ("abi_ulong_size", "D2 advertisement inside GetBackendInterfaces; not a PKCS#11 function"),
        ("abi_byte_order", "D6 advertisement inside GetBackendInterfaces; not a PKCS#11 function"),
        (
            "abi_attribute_stride",
            "D2-extension advertisement inside GetBackendInterfaces; not a PKCS#11 function",
        ),
        // Exact-output trait methods sharing the multiplexed ByteOutputExact RPC.
        ("sign_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("sign_final_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("sign_recover_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("verify_recover_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("digest_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("digest_final_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("encrypt_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("encrypt_exact_with_output", "exact-output variant sharing the ByteOutputExact RPC"),
        ("encrypt_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("encrypt_final_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("decrypt_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("decrypt_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("decrypt_final_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("digest_encrypt_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("decrypt_digest_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("sign_encrypt_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("decrypt_verify_update_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("wrap_key_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        ("wrap_key_exact_with_output", "exact-output variant sharing the ByteOutputExact RPC"),
        ("get_operation_state_exact", "exact-output variant sharing the ByteOutputExact RPC"),
        // Mechanism-out writers sharing their op's existing RPC via
        // `*Response.mechanism_out` (no separate wire method).
        (
            "derive_key_with_output",
            "shares the DeriveKey RPC via DeriveKeyResponse.mechanism_out (e.g. TLS pVersion writeback)",
        ),
        (
            "derive_key_with_output_result",
            "non-throwing result shape over derive_key_with_output; shares the DeriveKey RPC",
        ),
        (
            "generate_key_with_output",
            "shares the GenerateKey RPC via GenerateKeyResponse.mechanism_out (CK_PBE_PARAMS.pInitVector)",
        ),
        // Helper used by the simple Encrypt/Decrypt + Update/Final RPCs to
        // surface HSM-mutated mechanism params. Not its own RPC; populates
        // the `mechanism_out` field of the existing crypto-op responses.
        (
            "session_output_mechanism_params",
            "populates mechanism_out on existing crypto-op responses; not its own RPC",
        ),
        // NULL-mechanism init cancellation is carried by the existing *Init
        // RPCs with `mechanism: None`, not by separate proto methods.
        ("sign_init_cancel", "carried by the SignInit RPC with mechanism: None"),
        ("verify_init_cancel", "carried by the VerifyInit RPC with mechanism: None"),
        ("sign_recover_init_cancel", "carried by the SignRecoverInit RPC with mechanism: None"),
        ("verify_recover_init_cancel", "carried by the VerifyRecoverInit RPC with mechanism: None"),
        ("digest_init_cancel", "carried by the DigestInit RPC with mechanism: None"),
        ("encrypt_init_cancel", "carried by the EncryptInit RPC with mechanism: None"),
        ("decrypt_init_cancel", "carried by the DecryptInit RPC with mechanism: None"),
        // Exact-output trait methods shared via ParameterOutputExact RPC.
        ("encrypt_message_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        ("decrypt_message_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        ("sign_message_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        ("encrypt_message_next_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        ("decrypt_message_next_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        ("sign_message_next_exact", "exact-output variant sharing the ParameterOutputExact RPC"),
        (
            "wrap_key_authenticated_exact",
            "exact-output variant sharing the ParameterOutputExact RPC",
        ),
        // Typed authenticated envelopes reuse the existing authenticated RPCs
        // and ParameterOutputExact rather than introducing function-list slots.
        ("wrap_key_authenticated_typed", "typed envelope reusing the WrapKeyAuthenticated RPC"),
        (
            "wrap_key_authenticated_exact_typed",
            "typed envelope reusing the WrapKeyAuthenticated RPC via ParameterOutputExact",
        ),
        ("unwrap_key_authenticated_typed", "typed envelope reusing the UnwrapKeyAuthenticated RPC"),
        // Batch close via CloseAllSessions RPC.
        ("close_sessions", "batch close sharing the CloseAllSessions RPC"),
        // Structured message parameter variants (also via ParameterOutputExact RPC).
        ("encrypt_message_exact_msg", "structured variant sharing the ParameterOutputExact RPC"),
        ("decrypt_message_exact_msg", "structured variant sharing the ParameterOutputExact RPC"),
        ("sign_message_exact_msg", "structured variant sharing the ParameterOutputExact RPC"),
        (
            "encrypt_message_next_exact_msg",
            "structured variant sharing the ParameterOutputExact RPC",
        ),
        (
            "decrypt_message_next_exact_msg",
            "structured variant sharing the ParameterOutputExact RPC",
        ),
        ("sign_message_next_exact_msg", "structured variant sharing the ParameterOutputExact RPC"),
        // Structured/transactional helpers carried by the named message RPCs,
        // not additional wire methods.
        ("message_encrypt_init_contract", "contract helper carried by the MessageEncryptInit RPC"),
        ("message_decrypt_init_contract", "contract helper carried by the MessageDecryptInit RPC"),
        (
            "encrypt_message_begin_exact",
            "transactional helper carried by the EncryptMessageBegin RPC",
        ),
        (
            "decrypt_message_begin_exact",
            "transactional helper carried by the DecryptMessageBegin RPC",
        ),
        ("encrypt_message_begin_msg", "structured helper carried by the EncryptMessageBegin RPC"),
        ("decrypt_message_begin_msg", "structured helper carried by the DecryptMessageBegin RPC"),
        ("sign_message_begin_exact", "transactional helper carried by the SignMessageBegin RPC"),
        ("sign_message_next_feed_exact", "transactional helper carried by the SignMessageNext RPC"),
        ("verify_message_exact", "exact-output variant carried by the VerifyMessage RPC"),
        (
            "verify_message_begin_exact",
            "transactional helper carried by the VerifyMessageBegin RPC",
        ),
        ("verify_message_next_exact", "transactional helper carried by the VerifyMessageNext RPC"),
        // Drop-path destroy (F-01 Drop-may-never-admit): destructor cleanup
        // rides the enclosing op's exclusion and RPC; never itself on the
        // wire, so no proto method exists for it.
        (
            "destroy_quarantined_object",
            "drop-path destroy riding the enclosing op's RPC; never on the wire (F-01)",
        ),
    ];

    // The exemption list itself must not rot: every entry names a real trait
    // method, and every entry carries a non-empty justification.
    for (method, justification) in exempt {
        assert!(
            backend.iter().any(|m| m == method),
            "stale exemption: `{method}` is not a Pkcs11Backend trait method"
        );
        assert!(!justification.is_empty(), "exemption `{method}` lacks a justification");
    }

    let mut missing = Vec::new();
    for method in &backend {
        if exempt.iter().any(|(name, _)| name == method) {
            continue;
        }
        let pascal = snake_to_pascal(method);
        if !rpcs.contains(&pascal) {
            let lower = method.replace('_', "");
            if !rpc_pascal.iter().any(|r| r == &lower) {
                missing.push(method.as_str());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "Backend trait methods without matching proto RPCs: {:?}\n\
         Backend methods: {:?}\n\
         Proto RPCs: {:?}",
        missing,
        backend,
        rpcs
    );
}

#[test]
fn proto_rpcs_have_grpc_handlers() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();
    let handler_pascal: Vec<String> = handlers.iter().map(|h| snake_to_pascal(h)).collect();

    let mut missing = Vec::new();
    for rpc in &rpcs {
        // Case-insensitive comparison: tonic lowercases acronyms like ID → Id
        let rpc_lower = rpc.to_lowercase();
        if !handler_pascal.iter().any(|h| h.to_lowercase() == rpc_lower) {
            missing.push(rpc.as_str());
        }
    }
    assert!(
        missing.is_empty(),
        "Proto RPCs without gRPC handler: {:?}\n\
         Proto RPCs: {:?}\n\
         Handlers: {:?}",
        missing,
        rpcs,
        handlers
    );
}

#[test]
fn grpc_handlers_have_proto_rpcs() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();

    let mut orphaned = Vec::new();
    for handler in &handlers {
        let pascal = snake_to_pascal(handler);
        // Case-insensitive: tonic lowercases acronyms like ID → Id
        let pascal_lower = pascal.to_lowercase();
        if !rpcs.iter().any(|r| r.to_lowercase() == pascal_lower) {
            orphaned.push(handler.as_str());
        }
    }
    assert!(orphaned.is_empty(), "gRPC handlers without matching proto RPC: {:?}", orphaned);
}

#[test]
fn proto_rpc_count_matches_handler_count() {
    let rpcs = proto_rpc_names();
    let handlers = grpc_handler_rpcs();
    assert_eq!(
        rpcs.len(),
        handlers.len(),
        "Proto has {} RPCs but gRPC service has {} handlers.\n\
         RPCs: {:?}\n\
         Handlers: {:?}",
        rpcs.len(),
        handlers.len(),
        rpcs,
        handlers
    );
}

#[test]
fn config_proxy_fields_all_have_defaults() {
    let config = crate::config::ProxyConfig::default();
    // mechanism_discovery is kept for backward-compatible config parsing but is
    // ignored at runtime (server is now a pure proxy for mechanism discovery).
    assert_eq!(config.mechanism_discovery, crate::config::MechanismDiscovery::Transparent);
    assert!(config.lease_seconds > 0);
    assert!(config.max_message_bytes > 0);
    assert!(config.request_timeout_secs > 0);
    assert!(config.max_concurrent_backend_calls > 0);
    assert!(config.max_blocking_threads > 0);
    assert!(config.max_concurrent_backend_calls <= config.max_blocking_threads);
}

// Public docs ship INSIDE this repository (doc/, prd.md, README.md). These
// checks verify the released repo is self-describing: they resolve paths from
// the repo root and no longer reach into any outer planning workspace, so they
// pass in a standalone clone of this repository.

/// Repo root, derived from the server crate's manifest dir
/// (`<repo>/crates/server`).
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn public_docs_present() {
    let root = repo_root();
    for rel in ["README.md", "prd.md", "doc/architecture-overview.md", "doc/adr/README.md"] {
        let path = root.join(rel);
        assert!(path.exists(), "public doc missing: {} (expected at {})", rel, path.display());
    }
}

#[test]
fn adr_index_covers_every_numbered_adr() {
    let root = repo_root();
    let index = std::fs::read_to_string(root.join("doc/adr/README.md")).unwrap();
    for entry in std::fs::read_dir(root.join("doc/adr")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.starts_with("ADR-") && name.ends_with(".md") {
            assert!(index.contains(&format!("]({name})")), "ADR index does not link {name}");
        }
    }
}

#[test]
fn generated_support_table_is_complete() {
    let rpcs = proto_rpc_names();
    let backend = backend_trait_methods();
    let handlers = grpc_handler_rpcs();
    let shim_fns = shim_dispatch_functions();

    // RPCs exempt from shim/client alignment checks.
    // - GetBackendInterfaces: proxy-internal RPC (BUG-001) that doesn't correspond
    //   to a PKCS#11 C_ function — called by the shim's interface_probe module.
    // - GetAttributeValueExact: exact-output RPC called internally from existing
    //   shim c_get_attribute_value, not a separate extern "C" function.
    // - ByteOutputExact: multiplexed exact-output RPC called internally from existing
    //   shim c_sign/c_encrypt/etc., not a separate extern "C" function.
    let exempt_rpcs: [&str; 5] = [
        "GetBackendInterfaces",
        "GetAttributeValueExact",
        "ByteOutputExact",
        "ParameterOutputExact",
        "EncapsulateKeyExact",
    ];

    let mut missing_shim = Vec::new();
    for rpc in &rpcs {
        if exempt_rpcs.contains(&rpc.as_str()) {
            continue;
        }
        let c_fn = format!("c_{}", pascal_to_snake(rpc));
        if !shim_fns.iter().any(|f| f == &c_fn) {
            missing_shim.push(format!("{rpc} (expected {c_fn})"));
        }
    }
    assert!(
        missing_shim.is_empty(),
        "Proto RPCs without shim C_ function: {:?}\n\
         Shim functions: {:?}",
        missing_shim,
        shim_fns
    );

    let client_methods = client_method_names();

    let non_exempt_rpc_count = rpcs.len() - exempt_rpcs.len();
    assert!(backend.len() >= 2, "Backend should have methods");
    assert_eq!(rpcs.len(), handlers.len(), "Proto RPCs and handlers must match");
    assert!(
        shim_fns.len() >= non_exempt_rpc_count,
        "Shim should have at least {} C_ functions (has {})",
        non_exempt_rpc_count,
        shim_fns.len()
    );
    // Client methods must cover at least the non-exempt RPCs.
    // Exempt RPCs (3.x functions) get client methods in later implementation waves.
    assert!(
        client_methods.len() >= non_exempt_rpc_count,
        "Client should have at least {} methods (has {})\n\
         Client methods: {:?}",
        non_exempt_rpc_count,
        client_methods.len(),
        client_methods
    );
}

fn example_config_with_existing_placeholder_paths(content: &str, stub_path: &str) -> String {
    let mut value: toml::Value = toml::from_str(content).expect("example config TOML");
    // T2run win32: the caller passes a freshly-created 0600 stub file —
    // `/dev/null` does not exist on Windows and red-lined this test there,
    // and `load()` perm-guards the module path (with a `/dev/null`-only
    // exemption), so the stub must be a tight-permissioned real file.
    // Serialization re-escapes Windows backslashes automatically.
    let existing_stub = || toml::Value::String(stub_path.to_string());

    if let Some(backend) = value.get_mut("backend").and_then(toml::Value::as_table_mut) {
        backend.insert("module".to_string(), existing_stub());
    }

    if let Some(remote) = value
        .get_mut("listener")
        .and_then(toml::Value::as_table_mut)
        .and_then(|listener| listener.get_mut("remote"))
        .and_then(toml::Value::as_table_mut)
    {
        for key in ["ca_cert", "server_cert", "server_key"] {
            if remote.contains_key(key) {
                remote.insert(key.to_string(), existing_stub());
            }
        }
    }

    toml::to_string(&value).expect("serialize normalized example config")
}

#[test]
fn example_configs_parse_and_validate_without_errors() {
    let examples_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    assert!(examples_dir.exists(), "examples/ directory must exist: {}", examples_dir.display());
    let tempdir = tempfile::tempdir().expect("tempdir for normalized example configs");
    // Tight-permissioned stub satisfying both the existence check in
    // `validate()` and the perm guard in `load()` on every platform.
    let stub_path = tempdir.path().join("module.stub");
    std::fs::write(&stub_path, b"T2run existing-path stub")
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", stub_path.display()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", stub_path.display()));
    }
    let stub_path = stub_path.to_str().expect("stub path must be UTF-8").to_string();
    let mut count = 0;
    for entry in std::fs::read_dir(&examples_dir).expect("cannot read examples/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            // Skip non-daemon-config TOML files (mechanism overrides, etc.)
            if !name.starts_with("config") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let normalized = example_config_with_existing_placeholder_paths(&content, &stub_path);
            let normalized_path = tempdir
                .path()
                .join(std::path::Path::new(path.file_name().expect("example config file name")));
            std::fs::write(&normalized_path, normalized)
                .unwrap_or_else(|e| panic!("cannot write {}: {e}", normalized_path.display()));
            // The perm-guard in load() rejects group/world-writable files.
            // Temp files created by std::fs::write use the process umask and
            // may be 0664; set them to 0600 so the check passes here.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&normalized_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|e| panic!("cannot chmod {}: {e}", normalized_path.display()));
            }
            let _config = crate::config::DaemonConfig::load(&normalized_path)
                .unwrap_or_else(|e| panic!("{} failed to validate: {e}", path.display()));
            count += 1;
        }
    }
    assert!(count >= 3, "examples/ should have at least 3 reference configs, found {count}");
}

/// I-1 (W1-L6-01 follow-up): the scoped-dispatch test enumeration must cover
/// exactly the hand-written, context-carrying RPCs in the trait impl — a 10th
/// hand-written RPC (or a removal) must fail here, never silently drop
/// coverage. The two pre-context RPCs are pinned as explicit exemptions so a
/// new unguarded-looking method also forces triage instead of passing quietly.
#[test]
fn hand_written_context_rpcs_match_test_enumeration() {
    let rpcs = hand_written_rpcs();
    let impl_names: BTreeSet<&str> =
        rpcs.iter().filter(|rpc| is_context_carrying(rpc)).map(|rpc| rpc.name.as_str()).collect();
    let listed_vec = test_enumerated_rpc_names();
    let listed: BTreeSet<&str> = listed_vec.iter().map(String::as_str).collect();
    let missing_from_tests: Vec<&&str> = impl_names.difference(&listed).collect();
    let extra_in_tests: Vec<&&str> = listed.difference(&impl_names).collect();

    let all_impl: BTreeSet<&str> = rpcs.iter().map(|rpc| rpc.name.as_str()).collect();
    let mut expected_all = listed.clone();
    expected_all.insert("initialize");
    expected_all.insert("get_backend_interfaces");
    let untriaged: Vec<&&str> = all_impl.difference(&expected_all).collect();
    let stale_exempt: Vec<&&str> = expected_all.difference(&all_impl).collect();

    assert!(
        missing_from_tests.is_empty()
            && extra_in_tests.is_empty()
            && untriaged.is_empty()
            && stale_exempt.is_empty(),
        "HAND_WRITTEN_RPCS drift vs trait impl:\n\
         in impl but not tested: {missing_from_tests:?}\n\
         tested but not in impl: {extra_in_tests:?}\n\
         hand-written but neither tested nor exempt: {untriaged:?}\n\
         exempt/tested but no longer hand-written: {stale_exempt:?}\n\
         impl context-carrying fns: {impl_names:?}\n\
         HAND_WRITTEN_RPCS: {listed:?}"
    );
}

/// I-2 (W1-L6-01 follow-up): every hand-written, context-carrying RPC body
/// must route its handler call through exactly one `run_context_scoped` — the
/// `*_with_policy` handler invocation must sit INSIDE the scoped async block
/// (later line, deeper brace depth than the `run_context_scoped(` line), so a
/// future edit cannot keep M2 admission while hoisting the handler outside
/// the scope.
#[test]
fn hand_written_context_rpcs_route_through_scope_guard() {
    let rpcs = hand_written_rpcs();
    let mut failures = Vec::new();
    for rpc in &rpcs {
        if !is_context_carrying(rpc) {
            continue;
        }
        let scoped: Vec<(usize, i32)> = rpc
            .lines
            .iter()
            .enumerate()
            .filter(|(_, (_, code, _))| code.contains("run_context_scoped("))
            .map(|(idx, (_, _, depth))| (idx, *depth))
            .collect();
        if scoped.len() != 1 {
            failures.push(format!(
                "{}: expected exactly one `run_context_scoped(` call, found {}",
                rpc.name,
                scoped.len()
            ));
            continue;
        }
        let (scoped_idx, scoped_depth) = scoped[0];
        let handler_calls: Vec<(usize, i32)> = rpc
            .lines
            .iter()
            .enumerate()
            .filter(|(_, (_, code, _))| code.contains("_with_policy("))
            .map(|(idx, (_, _, depth))| (idx, *depth))
            .collect();
        if handler_calls.is_empty() {
            failures.push(format!(
                "{}: no `*_with_policy(` handler call found in body — if the handler \
                 was renamed, extend this scanner's handler-call marker",
                rpc.name
            ));
            continue;
        }
        for (idx, depth) in handler_calls {
            if idx <= scoped_idx || depth <= scoped_depth {
                failures.push(format!(
                    "{}: handler call on body line {} is not nested inside the \
                     `run_context_scoped` async block (handler depth {depth} vs \
                     scoped-call depth {scoped_depth})",
                    rpc.name,
                    idx + 1,
                ));
            }
        }
    }
    assert!(failures.is_empty(), "scope-guard routing drift:\n  {}", failures.join("\n  "));
}
