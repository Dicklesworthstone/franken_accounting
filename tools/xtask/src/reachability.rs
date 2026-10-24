//! `xtask reachability` (bead fa-2ioe): which library modules the surfaces
//! reach.
//!
//! Every non-test source file of the surfaces (fa-cli, fad, fa-mcp,
//! fa-verify) and the gate tools (xtask, registry-check) is reached. A module
//! file of crate C becomes reached when a reached file F references it:
//! - F imports (`use`) or path-qualifies, from C or from a crate that
//!   re-exports C, the module's last path segment or one of its top-level
//!   pub item names;
//! - F glob-imports the module (or C's root) and its code names one of the
//!   module's items;
//! - F is in C and its code names the module's segment before `::`, or one
//!   of its top-level items that no other file of C defines;
//! - F's code calls (`.name(`) a pub method of the module whose name only C
//!   defines as a method.
//!
//! Comments, string and char literals, `#[cfg(test)]` items, and `use`/`mod`
//! declarations are not references. The analysis reads tokens, not types,
//! so it can over-approximate reach (a shared name) but a module it calls
//! unreached is named by nothing reachable. A pub module or crate root of
//! a library crate (layers foundation through surface) with pub items or
//! methods of its own that stays unreached needs a row in
//! registries/unwired_modules.toml; one of trait impls or re-exports alone
//! has nothing to name and is not reported.

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::topology::Topology;
use fa_registry::unwired_modules::UnwiredModules;

/// The surfaces and gate tools whose code is reached by definition.
pub const ROOTS: [&str; 6] = [
    "fa-cli",
    "fad",
    "fa-mcp",
    "fa-verify",
    "xtask",
    "registry-check",
];

/// The layers whose modules must be reached or registered.
pub const SCANNED_LAYERS: [&str; 9] = [
    "foundation",
    "model",
    "laws",
    "kernel",
    "evidence",
    "analytics",
    "governance",
    "interop",
    "surface",
];

/// One crate of the workspace as the analysis sees it.
#[derive(Clone, Debug)]
pub struct CrateSpec {
    pub name: String,
    pub layer: String,
    /// Workspace-relative crate directory.
    pub path: String,
}

/// A library module and whether anything reachable references it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleReach {
    /// `crate_ident::seg::seg`, or the ident alone for a crate root.
    pub path: String,
    /// Workspace-relative source file.
    pub file: String,
    pub lines: usize,
    pub reached: bool,
}

/// The workspace's crate list from the topology registry (present crates).
pub fn workspace_crates() -> Result<Vec<CrateSpec>, String> {
    let topo = Topology::embedded().map_err(|e| e.to_string())?;
    Ok(topo
        .crates
        .into_iter()
        .filter(|c| !c.planned)
        .map(|c| CrateSpec {
            name: c.name,
            layer: c.layer,
            path: c.path,
        })
        .collect())
}

// ---- lexing and tokens ------------------------------------------------------

/// The source with comments, string and char literals blanked (newlines
/// kept, so lines and columns hold).
fn lex(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let n = c.len();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, s: &[char]| {
        for ch in s {
            out.push(if *ch == '\n' { '\n' } else { ' ' });
        }
    };
    let mut i = 0;
    while i < n {
        let prev_ident = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
        if c[i] == '/' && i + 1 < n && c[i + 1] == '/' {
            let mut j = i;
            while j < n && c[j] != '\n' {
                j += 1;
            }
            blank(&mut out, &c[i..j]);
            i = j;
        } else if c[i] == '/' && i + 1 < n && c[i + 1] == '*' {
            let (mut depth, mut j) = (1, i + 2);
            while j < n && depth > 0 {
                if c[j] == '/' && j + 1 < n && c[j + 1] == '*' {
                    depth += 1;
                    j += 2;
                } else if c[j] == '*' && j + 1 < n && c[j + 1] == '/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, &c[i..j.min(n)]);
            i = j.min(n);
        } else if !prev_ident && let Some(j) = raw_string_end(&c, i) {
            blank(&mut out, &c[i..j]);
            i = j;
        } else if c[i] == '"' || (!prev_ident && c[i] == 'b' && i + 1 < n && c[i + 1] == '"') {
            let mut j = i + if c[i] == 'b' { 2 } else { 1 };
            while j < n && c[j] != '"' {
                j += if c[j] == '\\' { 2 } else { 1 };
            }
            let j = (j + 1).min(n);
            blank(&mut out, &c[i..j]);
            i = j;
        } else if c[i] == '\'' || (!prev_ident && c[i] == 'b' && i + 1 < n && c[i + 1] == '\'') {
            let k = i + usize::from(c[i] == 'b');
            if k + 1 < n && c[k + 1] == '\\' {
                let mut j = k + 3;
                while j < n && c[j] != '\'' {
                    j += 1;
                }
                let j = (j + 1).min(n);
                blank(&mut out, &c[i..j]);
                i = j;
            } else if k + 2 < n && c[k + 2] == '\'' {
                blank(&mut out, &c[i..k + 3]);
                i = k + 3;
            } else {
                out.push(c[i]);
                i += 1;
            }
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

/// End (exclusive) of a raw string literal `r#*"…"#*` or `br#*"…"#*` at `i`.
fn raw_string_end(c: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    if c.get(j) == Some(&'b') {
        j += 1;
    }
    if c.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while c.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    if c.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < c.len() {
        if c[j] == '"' && (1..=hashes).all(|h| c.get(j + h) == Some(&'#')) {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(c.len())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    PathSep,
    Punct(char),
}

#[derive(Clone, Debug)]
struct Token {
    tok: Tok,
    /// First character of its line (no indentation).
    col0: bool,
}

fn tokens(lexed: &str) -> Vec<Token> {
    let c: Vec<char> = lexed.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let col0 = i == 0 || c[i - 1] == '\n';
        if c[i].is_whitespace() {
            i += 1;
        } else if c[i].is_alphabetic() || c[i] == '_' {
            let start = i;
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(Token {
                tok: Tok::Ident(c[start..i].iter().collect()),
                col0,
            });
        } else if c[i].is_ascii_digit() {
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                i += 1;
            }
        } else if c[i] == ':' && c.get(i + 1) == Some(&':') {
            out.push(Token {
                tok: Tok::PathSep,
                col0,
            });
            i += 2;
        } else {
            out.push(Token {
                tok: Tok::Punct(c[i]),
                col0,
            });
            i += 1;
        }
    }
    out
}

fn is_ident(t: &Token, s: &str) -> bool {
    matches!(&t.tok, Tok::Ident(x) if x == s)
}

fn is_punct(t: &Token, ch: char) -> bool {
    t.tok == Tok::Punct(ch)
}

fn ident_of(t: &Token) -> Option<&str> {
    match &t.tok {
        Tok::Ident(x) => Some(x),
        _ => None,
    }
}

/// Index just past the bracket group opening at `open` (`(`, `[` or `{`).
fn group_end(toks: &[Token], open: usize) -> usize {
    let (o, cl) = match toks[open].tok {
        Tok::Punct('(') => ('(', ')'),
        Tok::Punct('[') => ('[', ']'),
        _ => ('{', '}'),
    };
    let mut depth = 0usize;
    let mut j = open;
    while j < toks.len() {
        if is_punct(&toks[j], o) {
            depth += 1;
        } else if is_punct(&toks[j], cl) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return j + 1;
            }
        }
        j += 1;
    }
    toks.len()
}

/// Tokens with every `#[cfg(test)]`-gated item removed.
fn strip_cfg_test(toks: Vec<Token>) -> Vec<Token> {
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        let gated = i + 6 < toks.len()
            && is_punct(&toks[i], '#')
            && is_punct(&toks[i + 1], '[')
            && is_ident(&toks[i + 2], "cfg")
            && is_punct(&toks[i + 3], '(')
            && is_ident(&toks[i + 4], "test")
            && is_punct(&toks[i + 5], ')')
            && is_punct(&toks[i + 6], ']');
        if !gated {
            out.push(toks[i].clone());
            i += 1;
            continue;
        }
        // Skip to the end of the gated item: its `;` or body's `}`; for a
        // gated field, arm or statement, its `,` or the enclosing block's
        // `}` (which stays).
        let mut j = i + 7;
        while j < toks.len() {
            if is_punct(&toks[j], ';') || is_punct(&toks[j], ',') {
                j += 1;
                break;
            }
            if is_punct(&toks[j], '}') {
                break;
            }
            if is_punct(&toks[j], '{') {
                j = group_end(&toks, j);
                break;
            }
            if is_punct(&toks[j], '(') || is_punct(&toks[j], '[') {
                j = group_end(&toks, j);
                continue;
            }
            j += 1;
        }
        i = j;
    }
    out
}

// ---- per-file facts ---------------------------------------------------------

/// What one source file declares and references.
#[derive(Clone, Debug, Default)]
struct FileFacts {
    /// `mod name;` children: (name, bare `pub`, has `#[path]`).
    mods: Vec<(String, bool, bool)>,
    /// Top-level `pub` items (column 0) and exported macros.
    items: BTreeSet<String>,
    /// Indented `pub fn` names (methods and nested items).
    methods: BTreeSet<String>,
    /// Identifiers in code outside `use` and `mod` declarations.
    words: BTreeSet<String>,
    /// Identifiers directly followed by `::` in code.
    paths: BTreeSet<String>,
    /// Names called as `.name(` or `.name::<`.
    calls: BTreeSet<String>,
    /// For each path root, the names after it in qualified paths.
    qualified: BTreeMap<String, BTreeSet<String>>,
    /// Every identifier, `use` declarations included.
    all_words: BTreeSet<String>,
    /// `use` trees expanded into leaf paths; `*` kept as a segment.
    uses: Vec<Vec<String>>,
    /// Leaf paths of `pub use` trees.
    pub_uses: Vec<Vec<String>>,
}

fn file_facts(text: &str) -> FileFacts {
    let toks = strip_cfg_test(tokens(&lex(text)));
    let mut f = FileFacts::default();
    let mut body: Vec<&Token> = Vec::with_capacity(toks.len());
    let mut i = 0;
    let mut export_macro = false;
    while i < toks.len() {
        let t = &toks[i];
        if let Some(w) = ident_of(t) {
            f.all_words.insert(w.to_string());
        }
        // Visibility prefix: `pub` or `pub(…)`.
        let (vis_end, bare_pub) = if is_ident(t, "pub") {
            if toks.get(i + 1).is_some_and(|n| is_punct(n, '(')) {
                (group_end(&toks, i + 1), false)
            } else {
                (i + 1, true)
            }
        } else {
            (i, false)
        };
        let has_vis = vis_end > i;
        if toks.get(vis_end).is_some_and(|n| is_ident(n, "use")) {
            let end = (vis_end..toks.len())
                .find(|&j| is_punct(&toks[j], ';'))
                .unwrap_or(toks.len());
            for tk in &toks[vis_end..end] {
                if let Some(w) = ident_of(tk) {
                    f.all_words.insert(w.to_string());
                }
            }
            let leaves = use_leaves(&toks[vis_end + 1..end]);
            if has_vis {
                f.pub_uses.extend(leaves.iter().cloned());
            }
            f.uses.extend(leaves);
            i = end + 1;
            continue;
        }
        if toks.get(vis_end).is_some_and(|n| is_ident(n, "mod"))
            && let Some(name) = toks.get(vis_end + 1).and_then(ident_of)
            && toks.get(vis_end + 2).is_some_and(|n| is_punct(n, ';'))
        {
            let has_path = attr_before(&toks, i, "path");
            f.mods.push((name.to_string(), bare_pub, has_path));
            f.all_words.insert(name.to_string());
            i = vis_end + 3;
            continue;
        }
        if has_vis && let Some((name, kind)) = item_name(&toks, vis_end) {
            if t.col0 && bare_pub {
                f.items.insert(name);
            } else if !t.col0 && kind == "fn" {
                f.methods.insert(name);
            }
        }
        if is_ident(t, "macro_export") {
            export_macro = true;
        }
        if export_macro
            && is_ident(t, "macro_rules")
            && toks.get(i + 1).is_some_and(|n| is_punct(n, '!'))
            && let Some(name) = toks.get(i + 2).and_then(ident_of)
        {
            f.items.insert(name.to_string());
            export_macro = false;
        }
        body.push(t);
        i += 1;
    }
    for (k, t) in body.iter().enumerate() {
        let Some(w) = ident_of(t) else { continue };
        f.words.insert(w.to_string());
        let next = body.get(k + 1);
        if next.is_some_and(|n| n.tok == Tok::PathSep) {
            f.paths.insert(w.to_string());
            let mut chain = BTreeSet::new();
            let mut j = k + 1;
            while body.get(j).is_some_and(|n| n.tok == Tok::PathSep)
                && let Some(seg) = body.get(j + 1).and_then(|n| ident_of(n))
            {
                chain.insert(seg.to_string());
                j += 2;
            }
            f.qualified.entry(w.to_string()).or_default().extend(chain);
        }
        let after_dot = k > 0 && is_punct(body[k - 1], '.');
        let called = next.is_some_and(|n| is_punct(n, '('))
            || (next.is_some_and(|n| n.tok == Tok::PathSep)
                && body.get(k + 2).is_some_and(|n| is_punct(n, '<')));
        if after_dot && called {
            f.calls.insert(w.to_string());
        }
    }
    f
}

/// Whether an attribute named `name` directly precedes the item at `i`.
fn attr_before(toks: &[Token], i: usize, name: &str) -> bool {
    let mut j = i;
    while j >= 2 && is_punct(&toks[j - 1], ']') {
        // Walk back to this attribute's `#[`.
        let mut k = j - 1;
        let mut depth = 0usize;
        loop {
            if is_punct(&toks[k], ']') {
                depth += 1;
            } else if is_punct(&toks[k], '[') {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            if k == 0 {
                return false;
            }
            k -= 1;
        }
        if k == 0 || !is_punct(&toks[k - 1], '#') {
            return false;
        }
        if toks.get(k + 1).is_some_and(|t| is_ident(t, name)) {
            return true;
        }
        j = k - 1;
    }
    false
}

/// The item declared at `i` (after visibility): its name and kind
/// (`fn`, or the item keyword).
fn item_name(toks: &[Token], mut i: usize) -> Option<(String, &'static str)> {
    while toks
        .get(i)
        .is_some_and(|t| is_ident(t, "async") || is_ident(t, "unsafe") || is_ident(t, "extern"))
    {
        i += 1;
    }
    if toks.get(i).is_some_and(|t| is_ident(t, "const"))
        && toks.get(i + 1).is_some_and(|t| is_ident(t, "fn"))
    {
        i += 1;
    }
    let kind = match toks.get(i).and_then(ident_of)? {
        "fn" => "fn",
        "struct" => "struct",
        "enum" => "enum",
        "trait" => "trait",
        "type" => "type",
        "const" => "const",
        "static" => "static",
        "union" => "union",
        _ => return None,
    };
    let name = toks.get(i + 1).and_then(ident_of)?;
    Some((name.to_string(), kind))
}

/// A `use` tree (the tokens after `use`) expanded into leaf paths.
fn use_leaves(toks: &[Token]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut i = 0;
    expand_use(toks, &mut i, Vec::new(), &mut out);
    out
}

fn expand_use(toks: &[Token], i: &mut usize, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    let mut path = prefix;
    loop {
        match toks.get(*i).map(|t| &t.tok) {
            Some(Tok::PathSep) => *i += 1,
            Some(Tok::Ident(w)) if w == "as" => {
                *i += 2;
                out.push(path);
                return;
            }
            Some(Tok::Ident(w)) => {
                path.push(w.clone());
                *i += 1;
            }
            Some(Tok::Punct('*')) => {
                path.push("*".into());
                *i += 1;
                out.push(path);
                return;
            }
            Some(Tok::Punct('{')) => {
                *i += 1;
                loop {
                    match toks.get(*i).map(|t| &t.tok) {
                        None => return,
                        Some(Tok::Punct('}')) => {
                            *i += 1;
                            return;
                        }
                        Some(Tok::Punct(',')) => *i += 1,
                        _ => expand_use(toks, i, path.clone(), out),
                    }
                }
            }
            _ => {
                out.push(path);
                return;
            }
        }
    }
}

// ---- the workspace graph ----------------------------------------------------

struct ModFile {
    ident: String,
    crate_name: String,
    modpath: Vec<String>,
    public: bool,
    file: String,
    lines: usize,
    facts: FileFacts,
    imported: BTreeMap<String, BTreeSet<String>>,
    globs: BTreeMap<String, Vec<Vec<String>>>,
}

impl ModFile {
    fn display_path(&self) -> String {
        std::iter::once(self.ident.as_str())
            .chain(self.modpath.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("::")
    }
}

/// Every module file of a crate, walked from `src/lib.rs` and `src/main.rs`
/// through `mod name;` declarations (`#[cfg(test)]` and `#[path]` ones are
/// not walked).
fn crate_files(spec: &CrateSpec, read: &dyn Fn(&str) -> Option<String>) -> Vec<ModFile> {
    let ident = spec.name.replace('-', "_");
    let mut out = Vec::new();
    let mut stack: Vec<(String, Vec<String>, bool, String)> = Vec::new();
    for (root, modpath) in [
        ("lib.rs", Vec::new()),
        ("main.rs", vec!["<main>".to_string()]),
    ] {
        stack.push((
            format!("{}/src/{root}", spec.path),
            modpath,
            true,
            format!("{}/src", spec.path),
        ));
    }
    while let Some((file, modpath, public, dir)) = stack.pop() {
        let Some(text) = read(&file) else { continue };
        let facts = file_facts(&text);
        for (name, pubm, has_path) in facts.mods.iter().rev() {
            if *has_path {
                continue;
            }
            let flat = format!("{dir}/{name}.rs");
            let nested = format!("{dir}/{name}/mod.rs");
            let child = if read(&flat).is_some() { flat } else { nested };
            let mut p = modpath.clone();
            p.push(name.clone());
            stack.push((child, p, public && *pubm, format!("{dir}/{name}")));
        }
        out.push(ModFile {
            ident: ident.clone(),
            crate_name: spec.name.clone(),
            modpath,
            public,
            file,
            lines: text.lines().count(),
            facts,
            imported: BTreeMap::new(),
            globs: BTreeMap::new(),
        });
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

/// Reach every library module of `crates` from the root crates' code.
pub fn analyze(crates: &[CrateSpec], read: &dyn Fn(&str) -> Option<String>) -> Vec<ModuleReach> {
    let mut files: Vec<ModFile> = crates.iter().flat_map(|c| crate_files(c, read)).collect();
    let idents: BTreeSet<String> = crates.iter().map(|c| c.name.replace('-', "_")).collect();
    let layer: BTreeMap<String, &str> = crates
        .iter()
        .map(|c| (c.name.clone(), c.layer.as_str()))
        .collect();

    for f in &mut files {
        for leaf in &f.facts.uses {
            let Some(first) = leaf.first() else { continue };
            let root = if matches!(first.as_str(), "crate" | "self" | "super") {
                f.ident.clone()
            } else if idents.contains(first) {
                first.clone()
            } else {
                continue;
            };
            let rest: Vec<String> = leaf[1..]
                .iter()
                .filter(|s| !matches!(s.as_str(), "self" | "super" | "crate"))
                .cloned()
                .collect();
            if rest.last().is_some_and(|s| s == "*") {
                f.globs
                    .entry(root.clone())
                    .or_default()
                    .push(rest[..rest.len() - 1].to_vec());
            }
            f.imported
                .entry(root)
                .or_default()
                .extend(rest.into_iter().filter(|s| s != "*"));
        }
    }

    // Crate D re-exports crate C when a file of D holds `pub use C::…`.
    let mut reexports: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in &files {
        for leaf in &f.facts.pub_uses {
            if let Some(first) = leaf.first()
                && idents.contains(first)
                && *first != f.ident
            {
                reexports
                    .entry(f.ident.clone())
                    .or_default()
                    .insert(first.clone());
            }
        }
    }
    // reexported_by[C]: every crate D (C included) through which C's names
    // can be imported.
    let mut reexported_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for d in &idents {
        let mut seen = BTreeSet::from([d.clone()]);
        let mut stack = vec![d.clone()];
        while let Some(x) = stack.pop() {
            for e in reexports.get(&x).into_iter().flatten() {
                if seen.insert(e.clone()) {
                    stack.push(e.clone());
                }
            }
        }
        for c in seen {
            reexported_by.entry(c).or_default().insert(d.clone());
        }
    }

    let mut method_definers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut crate_definers: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for f in &files {
        for m in &f.facts.methods {
            method_definers
                .entry(m.as_str())
                .or_default()
                .insert(f.ident.as_str());
        }
        for it in &f.facts.items {
            *crate_definers
                .entry((f.ident.as_str(), it.as_str()))
                .or_default() += 1;
        }
    }

    let hit = |f: &ModFile, m: &ModFile| -> bool {
        let empty = BTreeSet::new();
        let via = reexported_by.get(&m.ident).unwrap_or(&empty);
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for d in via {
            for n in f.imported.get(d).into_iter().flatten() {
                names.insert(n);
            }
            for n in f.facts.qualified.get(d).into_iter().flatten() {
                names.insert(n);
            }
        }
        if f.ident == m.ident {
            for k in ["crate", "self", "super"] {
                for n in f.facts.qualified.get(k).into_iter().flatten() {
                    names.insert(n);
                }
            }
        }
        if m.modpath
            .last()
            .is_some_and(|seg| names.contains(seg.as_str()))
        {
            return true;
        }
        if m.facts.items.iter().any(|n| names.contains(n.as_str())) {
            return true;
        }
        for d in via {
            for g in f.globs.get(d).into_iter().flatten() {
                if (g.is_empty() || (*d == m.ident && *g == m.modpath))
                    && m.facts.items.iter().any(|n| f.facts.words.contains(n))
                {
                    return true;
                }
            }
        }
        if f.ident == m.ident {
            if m.modpath
                .last()
                .is_some_and(|seg| f.facts.paths.contains(seg))
            {
                return true;
            }
            if m.facts.items.iter().any(|n| {
                crate_definers.get(&(m.ident.as_str(), n.as_str())) == Some(&1)
                    && f.facts.words.contains(n)
            }) {
                return true;
            }
        }
        m.facts.methods.iter().any(|n| {
            f.facts.calls.contains(n)
                && method_definers
                    .get(n.as_str())
                    .is_some_and(|d| d.len() == 1 && d.contains(m.ident.as_str()))
        })
    };

    let is_root = |f: &ModFile| ROOTS.contains(&f.crate_name.as_str());
    let mut reached = vec![false; files.len()];
    let mut frontier: Vec<usize> = Vec::new();
    for (k, f) in files.iter().enumerate() {
        if is_root(f) {
            reached[k] = true;
            frontier.push(k);
        }
    }
    while let Some(k) = frontier.pop() {
        for (j, m) in files.iter().enumerate() {
            if !reached[j] && !is_root(m) && hit(&files[k], m) {
                reached[j] = true;
                frontier.push(j);
            }
        }
    }

    let mut out: Vec<ModuleReach> = files
        .iter()
        .zip(&reached)
        .filter(|(m, _)| {
            let m: &ModFile = m;
            !is_root(m)
                && SCANNED_LAYERS.contains(&layer.get(&m.crate_name).copied().unwrap_or(""))
                && m.public
                && m.modpath.first().is_none_or(|s| s != "<main>")
                // Only a module with something to name can be unwired: one of
                // trait impls or re-exports alone is reached through what it
                // implements, and rustc's dead_code covers pub(crate) items.
                && (!m.facts.items.is_empty() || !m.facts.methods.is_empty())
        })
        .map(|(m, r)| ModuleReach {
            path: m.display_path(),
            file: m.file.clone(),
            lines: m.lines,
            reached: *r,
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The gate: every unreached module has a live row, and every row is still
/// needed and names a real module. `today` (`YYYY-MM-DD`) enables the expiry
/// check; without it the verdict depends on the tree alone.
pub fn check(
    modules: &[ModuleReach],
    registry: &UnwiredModules,
    read: &dyn Fn(&str) -> Option<String>,
    today: Option<&str>,
) -> Vec<String> {
    let by_path: BTreeMap<&str, &ModuleReach> =
        modules.iter().map(|m| (m.path.as_str(), m)).collect();
    let registered: BTreeSet<&str> = registry
        .unwired
        .iter()
        .map(|u| u.path.as_str())
        .chain(registry.verification.iter().map(|v| v.path.as_str()))
        .collect();
    let mut fails = Vec::new();
    for m in modules.iter().filter(|m| !m.reached) {
        if !registered.contains(m.path.as_str()) {
            fails.push(format!(
                "unreached module {} ({}, {} lines): no surface references it. Wire it to a surface, or add an [[unwired]] row (owner_bead, reason, expires) to registries/unwired_modules.toml",
                m.path, m.file, m.lines
            ));
        }
    }
    let row_state = |path: &str, fails: &mut Vec<String>| -> bool {
        match by_path.get(path) {
            None => {
                fails.push(format!(
                    "registries/unwired_modules.toml names {path}, which is no pub library module; remove the row"
                ));
                false
            }
            Some(m) if m.reached => {
                fails.push(format!(
                    "stale row: {path} is reached from a surface now; remove its row from registries/unwired_modules.toml"
                ));
                false
            }
            Some(_) => true,
        }
    };
    for u in &registry.unwired {
        if row_state(u.path.as_str(), &mut fails)
            && let Some(today) = today
            && u.expires.as_str() < today
        {
            fails.push(format!(
                "expired row: {} expired on {} (owner {}); wire it, or renew the row with a new reason",
                u.path, u.expires, u.owner_bead
            ));
        }
    }
    for v in &registry.verification {
        if !row_state(v.path.as_str(), &mut fails) {
            continue;
        }
        let module = by_path.get(v.path.as_str()).map(|m| m.file.as_str());
        let named = match (read(v.consumer.as_str()), module.and_then(read)) {
            (Some(consumer), Some(source)) => {
                let words = file_facts(&consumer).all_words;
                let facts = file_facts(&source);
                let seg = v.path.rsplit("::").next().unwrap_or(&v.path);
                words.contains(seg) || facts.items.iter().any(|n| words.contains(n))
            }
            _ => false,
        };
        if !named {
            fails.push(format!(
                "verification row {}: consumer {} does not reference it",
                v.path, v.consumer
            ));
        }
    }
    fails
}

/// Today's UTC date as `YYYY-MM-DD` (days-from-civil inverse, Hinnant).
pub fn utc_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let z = i64::try_from(secs / 86_400).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The human report: one line per unreached module and the totals.
pub fn render(modules: &[ModuleReach], registry: &UnwiredModules) -> String {
    let mut out = String::new();
    for m in modules.iter().filter(|m| !m.reached) {
        let status = if let Some(u) = registry.unwired.iter().find(|u| u.path == m.path) {
            format!("unwired, {} until {}", u.owner_bead, u.expires)
        } else if let Some(v) = registry.verification.iter().find(|v| v.path == m.path) {
            format!("verification, {}", v.consumer)
        } else {
            "UNREGISTERED".to_string()
        };
        out.push_str(&format!("{:<40} {:>6} lines  {status}\n", m.path, m.lines));
    }
    let reached = modules.iter().filter(|m| m.reached).count();
    out.push_str(&format!(
        "{} library modules: {reached} reached, {} unreached ({} unwired rows, {} verification rows)\n",
        modules.len(),
        modules.len() - reached,
        registry.unwired.len(),
        registry.verification.len()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, layer: &str) -> CrateSpec {
        CrateSpec {
            name: name.into(),
            layer: layer.into(),
            path: format!("crates/{name}"),
        }
    }

    /// A small workspace: a surface `fa-cli`, a facade `fa` re-exporting
    /// `fa-lib`, whose modules are reached in different ways or not at all.
    fn fixture() -> (Vec<CrateSpec>, BTreeMap<String, String>) {
        let crates = vec![
            spec("fa-cli", "surface"),
            spec("fa", "surface"),
            spec("fa-lib", "kernel"),
        ];
        let files = [
            (
                "crates/fa-cli/src/main.rs",
                "use fa::{Book, Ledger};\nfn main() { let b = Book::open(); b.trial_balance(); Ledger::new(); }\n",
            ),
            (
                "crates/fa/src/lib.rs",
                "pub mod book;\npub use fa_lib::ledger::Ledger;\npub use book::Book;\n",
            ),
            (
                "crates/fa/src/book.rs",
                "pub struct Book;\nimpl Book {\n    pub fn open() -> Self { Book }\n    pub fn trial_balance(&self) { fa_lib::fold::fold_all(); }\n}\n",
            ),
            (
                "crates/fa-lib/src/lib.rs",
                "pub mod ledger;\npub mod fold;\npub mod orphan;\npub mod commented;\npub mod display;\n#[cfg(test)]\nmod tests;\n",
            ),
            ("crates/fa-lib/src/ledger.rs", "pub struct Ledger;\n"),
            (
                "crates/fa-lib/src/fold.rs",
                "pub fn fold_all() {}\n#[cfg(test)]\nmod tests { use crate::orphan::Orphan; fn t() { Orphan; } }\n",
            ),
            (
                "crates/fa-lib/src/orphan.rs",
                "pub struct Orphan;\npub fn unused_helper() {}\n",
            ),
            ("crates/fa-lib/src/commented.rs", "pub struct Mentioned;\n"),
            ("crates/fa-lib/src/tests.rs", "use crate::orphan::Orphan;\n"),
            // Trait impls alone: nothing to name, so never reported.
            (
                "crates/fa-lib/src/display.rs",
                "impl core::fmt::Display for crate::ledger::Ledger {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(\"ledger\") }\n}\n",
            ),
        ];
        let mut map: BTreeMap<String, String> = files
            .iter()
            .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
            .collect();
        // Names in comments and strings are not references.
        map.get_mut("crates/fa-cli/src/main.rs")
            .expect("main")
            .push_str(
                "// fa_lib::commented::Mentioned\nconst S: &str = \"Mentioned orphan::Orphan\";\n",
            );
        (crates, map)
    }

    fn reach(crates: &[CrateSpec], files: &BTreeMap<String, String>) -> Vec<ModuleReach> {
        analyze(crates, &|p: &str| files.get(p).cloned())
    }

    fn registry(text: &str) -> UnwiredModules {
        UnwiredModules::from_text(&format!("schema_version = 1\n{text}")).expect("registry")
    }

    fn unreached(modules: &[ModuleReach]) -> Vec<&str> {
        modules
            .iter()
            .filter(|m| !m.reached)
            .map(|m| m.path.as_str())
            .collect()
    }

    #[test]
    fn reach_follows_reexports_methods_and_qualified_paths() {
        let (crates, files) = fixture();
        let modules = reach(&crates, &files);
        // fa::book through `use fa::Book`; fa_lib::ledger through fa's
        // re-export; fa_lib::fold through a qualified call in a reached
        // method. Comments, strings and a cfg(test) use reach nothing.
        assert_eq!(
            unreached(&modules),
            vec!["fa_lib::commented", "fa_lib::orphan"]
        );
        assert!(
            modules
                .iter()
                .any(|m| m.path == "fa_lib::fold" && m.reached)
        );
    }

    #[test]
    fn unreached_module_without_exemption_fails() {
        let (crates, files) = fixture();
        let modules = reach(&crates, &files);
        let read = |p: &str| files.get(p).cloned();
        let only_one = registry(
            "[[unwired]]\npath = \"fa_lib::commented\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n",
        );
        let fails = check(&modules, &only_one, &read, Some("2026-10-22"));
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(
            fails[0].starts_with("unreached module fa_lib::orphan"),
            "{fails:?}"
        );

        let both = registry(
            "[[unwired]]\npath = \"fa_lib::commented\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n[[unwired]]\npath = \"fa_lib::orphan\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n",
        );
        assert!(check(&modules, &both, &read, Some("2026-10-22")).is_empty());
    }

    #[test]
    fn expired_exemption_fails() {
        let (crates, files) = fixture();
        let modules = reach(&crates, &files);
        let read = |p: &str| files.get(p).cloned();
        let rows = registry(
            "[[unwired]]\npath = \"fa_lib::commented\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n[[unwired]]\npath = \"fa_lib::orphan\"\nowner_bead = \"fa-2\"\nreason = \"r\"\nexpires = \"2026-10-21\"\n",
        );
        let fails = check(&modules, &rows, &read, Some("2026-10-22"));
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(
            fails[0].contains("expired row: fa_lib::orphan expired on 2026-10-21 (owner fa-2)"),
            "{fails:?}"
        );
        // The day itself is still live, and without a date only the tree is judged.
        assert!(check(&modules, &rows, &read, Some("2026-10-21")).is_empty());
        assert!(check(&modules, &rows, &read, None).is_empty());
    }

    #[test]
    fn stale_dangling_and_unreferenced_rows_fail() {
        let (crates, mut files) = fixture();
        files.insert(
            "crates/fa-lib/tests/it.rs".into(),
            "use fa_lib::commented::Mentioned;\n".into(),
        );
        let modules = reach(&crates, &files);
        let read = |p: &str| files.get(p).cloned();
        let rows = registry(
            "[[unwired]]\npath = \"fa_lib::ledger\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n[[unwired]]\npath = \"fa_lib::gone\"\nowner_bead = \"fa-1\"\nreason = \"r\"\nexpires = \"2026-11-21\"\n[[verification]]\npath = \"fa_lib::commented\"\nconsumer = \"crates/fa-lib/tests/it.rs\"\nreason = \"r\"\n[[verification]]\npath = \"fa_lib::orphan\"\nconsumer = \"crates/fa-lib/tests/it.rs\"\nreason = \"r\"\n",
        );
        let fails = check(&modules, &rows, &read, None);
        assert_eq!(fails.len(), 3, "{fails:?}");
        assert!(
            fails[0].starts_with("stale row: fa_lib::ledger"),
            "{fails:?}"
        );
        assert!(
            fails[1].contains("names fa_lib::gone, which is no pub library module"),
            "{fails:?}"
        );
        assert!(
            fails[2].contains("verification row fa_lib::orphan: consumer crates/fa-lib/tests/it.rs does not reference it"),
            "{fails:?}"
        );
    }

    #[test]
    fn lexing_blanks_comments_strings_and_chars_but_keeps_lifetimes() {
        let src = "fn a<'x>(s: &'x str) -> char { /* b /* c */ d */ let _ = r#\"e \"f\"\"#; let _ = b\"g\"; let _ = '\\''; let _ = 'h'; i } // j\n";
        let facts = file_facts(src);
        for kept in ["a", "x", "s", "str", "char", "i"] {
            assert!(facts.words.contains(kept), "{kept}: {:?}", facts.words);
        }
        for gone in ["b", "c", "d", "e", "f", "g", "h", "j"] {
            assert!(!facts.words.contains(gone), "{gone}: {:?}", facts.words);
        }
        // A cfg(test) field ends at its `,` or the struct's `}`: the next
        // item, and what it references, stay.
        let gated = file_facts(
            "struct S {\n    #[cfg(test)]\n    probe: Probe,\n    kept: u8,\n}\nstruct T {\n    #[cfg(test)]\n    last: Last\n}\npub fn after() { reached::call(); }\n",
        );
        assert!(gated.items.contains("after"), "{:?}", gated.items);
        assert!(gated.paths.contains("reached"), "{:?}", gated.paths);
        assert!(gated.words.contains("kept"), "{:?}", gated.words);
        assert!(!gated.words.contains("Probe") && !gated.words.contains("Last"));
    }

    #[test]
    fn use_trees_expand_into_leaves() {
        let facts = file_facts("use a::{b, c::{d as e, *}, self};\npub use ::f::g;\nuse h as i;\n");
        assert_eq!(
            facts.uses,
            vec![
                vec!["a".to_string(), "b".into()],
                vec!["a".into(), "c".into(), "d".into()],
                vec!["a".into(), "c".into(), "*".into()],
                vec!["a".into(), "self".into()],
                vec!["f".into(), "g".into()],
                vec!["h".into()],
            ]
        );
        assert_eq!(facts.pub_uses, vec![vec!["f".to_string(), "g".into()]]);
    }

    #[test]
    fn utc_today_is_a_valid_date() {
        let today = utc_today();
        assert!(
            fa_registry::unwired_modules::parse_date(&today).is_some(),
            "{today}"
        );
        assert!(today.as_str() >= "2026-10-22", "{today}");
    }

    /// The gate over the real workspace (bead fa-2ioe), judged on the tree
    /// alone; scripts/check.sh step `reachability` adds the expiry check.
    #[test]
    fn the_workspace_has_no_unregistered_unreached_module() {
        let root = crate::default_workspace_root();
        let crates = workspace_crates().expect("topology");
        let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
        let modules = analyze(&crates, &read);
        assert!(modules.len() > 100, "{} modules", modules.len());
        let registry = UnwiredModules::embedded().expect("unwired_modules.toml");
        let fails = check(&modules, &registry, &read, None);
        assert!(
            fails.is_empty(),
            "{}\n{}",
            fails.join("\n"),
            render(&modules, &registry)
        );
    }
}
