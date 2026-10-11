//! `fa-verify`, the dependency-free verifier as a command (plan §13.3).
//! Everything is in [`fa_verify::cli`]; this only reads files and exits.

#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = fa_verify::cli::run(&args, &|path: &str| std::fs::read(path));
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    std::process::exit(out.exit);
}
