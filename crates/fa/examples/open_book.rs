//! **A real `main()` that opens a FrankenAccounting book on FrankenGraphDB.**
//!
//! This is the Genesis de-risk witness (plan §19): a separately compiled binary
//! proving that a `fa` crate links the substrate at its pinned revision, builds
//! the production asupersync runtime, narrows a root `Cx` to the substrate's
//! purpose contexts, creates an in-memory book, writes through the real commit
//! path, and reads back what it wrote.
//!
//! ```text
//! cargo run -p fa --example open_book
//! ```
//!
//! What this proves: linkage, runtime wiring, and the write/read round trip.
//! What it does not prove: anything about the posting kernel, registers, or
//! performance.

use fa::book::{Book, BookKeys};

fn main() {
    if let Err(error) = run() {
        eprintln!("FAILED: {error}");
        std::process::exit(5);
    }
}

fn run() -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    println!("fa genesis witness");
    let keys = BookKeys::for_development(0x5a);
    let mut book = Book::open_memory(keys)?;
    println!("  opened an in-memory book");

    let seq = book.genesis_probe()?;
    println!("  wrote the probe vertex at commit seq {seq}");

    let row = book.read_probe()?;
    println!("  read it back: {row}");
    println!("OK");
    Ok(())
}
