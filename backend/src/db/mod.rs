use rocksdb::{DB, Options};

pub struct Ledger {
    pub db: DB,
}

impl Ledger {
    /// Opens or creates the RocksDB ledger at `path`.
    /// Panics immediately (fail-secure) if the database cannot be opened.
    pub fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, path)
            .unwrap_or_else(|e| panic!("FATAL: cannot open ledger at '{}': {}", path, e));

        Ledger { db }
    }
}
