// backend/src/services/mod.rs
pub mod escrow;
pub mod scanner;

pub use escrow::EscrowService;
pub use scanner::BlockchainScanner;
