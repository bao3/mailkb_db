//! Universal mail ingestion, MIME/HTML/OOXML parsing, domain-pack enrichment,
//! SQLite indexing (`1.0-universal`), corpus profiling, and pack testing.

pub mod apple_mail;
pub mod enrich;
pub mod html;
pub mod mime;
pub mod pack_tools;
pub mod schema;
pub mod sync;

pub use pack_tools::{run_profile_corpus, run_test_pack, ProfileOpts, TestPackOpts};
pub use sync::{run_sync, SyncOpts};
