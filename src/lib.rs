/// Public library crate for exe_tester.
/// Both the CLI binary (main.rs) and the GUI binary (bin/exe_tester_web_gui.rs)
/// import shared types and utilities from here instead of using #[path] hacks.
pub mod shared;
pub mod core;
