
#![crate_type = "dylib"]
#![crate_type = "rlib"]

#![feature(macro_rules)]

extern crate "rust-crypto" as crypto;
extern crate serialize;

pub mod websocket;