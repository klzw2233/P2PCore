//! Session API over [`p2p-trust`].
//!
//! Wiring to iroh belongs to issue #2. This empty shell keeps the two-crate
//! workspace boundary (ADR-0005) without depending on iroh yet.

#![forbid(unsafe_code)]

use p2p_trust as _;
