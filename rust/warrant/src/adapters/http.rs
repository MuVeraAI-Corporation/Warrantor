//! L4-27 â the governed HTTP call.
//!
//! Outbound HTTP for the long tail nobody writes an adapter for. See the full module
//! documentation in the task plan; the properties, in order of how much they matter:
//! the agent never names a destination (a capability, an enum over the egress catalog),
//! the payload declares a data class bounded by the catalog entry, and the response
//! never re-enters an agent context.

/// The tool name the agent calls.
pub const TOOL: &str = "http.call";
