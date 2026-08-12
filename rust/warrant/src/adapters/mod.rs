//! Effect adapters: the components that perform staged effects for real at settle time.
//!
//! Each adapter holds the credentials for its service. The agent never does — by the time an
//! adapter runs, the agent has no part in the process, which is what removes a leaked token from
//! the threat model rather than merely reducing its scope.

pub mod github;
