mod backends;
mod explain;
mod policy;
mod prepare;
mod probe;
mod run;

pub use explain::explain_backend;
pub use policy::{PolicyResolutionError, resolve_profile};
pub use prepare::prepare_run;
pub use probe::probe;
pub use run::run;

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;

#[cfg(test)]
#[path = "explain_tests.rs"]
mod explain_tests;

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;

#[cfg(test)]
#[path = "prepare_tests.rs"]
mod prepare_tests;

#[cfg(test)]
#[path = "run_tests.rs"]
mod run_tests;
