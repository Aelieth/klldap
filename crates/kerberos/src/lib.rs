#![forbid(unsafe_code)]

#[cfg(any(test, not(feature = "test-admission")))]
mod admission;
#[cfg(feature = "test-admission")]
mod admission_test;
pub mod boot;
pub mod embedded;
mod migrate;
mod policy;
mod rotate;
mod seam;
