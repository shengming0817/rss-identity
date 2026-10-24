//! Exact host-owned operation context; this value itself proves no authentication.
use serde::{Deserialize, Serialize};
/// Maximum age and lifetime of an operation-specific authentication proof.
pub const OPERATION_PROOF_SECONDS: i64 = 300;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Input")]
pub struct StepUpContext {
    purpose: String,
    digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    purpose: String,
    digest: [u8; 32],
}
impl TryFrom<Input> for StepUpContext {
    type Error = &'static str;
    fn try_from(v: Input) -> Result<Self, Self::Error> {
        Self::new(v.purpose, v.digest)
    }
}
impl StepUpContext {
    pub fn new(purpose: String, digest: [u8; 32]) -> Result<Self, &'static str> {
        if purpose.is_empty()
            || purpose.len() > 128
            || !purpose
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            return Err("invalid operation purpose");
        }
        Ok(Self { purpose, digest })
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
