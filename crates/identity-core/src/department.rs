//! A bounded complete organization assertion. Parsed values alone are not trusted facts.
use crate::{facts::valid_max_age, federation::FederationError};
use serde::{Deserialize, Serialize};

/// An exact controlled code, not a display name or globally unique identifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DepartmentId(String);
impl DepartmentId {
    pub fn new(value: String) -> Result<Self, FederationError> {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(FederationError::Claims);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for DepartmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DepartmentId(<redacted>)")
    }
}
impl TryFrom<String> for DepartmentId {
    type Error = FederationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<DepartmentId> for String {
    fn from(value: DepartmentId) -> Self {
        value.0
    }
}

/// Enabling a department mapping always includes its explicit bounded lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DepartmentSnapshotClaimInput")]
pub struct DepartmentSnapshotClaim {
    claim: String,
    max_age_seconds: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartmentSnapshotClaimInput {
    claim: String,
    max_age_seconds: i64,
}
impl TryFrom<DepartmentSnapshotClaimInput> for DepartmentSnapshotClaim {
    type Error = FederationError;
    fn try_from(value: DepartmentSnapshotClaimInput) -> Result<Self, Self::Error> {
        Self::new(value.claim, value.max_age_seconds)
    }
}
impl DepartmentSnapshotClaim {
    pub fn new(claim: String, max_age_seconds: i64) -> Result<Self, FederationError> {
        // Standard ID token/user-info claims are never a department identity.
        const RESERVED: &[&str] = &[
            "iss",
            "sub",
            "sid",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "at_hash",
            "c_hash",
            "s_hash",
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "email",
            "email_verified",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "phone_number",
            "phone_number_verified",
            "address",
            "updated_at",
        ];
        if claim.is_empty()
            || claim.len() > 64
            || !claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || RESERVED.contains(&claim.as_str())
            || !valid_max_age(max_age_seconds)
        {
            return Err(FederationError::Configuration);
        }
        Ok(Self {
            claim,
            max_age_seconds,
        })
    }
    pub fn claim(&self) -> &str {
        &self.claim
    }
    pub fn max_age_seconds(&self) -> i64 {
        self.max_age_seconds
    }
    /// The signed observation fixes the deadline; an already stale fact is not renewed.
    pub fn expires_at(
        &self,
        issued_at: i64,
        expires_at: i64,
        now: i64,
    ) -> Result<i64, FederationError> {
        crate::facts::expires_at(self.max_age_seconds, issued_at, expires_at, now)
    }
}

/// An exact node in one assertion. Names never establish membership or ancestry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DepartmentNode {
    id: DepartmentId,
    display_name: String,
    #[serde(deserialize_with = "Option::deserialize")]
    parent_id: Option<DepartmentId>,
}
impl DepartmentNode {
    pub fn id(&self) -> &DepartmentId {
        &self.id
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub fn parent_id(&self) -> Option<&DepartmentId> {
        self.parent_id.as_ref()
    }
}

/// One full tree and this subject's memberships at an opaque source revision.
/// Validation is shared by verified-token input and the strict persisted codec.
/// No payload field can declare an issuer, provider, tenant, or principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "DepartmentSnapshotInput")]
pub struct DepartmentSnapshot {
    version: u32,
    source_revision: String,
    nodes: Vec<DepartmentNode>,
    memberships: Vec<DepartmentId>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DepartmentSnapshotInput {
    version: u32,
    source_revision: String,
    nodes: Vec<DepartmentNode>,
    memberships: Vec<DepartmentId>,
}
impl TryFrom<DepartmentSnapshotInput> for DepartmentSnapshot {
    type Error = FederationError;
    fn try_from(input: DepartmentSnapshotInput) -> Result<Self, Self::Error> {
        use std::collections::{BTreeMap, BTreeSet};
        if input.version != 1
            || input.nodes.is_empty()
            || input.nodes.len() > 256
            || input.memberships.len() > 16
            || DepartmentId::new(input.source_revision.clone()).is_err()
        {
            return Err(FederationError::Claims);
        }
        let mut nodes = BTreeMap::new();
        for node in &input.nodes {
            if node.display_name.is_empty()
                || node.display_name.len() > 256
                || node.display_name.trim() != node.display_name
                || node.display_name.chars().any(char::is_control)
                || nodes
                    .insert(
                        node.id.as_str(),
                        node.parent_id.as_ref().map(DepartmentId::as_str),
                    )
                    .is_some()
            {
                return Err(FederationError::Claims);
            }
        }
        if nodes.values().filter(|parent| parent.is_none()).count() != 1 {
            return Err(FederationError::Claims);
        }
        // Following each chain is bounded by 16, detecting cycles, missing parents
        // and disconnected components without a second graph representation.
        for id in nodes.keys() {
            let mut cursor = Some(*id);
            let mut depth = 0;
            while let Some(id) = cursor {
                depth += 1;
                if depth > 16 {
                    return Err(FederationError::Claims);
                }
                cursor = *nodes.get(id).ok_or(FederationError::Claims)?;
            }
        }
        let mut members = BTreeSet::new();
        for id in &input.memberships {
            if !nodes.contains_key(id.as_str()) || !members.insert(id.as_str()) {
                return Err(FederationError::Claims);
            }
        }
        Ok(Self {
            version: input.version,
            source_revision: input.source_revision,
            nodes: input.nodes,
            memberships: input.memberships,
        })
    }
}
impl DepartmentSnapshot {
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
    pub fn nodes(&self) -> &[DepartmentNode] {
        &self.nodes
    }
    pub fn memberships(&self) -> &[DepartmentId] {
        &self.memberships
    }
}

/// Exact verified claim presence. Invalid department input withholds this fact,
/// independently of authentication and other valid facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamDepartmentSnapshot {
    NotConfigured,
    Missing,
    Invalid,
    Present(DepartmentSnapshot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepartmentUnavailableReason {
    LocalIdentity,
    NotConfigured,
    ClaimMissing,
    InvalidClaim,
    NotYetValid,
}
