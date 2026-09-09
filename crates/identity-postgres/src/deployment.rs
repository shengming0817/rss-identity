//! Persisted environment/origin identity. Artifact and schema versions are separate identities.
use crate::AuthorityError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OriginInput")]
pub struct DeploymentIdentity {
    pub(crate) environment_id: String,
    pub(crate) config_version: i64,
    pub(crate) identity_public_origin: String,
    pub(crate) product_public_origin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginInput {
    environment_id: String,
    config_version: i64,
    identity_public_origin: String,
    product_public_origin: String,
}
impl TryFrom<OriginInput> for DeploymentIdentity {
    type Error = AuthorityError;
    fn try_from(v: OriginInput) -> Result<Self, Self::Error> {
        Self::new(
            v.environment_id,
            v.config_version,
            v.identity_public_origin,
            v.product_public_origin,
        )
    }
}
impl DeploymentIdentity {
    pub fn new(
        environment_id: String,
        config_version: i64,
        identity_public_origin: String,
        product_public_origin: String,
    ) -> Result<Self, AuthorityError> {
        if environment_id.is_empty()
            || environment_id.len() > 128
            || !environment_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || config_version <= 0
            || identity_public_origin == product_public_origin
        {
            return Err(AuthorityError::Invalid);
        }
        for origin in [&identity_public_origin, &product_public_origin] {
            let url = url::Url::parse(origin).map_err(|_| AuthorityError::Invalid)?;
            if origin.len() > 2048
                || url.scheme() != "https"
                || url.host_str().is_none()
                || url.origin().ascii_serialization() != *origin
            {
                return Err(AuthorityError::Invalid);
            }
        }
        Ok(Self {
            environment_id,
            config_version,
            identity_public_origin,
            product_public_origin,
        })
    }
    pub fn environment(&self) -> &str {
        &self.environment_id
    }
    pub fn version(&self) -> i64 {
        self.config_version
    }
    pub fn identity_origin(&self) -> &str {
        &self.identity_public_origin
    }
    pub fn product_origin(&self) -> &str {
        &self.product_public_origin
    }
    pub fn issuer(&self) -> String {
        format!("{}/oidc", self.identity_public_origin)
    }
    pub fn product_callback(&self) -> String {
        format!("{}/auth/callback", self.product_public_origin)
    }
    pub fn identity_callback(&self) -> String {
        format!("{}/api/v1/oidc/callback", self.identity_public_origin)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_identity_is_closed_and_does_not_include_artifacts() {
        let v = DeploymentIdentity::new(
            "test".into(),
            1,
            "https://identity.test".into(),
            "https://product.test".into(),
        )
        .unwrap();
        assert_eq!(v.issuer(), "https://identity.test/oidc");
        let mut value = serde_json::to_value(&v).unwrap();
        value["artifact"] = serde_json::json!("different-binary");
        assert!(serde_json::from_value::<DeploymentIdentity>(value).is_err());
        for origin in [
            "http://identity.test",
            "https://identity.test/",
            "https://user@identity.test",
            "https://product.test",
        ] {
            assert!(
                DeploymentIdentity::new(
                    "test".into(),
                    1,
                    origin.into(),
                    "https://product.test".into()
                )
                .is_err()
            );
        }
    }
}
