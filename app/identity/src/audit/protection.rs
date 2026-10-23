//! Host-owned recovery keyring, separate from provider credentials.
//! ref: ring 0.17.14 src/aead/less_safe_key.rs (random nonce, detached tag).
use crate::{AppError, config::CredentialKeyFile, read_secret};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, DerivedAad, ENVELOPE_VERSION, EncryptionMode,
    Plaintext,
};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;

pub struct Protection {
    active: String,
    keys: BTreeMap<String, aead::LessSafeKey>,
}
impl Protection {
    pub fn load(active: &str, files: &[CredentialKeyFile]) -> Result<Self, AppError> {
        if files.is_empty() || files.len() > 8 {
            return Err(AppError::Configuration);
        }
        let mut keys = BTreeMap::new();
        for file in files {
            if file.key_id.is_empty() || file.key_id.len() > 64 {
                return Err(AppError::Configuration);
            }
            let value = read_secret(Path::new(&file.path))?;
            let mut raw = Zeroizing::new([0; 32]);
            hex::decode_to_slice(value.as_str(), raw.as_mut())
                .map_err(|_| AppError::Configuration)?;
            if raw.iter().all(|b| *b == 0) {
                return Err(AppError::Configuration);
            }
            let key = aead::UnboundKey::new(&aead::AES_256_GCM, raw.as_ref())
                .map_err(|_| AppError::Configuration)?;
            if keys
                .insert(file.key_id.clone(), aead::LessSafeKey::new(key))
                .is_some()
            {
                return Err(AppError::Configuration);
            }
        }
        if !keys.contains_key(active) {
            return Err(AppError::Configuration);
        }
        Ok(Self {
            active: active.into(),
            keys,
        })
    }
}
impl Aead for Protection {
    fn seal(&self, plain: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AeadError::Seal)?;
        let mut bytes = Zeroizing::new(plain.to_vec());
        let tag = self
            .keys
            .get(&self.active)
            .ok_or(AeadError::Seal)?
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                bytes.as_mut(),
            )
            .map_err(|_| AeadError::Seal)?;
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            &self.active,
            1,
            nonce.to_vec(),
            bytes.to_vec(),
            tag.as_ref().to_vec(),
            aad.coordinates().clone(),
        )
        .map_err(|_| AeadError::Seal)
    }
    fn open(
        &self,
        envelope: &CiphertextEnvelope,
        aad: &DerivedAad,
    ) -> Result<Plaintext, AeadError> {
        if envelope.version() != ENVELOPE_VERSION
            || envelope.alg() != CipherAlg::Aes256Gcm
            || envelope.mode() != EncryptionMode::Randomized
            || envelope.key_version() != 1
            || envelope.aad() != aad.coordinates()
            || envelope.tag().len() != 16
        {
            return Err(AeadError::Open);
        }
        let key = self.keys.get(envelope.kid()).ok_or(AeadError::Open)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(envelope.nonce())
            .map_err(|_| AeadError::Open)?;
        let mut bytes = Zeroizing::new(envelope.ciphertext().to_vec());
        bytes.extend_from_slice(envelope.tag());
        let plain = key
            .open_in_place(
                nonce,
                aead::Aad::from(aad.as_canonical_bytes()),
                bytes.as_mut(),
            )
            .map_err(|_| AeadError::Open)?;
        Ok(Plaintext::new(plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(raw: u8) -> aead::LessSafeKey {
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &[raw; 32]).unwrap())
    }
    #[test]
    fn recovery_ciphertext_authenticates_context_and_rotation() {
        use rss_data_protection::ProtectionContext;
        use rss_request_context::TenantId;
        let aad = ProtectionContext::new(
            TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            "identity.audit",
            "dead-letter",
            1,
        )
        .unwrap()
        .derive();
        let old = Protection {
            active: "old".into(),
            keys: BTreeMap::from([("old".into(), key(7))]),
        };
        let sealed = old.seal(b"private-event", &aad).unwrap();
        assert_ne!(
            sealed.nonce(),
            old.seal(b"private-event", &aad).unwrap().nonce()
        );
        let rotated = Protection {
            active: "new".into(),
            keys: BTreeMap::from([("old".into(), key(7)), ("new".into(), key(8))]),
        };
        assert_eq!(
            rotated.open(&sealed, &aad).unwrap().expose(),
            b"private-event"
        );
        assert_eq!(rotated.seal(b"private-event", &aad).unwrap().kid(), "new");
        let foreign = ProtectionContext::new(
            TenantId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            "identity.audit",
            "dead-letter",
            1,
        )
        .unwrap()
        .derive();
        assert!(rotated.open(&sealed, &foreign).is_err());
        for changed in 0..3 {
            let mut bytes = sealed.ciphertext().to_vec();
            let mut tag = sealed.tag().to_vec();
            if changed == 0 {
                bytes[0] ^= 1;
            } else if changed == 1 {
                tag[0] ^= 1;
            }
            let bad = CiphertextEnvelope::new(
                CipherAlg::Aes256Gcm,
                EncryptionMode::Randomized,
                if changed == 2 { "missing" } else { "old" },
                1,
                sealed.nonce().to_vec(),
                bytes,
                tag,
                aad.coordinates().clone(),
            )
            .unwrap();
            assert!(rotated.open(&bad, &aad).is_err());
        }
        assert!(!format!("{sealed:?}").contains("private-event"));
    }
}
