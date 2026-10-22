use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, DerivedAad, ENVELOPE_VERSION, EncryptionMode,
    Plaintext,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
pub(super) struct TestKey {
    active: String,
    keys: BTreeMap<String, aead::LessSafeKey>,
}
impl TestKey {
    pub(super) fn new() -> Self {
        Self {
            active: "fixture".into(),
            keys: BTreeMap::from([(
                "fixture".into(),
                aead::LessSafeKey::new(
                    aead::UnboundKey::new(&aead::AES_256_GCM, &[7; 32]).unwrap(),
                ),
            )]),
        }
    }
}
impl Aead for TestKey {
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
