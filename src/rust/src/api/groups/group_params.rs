//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto;
use poksho::ShoSha256;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, Default)]
pub struct GroupMasterKey {
    pub(crate) bytes: [u8; 32],
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupSecretParams {
    pub(crate) uid_enc_key_pair: crypto::uid_encryption::KeyPair,
    pub(crate) profile_key_enc_key_pair: crypto::profile_key_encryption::KeyPair,
    sig_key_pair: crypto::signature::KeyPair,
    master_key: GroupMasterKey,
    group_id: GroupIdentifierBytes,
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct GroupPublicParams {
    pub(crate) uid_enc_public_key: crypto::uid_encryption::PublicKey,
    pub(crate) profile_key_enc_public_key: crypto::profile_key_encryption::PublicKey,
    sig_public_key: crypto::signature::PublicKey,
    group_id: GroupIdentifierBytes,
}

impl GroupMasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        GroupMasterKey { bytes }
    }
}

impl GroupSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        let mut master_key: GroupMasterKey = Default::default();
        master_key.bytes.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_Master_Random",
                &randomness,
                GROUP_MASTER_KEY_LEN as u64,
            )[0..GROUP_MASTER_KEY_LEN],
        );
        GroupSecretParams::derive_from_master_key(master_key)
    }

    pub fn derive_from_master_key(master_key: GroupMasterKey) -> Self {
        let uid_enc_key_pair = crypto::uid_encryption::KeyPair::derive_from(master_key.bytes);
        let profile_key_enc_key_pair =
            crypto::profile_key_encryption::KeyPair::derive_from(master_key.bytes);
        let sig_key_pair = crypto::signature::KeyPair::derive_from(
            &master_key.bytes,
            b"Signal_ZKGroup_Sig_Client_KeyDerive",
        );

        let mut group_id: GroupIdentifierBytes = Default::default();
        group_id.copy_from_slice(
            &ShoSha256::shohash(
                b"Signal_ZKGroup_GroupId",
                &master_key.bytes,
                GROUP_IDENTIFIER_LEN as u64,
            )[0..GROUP_IDENTIFIER_LEN],
        );

        Self {
            uid_enc_key_pair,
            profile_key_enc_key_pair,
            sig_key_pair,
            master_key,
            group_id,
        }
    }

    pub fn get_master_key(&self) -> GroupMasterKey {
        self.master_key
    }

    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }

    pub fn get_public_params(&self) -> GroupPublicParams {
        GroupPublicParams {
            uid_enc_public_key: self.uid_enc_key_pair.get_public_key(),
            profile_key_enc_public_key: self.profile_key_enc_key_pair.get_public_key(),
            sig_public_key: self.sig_key_pair.get_public_key(),
            group_id: self.group_id,
        }
    }

    pub fn sign(
        &self,
        randomness: RandomnessBytes,
        message: &[u8],
    ) -> Result<ChangeSignatureBytes, ZkGroupError> {
        self.sig_key_pair.sign(message, randomness)
    }

    pub fn encrypt_uuid(&self, uid_bytes: UidBytes) -> api::groups::UuidCiphertext {
        let uid = crypto::uid_struct::UidStruct::new(uid_bytes);
        self.encrypt_uid_struct(uid)
    }

    pub fn encrypt_uid_struct(
        &self,
        uid: crypto::uid_struct::UidStruct,
    ) -> api::groups::UuidCiphertext {
        let ciphertext = self.uid_enc_key_pair.encrypt(uid);
        api::groups::UuidCiphertext { ciphertext }
    }

    pub fn decrypt_uuid(
        &self,
        ciphertext: api::groups::UuidCiphertext,
    ) -> Result<UidBytes, ZkGroupError> {
        let uid = self.uid_enc_key_pair.decrypt(ciphertext.ciphertext)?;
        Ok(uid.to_bytes())
    }

    pub fn encrypt_profile_key(
        &self,
        randomness: RandomnessBytes,
        profile_key: api::profiles::ProfileKey,
    ) -> api::groups::ProfileKeyCiphertext {
        self.encrypt_profile_key_bytes(randomness, profile_key.bytes)
    }

    pub fn encrypt_profile_key_bytes(
        &self,
        _randomness: RandomnessBytes,
        profile_key_bytes: ProfileKeyBytes,
    ) -> api::groups::ProfileKeyCiphertext {
        let profile_key = crypto::profile_key_struct::ProfileKeyStruct::new(profile_key_bytes);
        let ciphertext = self.profile_key_enc_key_pair.encrypt(profile_key);
        api::groups::ProfileKeyCiphertext { ciphertext }
    }

    pub fn decrypt_profile_key(
        &self,
        ciphertext: api::groups::ProfileKeyCiphertext,
    ) -> Result<api::profiles::ProfileKey, ZkGroupError> {
        let profile_key_struct = self
            .profile_key_enc_key_pair
            .decrypt(ciphertext.ciphertext)?;
        Ok(api::profiles::ProfileKey {
            bytes: profile_key_struct.bytes,
        })
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    pub fn decrypt_blob(self, ciphertext: &[u8]) -> Result<Vec<u8>, ZkGroupError> {
        Ok(ciphertext.to_vec())
    }
}

impl GroupPublicParams {
    pub fn get_group_identifier(&self) -> GroupIdentifierBytes {
        self.group_id
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: ChangeSignatureBytes,
    ) -> Result<(), ZkGroupError> {
        self.sig_public_key.verify(message, signature)
    }
}
