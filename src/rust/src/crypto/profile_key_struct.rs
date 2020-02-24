//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto::credentials;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::Sha512;

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileKeyStruct {
    pub(crate) bytes: ProfileKeyBytes,
    pub(crate) M4: RistrettoPoint,
    pub(crate) M5: RistrettoPoint,
    pub(crate) M6: RistrettoPoint,
    pub(crate) m6: Scalar,
}

impl ProfileKeyStruct {
    pub fn new(profile_key_bytes: ProfileKeyBytes) -> Self {
        let system = credentials::SystemParameters::get_hardcoded();
        let M4 = RistrettoPoint::lizard_encode::<Sha256>(&profile_key_bytes).unwrap(); // Swallow Lizard Encode errors; shouldn't happen
        let M5 = RistrettoPoint::hash_from_bytes::<Sha512>(&profile_key_bytes);
        let m6 = calculate_scalar(b"Signal_ZKGroup_Enc_ProfileKey_m6", &profile_key_bytes);
        let M6 = m6 * system.G_m6;
        ProfileKeyStruct {
            bytes: profile_key_bytes,
            M4,
            M5,
            M6,
            m6,
        }
    }

    // Might return PointDecodeFailure
    pub fn from_M4(M4: RistrettoPoint) -> Result<Self, ZkGroupError> {
        match M4.lizard_decode::<Sha256>() {
            None => Err(ZkGroupError::PointDecodeFailure),
            Some(bytes) => Ok(Self::new(bytes)),
        }
    }

    pub fn to_bytes(&self) -> ProfileKeyBytes {
        self.bytes
    }
}
