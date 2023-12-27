use crate::errors::CryptoError;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use error_stack::{Report, Result};

pub fn create_encryption_key(password: &[u8], salt: &[u8], encryption_key: &mut [u8; 32]) {
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(password, salt, encryption_key)
        .expect("Could not create encryption key")
}

pub fn hash(password: &[u8]) -> Result<String, CryptoError> {
    let argon2 = Argon2::default();

    match argon2.hash_password(password, &SaltString::generate(&mut OsRng)) {
        Ok(hashed_password) => Ok(hashed_password.to_string()),
        Err(err) => Err(Report::new(CryptoError {}).attach(format!("{:?}", err.to_string()))),
    }
}
