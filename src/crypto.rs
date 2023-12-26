use crate::errors::CryptoError;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use error_stack::{Report, Result};
use rand::{thread_rng, Rng, RngCore};

pub fn generate_signature(key: &SigningKey) -> Signature {
    // Generate a random length for the byte slice
    let length = thread_rng().gen_range(1..=20);

    // Create a mutable byte vector with the random length
    let mut random_bytes = vec![0u8; length];

    // Use the rand::thread_rng() generator to fill the vector with random bytes
    thread_rng().fill_bytes(&mut random_bytes);

    key.sign(random_bytes.as_slice())
}

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
