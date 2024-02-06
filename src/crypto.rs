use argon2::Argon2;

pub fn create_encryption_key(password: &[u8], salt: &[u8], encryption_key: &mut [u8; 32]) {
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(password, salt, encryption_key)
        .expect("Could not create encryption key")
}
