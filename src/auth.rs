use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, OsRng},
    AeadCore, KeyInit, XChaCha20Poly1305,
};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePublicKey},
    SigningKey, VerifyingKey,
};
use error_stack::{Report, Result, ResultExt};
use rand::{distributions::Standard, Rng};
use uuid::Uuid;

use crate::{
    crypto::{create_encryption_key, hash},
    endpoints::{BASE_URL, SIGNUP},
    errors::AuthError,
    http::get_client,
    keystore::{close_vault, open_vault, store_keypair},
    models::{SignupPayload, JWT},
    udid,
};

pub async fn signup(password: &str) -> Result<String, AuthError> {
    let user_id = Uuid::new_v4();
    let device_id = udid::get_udid().ok_or_else(|| {
        let message = format!("Could not get Device ID");
        Report::new(AuthError::SignupError(message.clone())).attach_printable(message.clone())
    })?;

    let hashed_device_id = hash(device_id.as_bytes())
        .change_context(AuthError::SignupError(format!("Could not hash device id")))
        .attach_printable(format!("Could not hash device id"))?;

    let password_bytes = password.as_bytes();

    let signing_key: SigningKey = SigningKey::generate(&mut OsRng);
    let keypair_bytes = signing_key.to_bytes();
    let salt: [u8; 16] = rand::thread_rng().sample(Standard);

    let mut encryption_key = [0u8; 32];

    create_encryption_key(password_bytes, &salt, &mut encryption_key);

    let xchacha_key = GenericArray::from_slice(&encryption_key);
    let cipher = XChaCha20Poly1305::new(&xchacha_key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let encrypted_keypair = cipher
        .encrypt(&nonce, keypair_bytes.as_ref())
        .map_err(|err| {
            Report::new(AuthError::SignupError(format!(
                "Could not generate KeyPair"
            )))
            .attach_printable(format!("{:?}", err.to_string()))
        })?;

    open_vault().await.map_err(|err| {
        Report::new(AuthError::SignupError(format!("Could not open vault")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;
    store_keypair(
        &encrypted_keypair,
        &nonce,
        &salt,
        user_id.as_bytes(),
        hashed_device_id.as_bytes(),
    )
    .await
    .map_err(|err| {
        Report::new(AuthError::SignupError(format!("Could use KeyStore")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;
    close_vault().await.map_err(|err| {
        Report::new(AuthError::SignupError(format!("Could not close KeyStore")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let armored_public_key = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| {
            Report::new(AuthError::SignupError(format!(
                "Could not extract armored public key"
            )))
            .attach_printable(format!("{:?}", err.to_string()))
        })?;

    let payload = SignupPayload {
        user_id: user_id.to_string(),
        device_id: hashed_device_id.to_owned(),
        publickey: armored_public_key,
    };

    let client = get_client()
        .change_context(AuthError::SignupError(format!(
            "Could not send request to server to Signup"
        )))
        .attach_printable(format!("Could not signup - payload {:?}", payload))?;

    let response = client
        .post(BASE_URL.to_owned() + SIGNUP)
        .json(&payload)
        .send()
        .await
        .change_context(AuthError::SignupError(format!(
            "Could not send request to server to Signup"
        )))
        .attach_printable(format!("Could not signup - payload {:?}", payload))?;

    if !response.status().is_success() {
        return Err(Report::new(AuthError::SignupError(format!(
            "Unable to Signup at the moment"
        )))
        .attach_printable(format!(
            "Signup Response Failed - Status: {:?}",
            response.status().clone()
        )));
    }

    let jwt: JWT = response
        .json()
        .await
        .change_context(AuthError::SignupError(format!("Something went wrong")))
        .attach_printable(format!("Could not parse json response"))?;

    Ok(jwt.token)
}
