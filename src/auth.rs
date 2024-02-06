use chacha20poly1305::{
    aead::{
        generic_array::{
            typenum::{UInt, UTerm},
            GenericArray,
        },
        Aead, OsRng,
    },
    consts::{B0, B1},
    AeadCore, KeyInit, XChaCha20Poly1305,
};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePublicKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use error_stack::{Report, Result, ResultExt};
use rand::{distributions::Standard, thread_rng, Rng, RngCore};

use crate::{
    crypto::create_encryption_key,
    endpoints::{BASE_URL, LOGIN, SIGNUP},
    errors::AuthError,
    http::get_client,
    keystore::{
        close_vault, get_device_id, get_encrypted_keypair, get_nonce, get_salt, get_user_id,
        open_vault, store_keypair,
    },
    models::{LoginPayload, RegisterResponse, SignupPayload, JWT},
    shared::SharedData,
    udid,
};

pub async fn signup(password: &str, shared_data: &SharedData) -> Result<(), AuthError> {
    // Check if config file exists
    if shared_data.lock().unwrap().xchacha_key.is_some() {
        return Err(AuthError::SignupError(format!("Already Logged in")).into());
    }

    let device_id = udid::get_udid().map_err(|err| {
        Report::new(AuthError::SignupError(format!(
            "Could not get device ID - Error: {}",
            err.to_string()
        )))
        .attach_printable(format!(
            "Could not get device ID - Error: {}",
            err.to_string()
        ))
    })?;

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
        device_id: device_id.clone(),
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

    let res: RegisterResponse = response
        .json()
        .await
        .change_context(AuthError::SignupError(format!(
            "Could not parse request json for Signup"
        )))
        .attach_printable(format!(
            "Could not parse request json for Signup - payload: {:?}",
            payload
        ))?;

    open_vault().await.map_err(|err| {
        Report::new(AuthError::SignupError(format!("Could not open vault")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;
    store_keypair(
        &encrypted_keypair,
        &nonce,
        &salt,
        res.user_id.as_bytes(),
        device_id.as_bytes(),
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

    //Create Empty Config File

    Ok(())
}

pub async fn login(password: &str, shared_data: &SharedData) -> Result<String, AuthError> {
    let password_bytes = password.as_bytes();
    open_vault().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not open vault")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let encrypted_keypair = get_encrypted_keypair().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not retrive keypair")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let raw_nonce = get_nonce().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not retrive nonce")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let nonce: &GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>> =
        GenericArray::from_slice(raw_nonce.as_slice());

    let salt = get_salt().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not retrive salt")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let raw_user_id = get_user_id().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not retrive user id")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let user_id = String::from_utf8(raw_user_id)
        .change_context(AuthError::LoginError(format!(
            "Could not parse user id byte vector"
        )))
        .attach_printable(format!("Could not parse user id byte vector"))?;

    let raw_device_id = get_device_id().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!(
            "Could not retrive device id hash"
        )))
        .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let device_id = String::from_utf8(raw_device_id)
        .change_context(AuthError::LoginError(format!(
            "Could not parse device id byte vector"
        )))
        .attach_printable(format!("Could not parse device id byte vector"))?;

    close_vault().await.map_err(|err| {
        Report::new(AuthError::LoginError(format!("Could not close KeyStore")))
            .attach_printable(format!("{:?}", err.to_string()))
    })?;

    let mut encryption_key = [0u8; 32];

    create_encryption_key(password_bytes, &salt, &mut encryption_key);
    let xchacha_key: &GenericArray<
        u8,
        UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
    > = GenericArray::from_slice(&encryption_key);
    let cipher = XChaCha20Poly1305::new(xchacha_key);

    let raw_keypair = cipher
        .decrypt(nonce, encrypted_keypair.as_ref())
        .map_err(|err| {
            Report::new(AuthError::LoginError(format!("Could not recreate KeyPair")))
                .attach_printable(format!("{:?}", err.to_string()))
        })?;

    let mut secret_key: [u8; 32] = [0u8; 32];

    secret_key.clone_from_slice(&raw_keypair[..]);

    let keypair = SigningKey::from_bytes(&secret_key);

    // Generate a random length for the byte slice
    let length = thread_rng().gen_range(1..=20);
    // Create a mutable byte vector with the random length
    let mut message_bytes = vec![0u8; length];
    // Use the rand::thread_rng() generator to fill the vector with random bytes
    thread_rng().fill_bytes(&mut message_bytes);

    let signature: Signature = keypair.sign(message_bytes.as_slice());

    let payload = LoginPayload {
        user_id,
        device_id,
        message: message_bytes,
        signature: signature.to_vec(),
    };

    let client = get_client()
        .change_context(AuthError::LoginError(format!(
            "Could not send request to server to Login"
        )))
        .attach_printable(format!("Could not login - payload {:?}", payload))?;

    let response = client
        .post(BASE_URL.to_owned() + LOGIN)
        .json(&payload)
        .send()
        .await
        .change_context(AuthError::LoginError(format!(
            "Could not send request to server to Login"
        )))
        .attach_printable(format!("Could not login - payload {:?}", payload))?;

    if !response.status().is_success() {
        let status = response.status().clone();
        let text = response
            .text()
            .await
            .change_context(AuthError::LoginError(format!(
                "Something went wrong while checking server error"
            )))
            .attach_printable(format!("Could not parse json response for http error"))?;

        return Err(Report::new(AuthError::LoginError(format!(
            "Unable to Login at the moment - Cause: {}",
            text
        )))
        .attach_printable(format!(
            "Signup Response Failed to login - Status: {:?}",
            status
        )));
    }

    let jwt: JWT = response
        .json()
        .await
        .change_context(AuthError::LoginError(format!("Something went wrong")))
        .attach_printable(format!("Could not parse json response"))?;

    //Store Cipher in a global like variable
    shared_data.lock().unwrap().xchacha_key = Some(*xchacha_key);

    Ok(jwt.token)
}
