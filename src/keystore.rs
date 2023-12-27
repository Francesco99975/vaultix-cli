use std::{collections::HashMap, error::Error};

use secret_service::{EncryptionType, SecretService};

const ID_CIPHER: [(&str, &str); 1] = [("encrypted_key", "encrypted_private_key")];
const ID_NONCE: [(&str, &str); 1] = [("nonce", "xcc_nonce")];
const ID_SALT: [(&str, &str); 1] = [("salt", "argon_salt")];
const ID_USER: [(&str, &str); 1] = [("id", "id_user")];
const ID_DEVICE: [(&str, &str); 1] = [("device", "id_device")];

struct RingStoreData<'a> {
    label: &'a str,
    attributes: [(&'a str, &'a str); 1],
    secret: &'a [u8],
    replace: bool,
    content_type: &'a str,
}

pub async fn store_keypair(
    ciphertext: &[u8],
    nonce: &[u8],
    salt: &[u8],
    id: &[u8],
    device: &[u8],
) -> Result<(), Box<dyn Error>> {
    let items: [RingStoreData<'_>; 5] = [
        RingStoreData {
            label: "ciphertext",
            attributes: ID_CIPHER,
            secret: &ciphertext,
            replace: true,
            content_type: "application/octet-stream",
        },
        RingStoreData {
            label: "nonce",
            attributes: ID_NONCE,
            secret: &nonce,
            replace: true,
            content_type: "application/octet-stream",
        },
        RingStoreData {
            label: "salt",
            attributes: ID_SALT,
            secret: &salt,
            replace: true,
            content_type: "application/octet-stream",
        },
        RingStoreData {
            label: "id",
            attributes: ID_USER,
            secret: &id,
            replace: true,
            content_type: "application/octet-stream",
        },
        RingStoreData {
            label: "device",
            attributes: ID_DEVICE,
            secret: &device,
            replace: true,
            content_type: "application/octet-stream",
        },
    ];
    // initialize secret service (dbus connection and encryption session)
    let ss = SecretService::connect(EncryptionType::Dh).await?;

    // get or create collection
    // let collection = match ss.get_collection_by_alias("SecureEncryptonKeys").await {
    //     Ok(coll) => coll,
    //     Err(_) => {
    //         ss.create_collection("EncryptionKeys", "SecureEncryptonKeys")
    //             .await?
    //     }
    // };

    // get default collection
    let collection = ss.get_default_collection().await?;

    // store keys
    for item in items {
        collection
            .create_item(
                item.label,
                HashMap::from(item.attributes),
                item.secret,
                item.replace,
                item.content_type,
            )
            .await?;
    }

    Ok(())
}

async fn retreive_from_keyring(attributes: [(&str, &str); 1]) -> Result<Vec<u8>, Box<dyn Error>> {
    // initialize secret service (dbus connection and encryption session)
    let ss = SecretService::connect(EncryptionType::Dh).await?;

    let search_items = ss.search_items(HashMap::from(attributes)).await?;

    let item = search_items.unlocked.get(0).ok_or("Not Found")?;

    let secret = item.get_secret().await?;

    Ok(secret)
}

pub async fn get_encrypted_keypair() -> Result<Vec<u8>, Box<dyn Error>> {
    let secret = retreive_from_keyring(ID_CIPHER).await?;

    Ok(secret)
}

pub async fn get_nonce() -> Result<Vec<u8>, Box<dyn Error>> {
    let secret = retreive_from_keyring(ID_NONCE).await?;

    Ok(secret)
}

pub async fn get_salt() -> Result<Vec<u8>, Box<dyn Error>> {
    let secret = retreive_from_keyring(ID_SALT).await?;

    Ok(secret)
}

pub async fn get_user_id() -> Result<Vec<u8>, Box<dyn Error>> {
    let secret = retreive_from_keyring(ID_USER).await?;

    Ok(secret)
}

pub async fn get_device_id() -> Result<Vec<u8>, Box<dyn Error>> {
    let secret = retreive_from_keyring(ID_DEVICE).await?;

    Ok(secret)
}

pub async fn open_vault() -> Result<(), Box<dyn Error>> {
    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;
    collection.unlock().await?;

    Ok(())
}

pub async fn close_vault() -> Result<(), Box<dyn Error>> {
    let ss = SecretService::connect(EncryptionType::Dh).await?;
    let collection = ss.get_default_collection().await?;
    collection.lock().await?;

    Ok(())
}
