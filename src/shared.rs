use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    aead::generic_array::{
        typenum::{UInt, UTerm},
        GenericArray,
    },
    consts::{B0, B1},
};

// Define your global-like data structure
#[derive(Debug)]
pub struct UserTools {
    pub xchacha_key:
        Option<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>>,
}

// Wrap it in a Mutex for safe concurrent access
pub type SharedData = Arc<Mutex<UserTools>>;

// Function to initialize the global-like variable
pub fn initialize_data() -> SharedData {
    Arc::new(Mutex::new(UserTools { xchacha_key: None }))
}
