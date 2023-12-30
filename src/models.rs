use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignupPayload {
    pub device_id: String,
    pub publickey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginPayload {
    pub user_id: String,
    pub device_id: String,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWT {
    pub token: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct HttpError {
    pub message: String,
    pub status_code: u16,
    pub error_code: Option<i8>,
}
