use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignupPayload {
    pub user_id: String,
    pub device_id: String,
    pub publickey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JWT {
    pub token: String,
}
