use std::fs;
use std::io::BufReader;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VConfig {
    pub jwt_token: String,
}

pub fn load_config() -> Result<Vec<VConfig>, Box<dyn std::error::Error>> {
    let file = fs::File::open("vconfig.json")?;
    let reader = BufReader::new(file);
    let config: Vec<VConfig> = serde_json::from_reader(reader)?;

    Ok(config)
}
