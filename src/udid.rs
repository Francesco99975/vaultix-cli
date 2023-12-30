use crate::errors::UdidError;
use std::process::Command;

#[cfg(target_os = "windows")]
fn get_windows_device_identifier() -> Option<String> {
    if let Ok(output) = Command::new("wmic")
        .args(&["csproduct", "get", "UUID"])
        .output()
    {
        if let Ok(result) = String::from_utf8(output.stdout) {
            return result.lines().nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn get_mac_device_identifier() -> Option<String> {
    if let Ok(output) = Command::new("system_profiler")
        .args(&["SPHardwareDataType"])
        .output()
    {
        if let Ok(result) = String::from_utf8(output.stdout) {
            if let Some(line) = result.lines().find(|s| s.contains("Hardware UUID")) {
                return line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_linux_device_identifier() -> Result<String, UdidError> {
    let output = Command::new("sudo")
        .arg("dmidecode")
        .output()
        .map_err(|err| UdidError {
            message: err.to_string(),
        })?;

    let result = String::from_utf8(output.stdout).map_err(|err| UdidError {
        message: err.to_string(),
    })?;

    let line = result
        .lines()
        .find(|s| s.contains("UUID"))
        .ok_or_else(|| UdidError {
            message: format!("UUID Not found - {}", result),
        })?;

    let id = line
        .split_whitespace()
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| UdidError {
            message: format!("UUID Malformed - {}", line),
        })?;

    Ok(id)
}

pub fn get_udid() -> Result<String, UdidError> {
    #[cfg(target_os = "macos")]
    let udid = get_mac_device_identifier();

    #[cfg(target_os = "linux")]
    let udid = get_linux_device_identifier();

    #[cfg(target_os = "windows")]
    let udid = get_windows_device_identifier();

    // Parse and extract relevant information from the output

    return udid;
}
