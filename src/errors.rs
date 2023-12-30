use std::{error::Error, fmt};

#[derive(Debug)]
pub enum AuthError {
    LoginError(String),
    SignupError(String),
}

impl Error for AuthError {}

impl fmt::Display for AuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::LoginError(msg) => String::from("Could not Login: ") + msg,
            Self::SignupError(msg) => String::from("Could not Signup: ") + msg,
        };
        write!(fmt, "{}", message)
    }
}

#[derive(Debug)]
pub struct CryptoError {}
impl Error for CryptoError {}

impl fmt::Display for CryptoError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "Something went wrong")
    }
}

#[derive(Debug)]
pub struct UdidError {
    pub message: String,
}
impl Error for UdidError {}

impl fmt::Display for UdidError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "Could not get device id - Error: {}", self.message)
    }
}
