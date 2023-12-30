use std::{
    error::Error,
    fmt::{self, Display},
};

#[derive(Debug)]
pub struct SystemTrayError {
    pub message: String,
    pub code: i32,
}

impl SystemTrayError {
    pub fn new(code: i32) -> SystemTrayError {
        let message = match code {
            1 => "Index out of bounds exception".to_string(),
            2 => "Can't open file".to_string(),
            3 => "No mac address found".to_string(),
            4 => "Seed too short (10 char)".to_string(),
            5 => "Key is too short".to_string(),
            6 => "Character not found in character set".to_string(),
            7 => "Error when dividing by 8".to_string(),
            _ => format!("Unknown error with code {}", code),
        };

        SystemTrayError { message, code }
    }
}

impl Error for SystemTrayError {}

impl Display for SystemTrayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}