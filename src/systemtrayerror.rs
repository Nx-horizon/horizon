use std::{
    error::Error,
    fmt::{self, Display},
};
/// Represents custom error types for the SystemTray application.
#[derive(Debug)]
pub struct SystemTrayError {
    /// A human-readable error message describing the nature of the error.
    pub message: String,
    /// An error code indicating the specific type of error.
    pub code: i32,
}

impl SystemTrayError {
    /// Creates a new instance of `SystemTrayError` with the specified error code.
    ///
    /// # Parameters
    ///
    /// - `code`: An integer representing the error code.
    ///
    /// # Returns
    ///
    /// Returns a `SystemTrayError` instance with the given error code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let error = SystemTrayError::new(1);
    /// println!("{:?}", error);
    /// ```
    pub fn new(code: i32) -> SystemTrayError {
        let message = match code {
            1 => "Index out of bounds exception".to_string(),
            2 => "Can't open file".to_string(),
            3 => "No mac address found".to_string(),
            4 => "Seed too short (10 char)".to_string(),
            5 => "Key is too short".to_string(),
            6 => "Character not found in character set".to_string(),
            7 => "Error when dividing by 8".to_string(),
            8 => "Error no processus found".to_string(),
            _ => format!("Unknown error with code {}", code),
        };

        SystemTrayError { message, code }
    }
}
/// Implements the `Error` trait for the custom error type `SystemTrayError`.
impl Error for SystemTrayError {}
/// Implements the `Display` trait for the custom error type `SystemTrayError`.
impl Display for SystemTrayError {
    /// Formats the error message for display.
    ///
    /// # Parameters
    ///
    /// - `f`: A mutable reference to a `fmt::Formatter` used for formatting.
    ///
    /// # Returns
    ///
    /// Returns a `fmt::Result` indicating the success or failure of the formatting.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let error = SystemTrayError::new(1);
    /// let formatted_message = format!("{}", error);
    /// println!("{}", formatted_message);
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}