//! A wrapper around strings that hides their contents when printed or
//! formatted for debugging.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::fmt::Debug;

/// A string wrapper that hides its contents when printed or formatted for
/// debugging.
/// # Examples
/// ```
/// use secret_string::SecretString;
/// let secret = SecretString::new("my_secret_password");
/// assert_eq!(format!("{}", secret), "******************");
/// assert_eq!(format!("{:?}", secret), "SecretString(******************)");
/// assert_eq!(secret.value(), "my_secret_password");
pub struct SecretString<T>(T)
where
    T: AsRef<str>;

impl<T: AsRef<str>> SecretString<T> {
    pub fn new(s: T) -> Self {
        SecretString(s)
    }

    pub fn value(&self) -> &str {
        self.0.as_ref()
    }

    fn as_stars(&self) -> String {
        self.0.as_ref().bytes().map(|_| "*").collect::<String>()
    }
}

impl<T: AsRef<str>> std::fmt::Display for SecretString<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_stars())
    }
}

impl Debug for SecretString<&str> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString({})", self.as_stars())
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn test_secret_string_display() {
        let secret = SecretString::new("my_secret_password");
        assert_eq!(format!("{}", secret), "******************");
    }

    #[test]
    fn test_secret_string_debug() {
        let secret = SecretString::new("my_secret_password");
        assert_eq!(format!("{:?}", secret), "SecretString(******************)");
    }
    #[test]
    fn test_secret_string_value() {
        let secret = SecretString::new("my_secret_password");
        assert_eq!(secret.value(), "my_secret_password");
    }
}
