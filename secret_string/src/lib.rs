//! A wrapper around strings that hides their contents when printed or
//! formatted for debugging.///
//! It WILL however serialize the value when using [serde](https://serde.rs) serialization/deserialization.
//!
//! # Examples
//! ```
//! use secret_string::SecretString;
//! let secret = SecretString::new("my_secret_password");
//! assert_eq!(format!("{}", secret), "******************");
//! assert_eq!(format!("{:?}", secret), "SecretString(******************)");
//! assert_eq!(secret.value(), "my_secret_password");
//! ```

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
///
/// It WILL however serialize the value when using [serde](https://serde.rs) serialization/deserialization.
///
/// # Examples
/// ```
/// use secret_string::SecretString;
/// let secret = SecretString::new("my_secret_password");
/// assert_eq!(format!("{}", secret), "******************");
/// assert_eq!(format!("{:?}", secret), "SecretString(******************)");
/// assert_eq!(secret.value(), "my_secret_password");
/// ```

#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SecretString<T>(T)
where
    T: AsRef<str>;

impl<T: AsRef<str>> SecretString<T> {
    pub fn new(s: T) -> Self {
        SecretString(s)
    }

    /// Returns the underlying value.
    pub fn value(&self) -> &str {
        self.0.as_ref()
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a string of asterisks (*) with the same length as the secret string.
    pub fn as_stars(&self) -> String {
        String::from("*").repeat(self.len())
    }

    /// In case you don't want to show the length of the secret
    pub fn as_stars_with_with_len(&self, len: usize) -> String {
        String::from("*").repeat(len)
    }
}

impl<T: AsRef<str>> From<T> for SecretString<T> {
    fn from(s: T) -> Self {
        SecretString(s)
    }
}

impl<T: AsRef<str>> std::fmt::Display for SecretString<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_stars())
    }
}

impl<T: AsRef<str>> Debug for SecretString<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString({})", self.as_stars())
    }
}

#[cfg(feature = "serde")]
impl<T: AsRef<str> + serde::Serialize> serde::Serialize for SecretString<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.value())
    }
}

#[cfg(feature = "serde")]
impl<'de, T: AsRef<str> + serde::Deserialize<'de>> serde::Deserialize<'de> for SecretString<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::new(serde::Deserialize::deserialize(deserializer)?))
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_secret_string_serde() {
        let secret = SecretString::new("my_secret_password");
        let serialized = serde_json::to_string(&secret).expect("Failed to serialize");
        assert_eq!(serialized, format!("\"{}\"", secret.value()));

        let deserialized: SecretString<_> =
            serde_json::from_str("\"my_secret_password\"").expect("Failed to deserialize");
        assert_eq!(deserialized, secret);
    }
}
