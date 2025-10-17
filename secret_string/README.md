# secret-string

A lightweight Rust library that provides a wrapper around strings to prevent accidental exposure of sensitive data in logs, debug output, or error messages.

## Overview

`SecretString` wraps sensitive string data and replaces it with asterisks when printed or formatted for debugging. This helps prevent accidental leakage of passwords, API keys, tokens, and other sensitive information.

## Features

- Hides sensitive data when using `Display` trait (prints as asterisks)
- Hides sensitive data when using `Debug` trait (prints as `SecretString(**)`)
- Provides explicit `.value()` method to access the actual secret when needed
- Zero-copy wrapper - works with any type that implements `AsRef<str>`
- No external dependencies

## Installation

Add the package:

```shell
cargo add secret-string
```

## Usage

### Basic Example

```rust
use secret_string::SecretString;

fn main() {
    let password = SecretString::new("super_secret_password");

    // Printing the secret shows asterisks instead of the actual value
    println!("Password: {}", password);
    // Output: Password: *********************

    // Debug formatting also hides the value
    println!("Debug: {:?}", password);
    // Output: Debug: SecretString(*********************)

    // Access the actual value when needed
    if password.value() == "super_secret_password" {
        println!("Password is correct!");
    }
}
```

### Preventing Accidental Exposure

```rust
use secret_string::SecretString;

struct Config {
    api_key: SecretString<String>,
    database_password: SecretString<String>,
}

fn main() {
    let config = Config {
        api_key: SecretString::new("sk_live_1234567890".to_string()),
        database_password: SecretString::new("db_pass_xyz".to_string()),
    };

    // Safe to log - secrets won't be exposed
    println!("Config: {:?}", config);

    // Use the actual values only when needed
    let connection_string = format!(
        "postgres://user:{}@localhost/mydb",
        config.database_password.value()
    );
}
```

### With String Slices

```rust
use secret_string::SecretString;

fn authenticate(password: &str) -> bool {
    let secret = SecretString::new(password);

    // Even if this gets logged, the password won't be exposed
    println!("Authenticating with: {}", secret);

    // Use the actual value for comparison
    secret.value() == "correct_password"
}
```

## Contributing

This library is part of the [crabcakes](https://github.com/yaleman/crabcakes) project. Contributions are welcome.
