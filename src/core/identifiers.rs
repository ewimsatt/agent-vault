//! Lexical validation for vault-controlled identifiers.
//!
//! These values are later used to construct paths under the vault, so they are
//! deliberately constrained independently of the host filesystem.

use std::path::{Component, Path};

use crate::error::VaultError;

pub fn validate_agent(name: &str) -> Result<(), VaultError> {
    validate_single_component("agent", name)
}

pub fn validate_group(name: &str) -> Result<(), VaultError> {
    validate_single_component("group", name)
}

pub fn validate_secret_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty() || path.contains('\\') || contains_control(path) || has_windows_prefix(path)
    {
        return invalid("secret path", path);
    }

    let mut count = 0;
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) if !part.is_empty() => count += 1,
            _ => return invalid("secret path", path),
        }
    }

    if count == 0
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return invalid("secret path", path);
    }

    Ok(())
}


fn validate_single_component(kind: &str, value: &str) -> Result<(), VaultError> {
    if value.is_empty()
        || value.contains(['/', '\\'])
        || contains_control(value)
        || has_windows_prefix(value)
    {
        return invalid(kind, value);
    }

    match Path::new(value).components().next() {
        Some(Component::Normal(part)) if part == value => Ok(()),
        _ => invalid(kind, value),
    }
}

fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn has_windows_prefix(value: &str) -> bool {
    value.len() >= 2 && value.as_bytes()[0].is_ascii_alphabetic() && value.as_bytes()[1] == b':'
}

fn invalid(kind: &str, value: &str) -> Result<(), VaultError> {
    Err(VaultError::InvalidIdentifier(format!(
        "invalid {kind}: {value:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_and_group_identifiers_must_be_single_normal_components() {
        for value in ["", ".", "..", "a/b", r"a\b", "/tmp", "C:temp", "bad\0name"] {
            assert!(
                validate_agent(value).is_err(),
                "agent {value:?} should fail"
            );
            assert!(
                validate_group(value).is_err(),
                "group {value:?} should fail"
            );
        }
        assert!(validate_agent("build.bot").is_ok());
        assert!(validate_group("production").is_ok());
    }

    #[test]
    fn secret_paths_allow_nested_normal_components_only() {
        assert!(validate_secret_path("stripe/production/api-key").is_ok());
        for value in [
            "",
            "/etc/passwd",
            "stripe//api",
            "stripe/./api",
            "stripe/../api",
            r"stripe\api",
            "C:temp",
        ] {
            assert!(
                validate_secret_path(value).is_err(),
                "secret path {value:?} should fail"
            );
        }
    }
}
