use std::io::{self, BufRead, IsTerminal, Write};

use zeroize::Zeroizing;

use crate::error::Error;

/// Read one secret.
///
/// An environment variable wins so tests do not need a terminal. A terminal
/// prompts without echo. Otherwise one line is read from stdin.
pub fn read_secret(env_key: &str, prompt: &str) -> Result<Zeroizing<String>, Error> {
    if let Ok(value) = std::env::var(env_key) {
        if !value.is_empty() {
            return Ok(Zeroizing::new(value));
        }
    }
    if io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush().map_err(Error::Read)?;
        let value = rpassword::read_password().map_err(Error::Read)?;
        eprintln!();
        if value.is_empty() {
            return Err(Error::MissingSecret);
        }
        return Ok(Zeroizing::new(value));
    }
    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(Error::Read)?;
    if read == 0 {
        return Err(Error::MissingSecret);
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    if line.is_empty() {
        return Err(Error::MissingSecret);
    }
    Ok(Zeroizing::new(line))
}
