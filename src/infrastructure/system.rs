//! Runs fixed, read-only commands with a time limit.
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

/// Runs a fixed command. Returns None when it is missing, fails or times out.
pub fn run(file: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_allowing_exit(file, args, None, timeout)
}

/// Like `run`, but one exit code means "no output" rather than failure (lsof exits 1 when nothing matches).
pub fn run_allowing_exit(file: &str, args: &[&str], empty_exit_code: Option<i32>, timeout: Duration) -> Option<String> {
    let mut child = Command::new(file).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let output = reader.join().ok()?;
    if status.success() {
        Some(output)
    } else if empty_exit_code.is_some() && status.code() == empty_exit_code {
        Some(String::new())
    } else {
        None
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn runs_a_command_and_returns_its_output() {
        assert_eq!(run("echo", &["hello"], COMMAND_TIMEOUT).as_deref(), Some("hello\n"));
    }

    #[test]
    fn a_missing_failing_or_slow_command_is_nothing() {
        assert_eq!(run("definitely-not-a-command", &[], COMMAND_TIMEOUT), None);
        assert_eq!(run("false", &[], COMMAND_TIMEOUT), None);
        assert_eq!(run("sleep", &["5"], Duration::from_millis(200)), None);
    }

    #[test]
    fn one_exit_code_can_mean_no_output() {
        assert_eq!(run_allowing_exit("false", &[], Some(1), COMMAND_TIMEOUT).as_deref(), Some(""));
        assert_eq!(run_allowing_exit("false", &[], Some(2), COMMAND_TIMEOUT), None);
    }
}
