use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub enum HashError {
    Io(io::Error),
    FileTooLarge { path: String, size: u64, limit: u64 },
    Timeout { path: String },
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::FileTooLarge { path, size, limit } => {
                write!(f, "File too large: {path} ({size} bytes, limit {limit})")
            }
            Self::Timeout { path } => write!(f, "Timeout reading: {path}"),
        }
    }
}

fn open_with_retry(path: &Path) -> Result<std::fs::File, HashError> {
    let mut last_error = None;

    for attempt in 0..5 {
        match std::fs::File::open(path) {
            Ok(file) => return Ok(file),
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.kind() == io::ErrorKind::WouldBlock
                {
                    tracing::warn!(
                        "File locked, retrying (attempt {}/5): {}",
                        attempt + 1,
                        path.display()
                    );
                    last_error = Some(HashError::Io(e));
                    std::thread::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt)));
                } else {
                    return Err(HashError::Io(e));
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        HashError::Io(io::Error::new(io::ErrorKind::TimedOut, "max retries exceeded"))
    }))
}

pub fn sha256_hash(path: &Path) -> Result<String, HashError> {
    let metadata = std::fs::metadata(path).map_err(HashError::Io)?;
    let file_size = metadata.len();
    let max_size = 100 * 1024 * 1024;

    if file_size > max_size {
        return Err(HashError::FileTooLarge {
            path: path.display().to_string(),
            size: file_size,
            limit: max_size,
        });
    }

    let file = open_with_retry(path)?;

    let mut reader = io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    loop {
        if std::time::Instant::now() > deadline {
            return Err(HashError::Timeout {
                path: path.display().to_string(),
            });
        }
        let bytes_read = reader.read(&mut buffer).map_err(HashError::Io)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
