use core::fmt;

/// Error returned when encoding or decoding an OmniBuf packet fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wire input violated framing, varint, bounds, or container invariants.
    Parse(String),
    /// Encoding a message failed validation.
    Serialize(String),
    /// A `WireString` payload contained invalid UTF-8 bytes.
    InvalidUtf8,
    /// Container or sub-message nesting exceeded `MAX_NESTING_DEPTH`.
    DepthLimitExceeded(usize),
}

impl Error {
    #[inline]
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    #[inline]
    pub fn serialize(msg: impl Into<String>) -> Self {
        Self::Serialize(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "omnibuf: {msg}"),
            Self::Serialize(msg) => write!(f, "omnibuf: {msg}"),
            Self::InvalidUtf8 => f.write_str("omnibuf: invalid UTF-8 in WireString"),
            Self::DepthLimitExceeded(depth) => {
                write!(
                    f,
                    "omnibuf: nesting depth {depth} exceeds MAX_NESTING_DEPTH ({})",
                    crate::wire::MAX_NESTING_DEPTH
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// Specialized result type for OmniBuf operations.
pub type Result<T> = core::result::Result<T, Error>;
