//! Canonical derivation paths.

use alloc::{string::ToString, vec::Vec};
use core::{fmt, str::FromStr};

use crate::{Error, MAX_PATH_DEPTH, PATH_ENCODING_VERSION};

/// One explicitly typed derivation path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathSegment {
    /// A publicly derivable child index.
    Normal(u32),
    /// A private-only child index. It parses and serializes canonically, but
    /// derivation returns [`Error::HardenedDerivationUnsupported`].
    Hardened(u32),
}

impl PathSegment {
    /// Returns the numeric child index.
    pub const fn index(self) -> u32 {
        match self {
            Self::Normal(index) | Self::Hardened(index) => index,
        }
    }

    /// Returns whether this segment requests hardened derivation.
    pub const fn is_hardened(self) -> bool {
        matches!(self, Self::Hardened(_))
    }

    pub(crate) const fn kind(self) -> u8 {
        match self {
            Self::Normal(_) => 0,
            Self::Hardened(_) => 1,
        }
    }
}

/// A canonical, versioned path rooted at `m`.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivationPath {
    segments: Vec<PathSegment>,
}

impl DerivationPath {
    /// Creates the root path `m`.
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Creates a path from explicitly typed segments.
    pub fn new(segments: Vec<PathSegment>) -> Result<Self, Error> {
        if segments.len() > MAX_PATH_DEPTH {
            return Err(Error::PathTooDeep);
        }
        Ok(Self { segments })
    }

    /// Returns the path segments.
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// Returns the path depth.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Returns a child path without mutating this path.
    pub fn child(&self, segment: PathSegment) -> Result<Self, Error> {
        if self.segments.len() == MAX_PATH_DEPTH {
            return Err(Error::PathTooDeep);
        }
        let mut segments = self.segments.clone();
        segments.push(segment);
        Ok(Self { segments })
    }

    /// Serializes this path canonically.
    ///
    /// ```text
    /// version_u16 || count_u16 || (kind_u8 || index_u32_be)*
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(4 + self.segments.len() * 5);
        output.extend_from_slice(&PATH_ENCODING_VERSION.to_be_bytes());
        output.extend_from_slice(&(self.segments.len() as u16).to_be_bytes());
        for segment in &self.segments {
            output.push(segment.kind());
            output.extend_from_slice(&segment.index().to_be_bytes());
        }
        output
    }

    /// Parses the canonical binary path encoding.
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        if input.len() < 4 {
            return Err(Error::MalformedPathEncoding);
        }
        let (header, body) = input.split_at(4);
        let version = u16::from_be_bytes(
            header
                .get(0..2)
                .ok_or(Error::MalformedPathEncoding)?
                .try_into()
                .map_err(|_| Error::MalformedPathEncoding)?,
        );
        if version != PATH_ENCODING_VERSION {
            return Err(Error::UnsupportedPathVersion);
        }
        let count = u16::from_be_bytes(
            header
                .get(2..4)
                .ok_or(Error::MalformedPathEncoding)?
                .try_into()
                .map_err(|_| Error::MalformedPathEncoding)?,
        ) as usize;
        if count > MAX_PATH_DEPTH {
            return Err(Error::PathTooDeep);
        }
        let expected_len = 4usize
            .checked_add(count.checked_mul(5).ok_or(Error::MalformedPathEncoding)?)
            .ok_or(Error::MalformedPathEncoding)?;
        if input.len() != expected_len {
            return Err(Error::MalformedPathEncoding);
        }

        let mut segments = Vec::with_capacity(count);
        for chunk in body.chunks_exact(5) {
            let kind = *chunk.first().ok_or(Error::MalformedPathEncoding)?;
            let index = u32::from_be_bytes(
                chunk
                    .get(1..5)
                    .ok_or(Error::MalformedPathEncoding)?
                    .try_into()
                    .map_err(|_| Error::MalformedPathEncoding)?,
            );
            let segment = match kind {
                0 => PathSegment::Normal(index),
                1 => PathSegment::Hardened(index),
                _ => return Err(Error::UnknownSegmentKind),
            };
            segments.push(segment);
        }
        Self::new(segments)
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("m")?;
        for segment in &self.segments {
            match segment {
                PathSegment::Normal(index) => write!(formatter, "/{index}")?,
                PathSegment::Hardened(index) => write!(formatter, "/{index}'")?,
            }
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "m" {
            return Ok(Self::root());
        }
        let suffix = input.strip_prefix("m/").ok_or(Error::NonCanonicalPath)?;
        if suffix.is_empty() {
            return Err(Error::NonCanonicalPath);
        }

        let mut segments = Vec::new();
        for token in suffix.split('/') {
            if token.is_empty() {
                return Err(Error::NonCanonicalPath);
            }
            let (digits, hardened) = match token.strip_suffix('\'') {
                Some(digits) => (digits, true),
                None => (token, false),
            };
            if digits.is_empty()
                || !digits.as_bytes().iter().all(u8::is_ascii_digit)
                || (digits.len() > 1 && digits.starts_with('0'))
            {
                return Err(Error::NonCanonicalPath);
            }
            let index = digits.parse::<u32>().map_err(|_| Error::PathIndexOverflow)?;
            segments.push(if hardened {
                PathSegment::Hardened(index)
            } else {
                PathSegment::Normal(index)
            });
            if segments.len() > MAX_PATH_DEPTH {
                return Err(Error::PathTooDeep);
            }
        }

        let path = Self::new(segments)?;
        // This equality check prevents future parser changes from accidentally
        // accepting a second textual representation of the same path.
        if path.to_string() != input {
            return Err(Error::NonCanonicalPath);
        }
        Ok(path)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_text_and_binary_round_trip() {
        for text in ["m", "m/0", "m/1/4294967295", "m/0'/1"] {
            let path: DerivationPath = text.parse().expect("canonical path");
            assert_eq!(path.to_string(), text);
            assert_eq!(
                DerivationPath::from_bytes(&path.to_bytes()).expect("canonical bytes"),
                path
            );
        }
    }

    #[test]
    fn rejects_non_canonical_text() {
        for text in ["", "M", "m/", "m//1", "m/+1", "m/-1", "m/01", "m/1''"] {
            assert_eq!(text.parse::<DerivationPath>(), Err(Error::NonCanonicalPath));
        }
        assert_eq!(
            "m/4294967296".parse::<DerivationPath>(),
            Err(Error::PathIndexOverflow)
        );
    }

    #[test]
    fn rejects_malformed_binary() {
        assert_eq!(
            DerivationPath::from_bytes(&[0, 1, 0]),
            Err(Error::MalformedPathEncoding)
        );
        assert_eq!(
            DerivationPath::from_bytes(&[0, 2, 0, 0]),
            Err(Error::UnsupportedPathVersion)
        );
        assert_eq!(
            DerivationPath::from_bytes(&[0, 1, 0, 1, 2, 0, 0, 0, 0]),
            Err(Error::UnknownSegmentKind)
        );
    }
}
