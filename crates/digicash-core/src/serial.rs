use crate::error::CoreError;

/// A 256-bit coin serial number.
///
/// Chosen by the wallet and never revealed to the bank until deposit; the gap between
/// blinded signing and deposit is what makes withdrawals unlinkable. Generated from the
/// OS CSPRNG (`getrandom`), never a userspace PRNG, per spec v0.2 section 3.
pub struct Serial([u8; 32]);

impl Serial {
    /// Generate a fresh serial from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CoreError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(CoreError::SerialGeneration)?;
        Ok(Self(bytes))
    }

    /// The raw 32 bytes, as fed to the blind-signature scheme.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Serial;

    #[test]
    fn generated_serials_are_full_width_and_distinct() {
        let a = Serial::generate().expect("OS CSPRNG available in test environment");
        let b = Serial::generate().expect("OS CSPRNG available in test environment");
        assert_eq!(a.as_bytes().len(), 32);
        assert!(
            a.as_bytes() != b.as_bytes(),
            "two independently generated serials collided"
        );
    }
}
