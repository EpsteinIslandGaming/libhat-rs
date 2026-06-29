use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignatureElement {
    value: u8,
    mask: u8,
}

impl SignatureElement {
    pub const fn new() -> Self {
        Self { value: 0, mask: 0 }
    }

    pub const fn from_value(value: u8) -> Self {
        Self { value, mask: 0xFF }
    }

    pub const fn from_value_mask(value: u8, mask: u8) -> Self {
        Self { value: value & mask, mask }
    }

    pub const fn wildcard() -> Self {
        Self { value: 0, mask: 0 }
    }

    pub const fn value(self) -> u8 {
        self.value
    }

    pub const fn mask(self) -> u8 {
        self.mask
    }

    pub const fn is_all(self) -> bool {
        self.mask == 0xFF
    }

    pub const fn is_any(self) -> bool {
        self.mask != 0
    }

    pub const fn is_none(self) -> bool {
        self.mask == 0
    }

    pub fn matches(self, byte: u8) -> bool {
        (byte & self.mask) == self.value
    }
}

impl From<u8> for SignatureElement {
    fn from(value: u8) -> Self {
        Self::from_value(value)
    }
}

pub type Signature = Vec<SignatureElement>;
pub type SignatureView<'a> = &'a [SignatureElement];
pub type FixedSignature<const N: usize> = [SignatureElement; N];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    MissingMaskedByte,
    ElementParseError,
    EmptySignature,
    ExpectedWildcard,
    InvalidTokenLength,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::MissingMaskedByte => write!(f, "signature missing masked byte"),
            SignatureError::ElementParseError => write!(f, "signature element parse error"),
            SignatureError::EmptySignature => write!(f, "empty signature"),
            SignatureError::ExpectedWildcard => write!(f, "expected wildcard"),
            SignatureError::InvalidTokenLength => write!(f, "invalid token length"),
        }
    }
}

pub type SignatureResult<T> = Result<T, SignatureError>;

fn parse_int(s: &str, base: u8) -> Option<u8> {
    u8::from_str_radix(s, base as u32).ok()
}

fn parse_signature_element(word: &str, base: u8) -> Option<SignatureElement> {
    let mut value: u8 = 0;
    let mut mask: u8 = 0;
    for ch in word.chars() {
        value = value.wrapping_mul(base);
        mask = mask.wrapping_mul(base);
        if ch != '?' {
            let digit = parse_int(&ch.to_string(), base)?;
            value += digit;
            mask += base - 1;
        }
    }
    Some(SignatureElement::from_value_mask(value, mask))
}

pub fn parse_signature_to(sig: &mut Vec<SignatureElement>, str: &str) -> SignatureResult<usize> {
    let mut written = 0;
    let mut contains_byte = false;

    for word in str.split(' ') {
        if word.is_empty() {
            continue;
        }
        match word.len() {
            1 => {
                if word.as_bytes()[0] != b'?' {
                    return Err(SignatureError::ExpectedWildcard);
                }
                sig.push(SignatureElement::wildcard());
                written += 1;
            }
            2 | 8 => {
                let base = if word.len() == 2 { 16 } else { 2 };
                let element = parse_signature_element(word, base)
                    .ok_or(SignatureError::ElementParseError)?;
                contains_byte |= element.is_all();
                sig.push(element);
                written += 1;
            }
            _ => return Err(SignatureError::InvalidTokenLength),
        }
    }

    if written == 0 {
        return Err(SignatureError::EmptySignature);
    }
    if !contains_byte {
        return Err(SignatureError::MissingMaskedByte);
    }
    Ok(written)
}

pub fn parse_signature(str: &str) -> SignatureResult<Signature> {
    let mut sig = Signature::new();
    parse_signature_to(&mut sig, str)?;
    Ok(sig)
}

pub fn bytes_to_signature<const N: usize>(bytes: &[u8; N]) -> FixedSignature<N> {
    let mut result = [SignatureElement::wildcard(); N];
    for (i, b) in bytes.iter().enumerate() {
        result[i] = SignatureElement::from_value(*b);
    }
    result
}

pub fn object_to_signature<T: Copy>(value: &T) -> Vec<SignatureElement> {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    bytes.iter().map(|b| SignatureElement::from_value(*b)).collect()
}

pub fn string_to_signature(str: &str) -> SignatureResult<Signature> {
    if str.is_empty() {
        return Err(SignatureError::EmptySignature);
    }
    Ok(str.bytes().map(SignatureElement::from_value).collect())
}

pub fn compile_signature<const N: usize>(str: &str) -> SignatureResult<FixedSignature<N>> {
    let mut sig = Signature::new();
    let size = parse_signature_to(&mut sig, str)?;
    if size > N {
        panic!("signature too large for fixed size");
    }
    let mut result = [SignatureElement::wildcard(); N];
    for (i, elem) in sig.iter().enumerate().take(size) {
        result[i] = *elem;
    }
    Ok(result)
}

pub fn to_string(sig: &[SignatureElement]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut ret = String::with_capacity(sig.len() * 3);
    for element in sig {
        let a = (element.mask() & 0xF0) == 0xF0;
        let b = (element.mask() & 0x0F) == 0x0F;
        if a || b {
            ret.push(if a {
                HEX[((element.value() >> 4) & 0x0F) as usize] as char
            } else {
                '?'
            });
            ret.push(if b {
                HEX[((element.value()) & 0x0F) as usize] as char
            } else {
                '?'
            });
            ret.push(' ');
        } else if element.is_none() {
            ret.push_str("? ");
        } else {
            for digit in (0..8).rev() {
                if element.mask() & (1 << digit) != 0 {
                    ret.push(if element.value() & (1 << digit) != 0 { '1' } else { '0' });
                } else {
                    ret.push('?');
                }
            }
            ret.push(' ');
        }
    }
    ret.pop();
    ret
}

/// Compile-time signature parsing via the `libhat-macros` proc-macro.
pub use libhat_macros::sig as sig_const;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signature() {
        let sig = parse_signature("48 8D 05 ? ? ? ? E8").unwrap();
        assert_eq!(sig.len(), 8);
        assert_eq!(sig[0].value(), 0x48);
        assert!(sig[0].is_all());
        assert_eq!(sig[1].value(), 0x8D);
        assert!(sig[1].is_all());
        assert!(sig[3].is_none());
        assert_eq!(sig[7].value(), 0xE8);
    }

    #[test]
    fn test_parse_signature_with_wildcards() {
        let sig = parse_signature("AB ? 12 ?3").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig[0].value(), 0xAB);
        assert!(sig[0].is_all());
        assert!(sig[1].is_none());
        assert_eq!(sig[2].value(), 0x12);
        assert!(sig[2].is_all());
        assert_eq!(sig[3].mask(), 0x0F);
    }

    #[test]
    fn test_to_string() {
        let sig = parse_signature("48 8D 05 ? ? ? ? E8").unwrap();
        let s = to_string(&sig);
        assert_eq!(s, "48 8D 05 ? ? ? ? E8");
    }

    #[test]
    fn test_empty_signature() {
        assert!(parse_signature("").is_err());
    }

    #[test]
    fn test_sig_macro() {
        let sig: &[SignatureElement] = &[
            SignatureElement::from_value(0x48),
            SignatureElement::from_value(0x8D),
            SignatureElement::from_value(0x05),
            SignatureElement::wildcard(),
            SignatureElement::wildcard(),
            SignatureElement::wildcard(),
            SignatureElement::wildcard(),
            SignatureElement::from_value(0xE8),
        ];
        assert_eq!(sig.len(), 8);
        assert_eq!(sig[0].value(), 0x48);
        assert!(sig[3].is_none());
    }

    #[test]
    fn test_signature_matches() {
        let sig = parse_signature("48 8D 05 ? ? ? ? E8").unwrap();
        let bytes = [0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01];
        for (elem, byte) in sig.iter().zip(bytes.iter()) {
            assert!(elem.matches(*byte));
        }
        assert!(!sig[0].matches(0x49));
    }
}
