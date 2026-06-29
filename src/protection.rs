use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection(u8);

impl Protection {
    pub const READ: Protection = Protection(0b001);
    pub const WRITE: Protection = Protection(0b010);
    pub const EXECUTE: Protection = Protection(0b100);

    pub const fn empty() -> Self {
        Protection(0)
    }

    pub const fn from_bits(bits: u8) -> Self {
        Protection(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, other: Protection) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Protection {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Protection(self.0 | rhs.0)
    }
}

impl BitAnd for Protection {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Protection(self.0 & rhs.0)
    }
}

impl BitXor for Protection {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Protection(self.0 ^ rhs.0)
    }
}

impl BitOrAssign for Protection {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for Protection {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitXorAssign for Protection {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}
