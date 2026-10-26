//! Independent exact signed accumulation. Positive and negative magnitudes
//! are added separately in 256 bits, then cancelled before narrowing to i128.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Magnitude {
    high: u128,
    low: u128,
}
impl Magnitude {
    fn add(&mut self, amount: u128) -> Option<()> {
        let (low, carry) = self.low.overflowing_add(amount);
        self.high = self.high.checked_add(u128::from(carry))?;
        self.low = low;
        Some(())
    }
    fn subtract(self, other: Self) -> Option<u128> {
        let (low, borrow) = self.low.overflowing_sub(other.low);
        let high = self
            .high
            .checked_sub(other.high)?
            .checked_sub(u128::from(borrow))?;
        (high == 0).then_some(low)
    }
}
#[derive(Clone, Copy, Default)]
pub(in crate::report) struct Sum {
    positive: Magnitude,
    negative: Magnitude,
}
impl Sum {
    pub fn add(&mut self, value: i128, subtract: bool) -> Option<()> {
        if (value < 0) != subtract {
            self.negative.add(value.unsigned_abs())
        } else {
            self.positive.add(value.unsigned_abs())
        }
    }
    pub fn value(self) -> Option<i128> {
        if self.positive >= self.negative {
            i128::try_from(self.positive.subtract(self.negative)?).ok()
        } else {
            let magnitude = self.negative.subtract(self.positive)?;
            if magnitude == i128::MIN.unsigned_abs() {
                Some(i128::MIN)
            } else {
                i128::try_from(magnitude).ok()?.checked_neg()
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_precedes_narrowing_in_either_order() {
        for reverse in [false, true] {
            let mut values = [i128::MAX, i128::MAX, i128::MIN, i128::MIN, 5];
            if reverse {
                values.reverse();
            }
            let mut sum = Sum::default();
            for amount in values {
                sum.add(amount, false).unwrap();
            }
            assert_eq!(sum.value(), Some(3));
        }
    }
    #[test]
    fn true_overflow_and_minimum_negative_remain_distinct() {
        let mut sum = Sum::default();
        sum.add(i128::MAX, false).unwrap();
        sum.add(1, false).unwrap();
        assert_eq!(sum.value(), None);
        let mut negative = Sum::default();
        negative.add(i128::MIN, false).unwrap();
        assert_eq!(negative.value(), Some(i128::MIN));
        negative.add(1, true).unwrap();
        assert_eq!(negative.value(), None);
        negative.add(2, false).unwrap();
        assert_eq!(negative.value(), Some(i128::MIN + 1));
    }
}
