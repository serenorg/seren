#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsdCents(pub i64);

impl std::str::FromStr for UsdCents {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cents = parse_decimal_to_scaled_i64(s, 2)?;
        Ok(Self(cents))
    }
}

fn parse_decimal_to_scaled_i64(input: &str, scale: u32) -> Result<i64, String> {
    let mut s = input.trim();
    if let Some(rest) = s.strip_prefix('$') {
        s = rest.trim();
    }
    if s.is_empty() {
        return Err("Amount is required (example: 10.00)".to_string());
    }
    if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }
    if s.starts_with('-') {
        return Err("Amount must be non-negative".to_string());
    }

    let mut parts = s.split('.');
    let whole_str = parts.next().unwrap_or_default();
    let frac_str = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err("Invalid amount: too many decimal points".to_string());
    }

    let whole = parse_digits_u64(whole_str)?;
    let frac = parse_fraction_to_scale(frac_str, scale)?;

    let scale_factor = 10_i64
        .checked_pow(scale)
        .ok_or_else(|| "Invalid scale".to_string())?;

    let whole_i64: i64 = whole
        .try_into()
        .map_err(|_| "Amount is too large".to_string())?;

    whole_i64
        .checked_mul(scale_factor)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| "Amount is too large".to_string())
}

fn parse_digits_u64(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Ok(0);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Invalid amount: expected digits (example: 10.00)".to_string());
    }
    s.parse::<u64>()
        .map_err(|_| "Amount is too large".to_string())
}

fn parse_fraction_to_scale(frac: &str, scale: u32) -> Result<i64, String> {
    if frac.is_empty() {
        return Ok(0);
    }
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Invalid amount: expected digits after decimal point".to_string());
    }

    let frac_len: u32 = frac
        .len()
        .try_into()
        .map_err(|_| "Invalid amount".to_string())?;
    if frac_len > scale {
        return Err(format!(
            "Invalid amount: too many decimal places (max {scale})"
        ));
    }

    let mut value: i64 = frac
        .parse::<i64>()
        .map_err(|_| "Invalid amount".to_string())?;

    // Right-pad with zeros to the target scale.
    for _ in 0..(scale - frac_len) {
        value = value
            .checked_mul(10)
            .ok_or_else(|| "Amount is too large".to_string())?;
    }

    Ok(value)
}
