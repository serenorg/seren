#[derive(Debug, thiserror::Error)]
pub enum MoneyParseError {
    #[error("Amount is required (example: {example})")]
    Empty { example: &'static str },
    #[error("Amount must be non-negative")]
    Negative,
    #[error("Invalid amount: expected digits (example: {example})")]
    InvalidDigits { example: &'static str },
    #[error("Invalid amount: expected digits after decimal point")]
    InvalidFractionDigits,
    #[error("Invalid amount: too many decimal points")]
    TooManyDecimalPoints,
    #[error("Invalid amount: too many decimal places (max {scale})")]
    TooManyDecimalPlaces { scale: u32 },
    #[error("Amount is too large")]
    TooLarge,
    #[error("Amount must be a finite number")]
    NotFinite,
}

pub fn parse_usd_to_cents(input: &str) -> Result<i64, MoneyParseError> {
    parse_decimal_to_scaled_i64(input, 2, "10.00")
}

pub fn parse_usd_to_micros(input: &str) -> Result<i64, MoneyParseError> {
    parse_decimal_to_scaled_i64(input, 6, "0.10")
}

pub fn usd_f64_to_cents(amount: f64) -> Result<i64, MoneyParseError> {
    f64_to_scaled_i64(amount, 2)
}

pub fn usd_f64_to_micros(amount: f64) -> Result<i64, MoneyParseError> {
    f64_to_scaled_i64(amount, 6)
}

pub fn format_usd_micros(micros: i64) -> String {
    format_scaled_i64(micros, 6)
}

fn parse_decimal_to_scaled_i64(
    input: &str,
    scale: u32,
    example: &'static str,
) -> Result<i64, MoneyParseError> {
    let mut s = input.trim();
    if let Some(rest) = s.strip_prefix('$') {
        s = rest.trim();
    }
    if s.is_empty() {
        return Err(MoneyParseError::Empty { example });
    }
    if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }
    if s.starts_with('-') {
        return Err(MoneyParseError::Negative);
    }

    let mut parts = s.split('.');
    let whole_str = parts.next().unwrap_or_default();
    let frac_str = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(MoneyParseError::TooManyDecimalPoints);
    }

    let whole = parse_digits_u64(whole_str, example)?;
    let frac = parse_fraction_to_scale(frac_str, scale)?;

    let scale_factor = 10_i64.checked_pow(scale).ok_or(MoneyParseError::TooLarge)?;
    let whole_i64: i64 = whole.try_into().map_err(|_| MoneyParseError::TooLarge)?;

    whole_i64
        .checked_mul(scale_factor)
        .and_then(|v| v.checked_add(frac))
        .ok_or(MoneyParseError::TooLarge)
}

fn parse_digits_u64(s: &str, example: &'static str) -> Result<u64, MoneyParseError> {
    if s.is_empty() {
        return Ok(0);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MoneyParseError::InvalidDigits { example });
    }
    s.parse::<u64>().map_err(|_| MoneyParseError::TooLarge)
}

fn parse_fraction_to_scale(frac: &str, scale: u32) -> Result<i64, MoneyParseError> {
    if frac.is_empty() {
        return Ok(0);
    }
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MoneyParseError::InvalidFractionDigits);
    }

    let frac_len: u32 = frac
        .len()
        .try_into()
        .map_err(|_| MoneyParseError::TooLarge)?;
    if frac_len > scale {
        return Err(MoneyParseError::TooManyDecimalPlaces { scale });
    }

    let mut value: i64 = frac.parse::<i64>().map_err(|_| MoneyParseError::TooLarge)?;
    for _ in 0..(scale - frac_len) {
        value = value.checked_mul(10).ok_or(MoneyParseError::TooLarge)?;
    }
    Ok(value)
}

fn f64_to_scaled_i64(amount: f64, scale: u32) -> Result<i64, MoneyParseError> {
    if !amount.is_finite() {
        return Err(MoneyParseError::NotFinite);
    }
    if amount < 0.0 {
        return Err(MoneyParseError::Negative);
    }

    let scale_factor = 10_f64.powi(scale as i32);
    let scaled = amount * scale_factor;

    if scaled > (i64::MAX as f64) {
        return Err(MoneyParseError::TooLarge);
    }
    Ok(scaled.round() as i64)
}

fn format_scaled_i64(amount: i64, scale: u32) -> String {
    let scale_factor: i64 = 10_i64.pow(scale);
    let amount_i128 = i128::from(amount);
    let scale_i128 = i128::from(scale_factor);

    let sign = if amount_i128 < 0 { "-" } else { "" };
    let abs = amount_i128.abs();
    let whole = abs / scale_i128;
    let frac = abs % scale_i128;

    if scale == 0 {
        return format!("{sign}{whole}");
    }

    format!("{sign}{whole}.{frac:0width$}", width = scale as usize)
}
