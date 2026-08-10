use totp_rs::{Algorithm, Builder, Secret, Totp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySpec {
    pub issuer: String,
    pub account: String,
    pub label: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
}

pub fn normalize_secret(value: &str) -> Result<String, String> {
    let mut normalized: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    while normalized.ends_with('=') {
        normalized.pop();
    }
    if normalized.is_empty()
        || normalized
            .chars()
            .any(|character| !matches!(character, 'A'..='Z' | '2'..='7'))
    {
        return Err("Invalid Base32 TOTP secret".to_owned());
    }
    Secret::try_from_base32(&normalized).map_err(|_| "Invalid Base32 TOTP secret".to_owned())?;
    Ok(normalized)
}

pub fn parse_algorithm(value: &str) -> Result<Algorithm, String> {
    match value.trim().to_ascii_uppercase().as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        _ => Err("Algorithm must be SHA1, SHA256, or SHA512".to_owned()),
    }
}

pub fn build_totp(entry: &EntrySpec) -> Result<Totp, String> {
    let secret = Secret::try_from_base32(&entry.secret)
        .map_err(|_| "Invalid Base32 TOTP secret".to_owned())?;
    if secret.as_bytes().len() < 10 {
        return Err("TOTP secret is too short".to_owned());
    }
    if entry.digits != 6 && entry.digits != 8 {
        return Err("Digits must be 6 or 8".to_owned());
    }
    if !(1..=86_400).contains(&entry.period) {
        return Err("Period must be between 1 and 86400 seconds".to_owned());
    }
    if entry.account.is_empty() || entry.account.contains(':') {
        return Err("Account is required and cannot contain ':'".to_owned());
    }
    if entry.issuer.contains(':') {
        return Err("Issuer cannot contain ':'".to_owned());
    }
    let algorithm = parse_algorithm(&entry.algorithm)?;
    let builder = Builder::new()
        .with_algorithm(algorithm)
        .with_digits(entry.digits)
        .with_step_duration(entry.period)
        .with_secret(secret.as_bytes().to_vec())
        .with_account_name(entry.account.clone());
    let builder = if entry.issuer.is_empty() {
        builder.with_issuer(None::<String>)
    } else {
        builder.with_issuer(Some(entry.issuer.clone()))
    };
    if secret.as_bytes().len() < 16 {
        Ok(builder.build_noncompliant())
    } else {
        builder
            .build()
            .map_err(|_| "TOTP settings are invalid".to_owned())
    }
}

pub fn parse_otpauth_uri(uri: &str) -> Result<EntrySpec, String> {
    let totp =
        Totp::from_url_unchecked(uri.trim()).map_err(|_| "Invalid otpauth URI".to_owned())?;
    let issuer = totp.issuer().unwrap_or_default().to_owned();
    let account = totp.account_name().to_owned();
    let secret = normalize_secret(&totp.secret().to_base32())?;
    let label = if issuer.is_empty() {
        account.clone()
    } else {
        issuer.clone()
    };
    Ok(EntrySpec {
        issuer,
        account,
        label,
        secret,
        algorithm: totp.algorithm().to_string(),
        digits: totp.digits(),
        period: totp.step(),
    })
}

pub fn make_otpauth_uri(entry: &EntrySpec) -> Result<String, String> {
    build_totp(entry)?
        .to_url()
        .map_err(|_| "Could not create otpauth URI".to_owned())
}

pub fn generate_code(entry: &EntrySpec, now: u64) -> Result<(String, i64), String> {
    let totp = build_totp(entry)?;
    let expires_at = totp.next_step(now) as i64 * 1000;
    Ok((totp.generate(now).to_string(), expires_at))
}

#[cfg(test)]
mod tests {
    use super::{generate_code, make_otpauth_uri, normalize_secret, parse_otpauth_uri, EntrySpec};

    #[test]
    fn generates_the_rfc_6238_sha1_vector() {
        let entry = EntrySpec {
            issuer: "RFC".to_owned(),
            account: "test".to_owned(),
            label: "RFC".to_owned(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned(),
            algorithm: "SHA1".to_owned(),
            digits: 8,
            period: 30,
        };
        let (code, expires_at) = generate_code(&entry, 59).unwrap();
        assert_eq!(code, "94287082");
        assert_eq!(expires_at, 60_000);
    }

    #[test]
    fn normalizes_and_validates_base32() {
        assert_eq!(
            normalize_secret(" jbsw y3dp ehpk 3pxp ").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(normalize_secret("not-a-secret").is_err());
    }

    #[test]
    fn parses_and_round_trips_otpauth_uri() {
        let uri = "otpauth://totp/GitHub:xin%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=SHA1";
        let entry = parse_otpauth_uri(uri).unwrap();
        assert_eq!(entry.issuer, "GitHub");
        assert_eq!(entry.account, "xin@example.com");
        assert_eq!(entry.secret, "JBSWY3DPEHPK3PXP");
        assert!(make_otpauth_uri(&entry)
            .unwrap()
            .starts_with("otpauth://totp/"));
    }
}
