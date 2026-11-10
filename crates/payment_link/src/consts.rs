// Payment link constants

/// Default merchant logo link for payment links.
/// No logo: a link shows its own, else its theme's, else none. A placeholder
/// cannot be inlined here: the default is stored in the link's config, whose
/// XSS/SQLi check refuses a `data:` URI (its `;`, its `%` or its markup).
pub const DEFAULT_MERCHANT_LOGO: &str = "";

/// Relative path for the redirection log endpoint.
pub const REDIRECTION_LOG_ENDPOINT: &str = "logs/redirection";
