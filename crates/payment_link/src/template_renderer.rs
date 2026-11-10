use error_stack::{Result, ResultExt};
use tera::{Context, Tera};

use crate::types::{PaymentLinkFormData, PaymentLinkStatusData};

#[derive(Debug, thiserror::Error)]
pub enum PaymentLinkError {
    #[error("Failed to render template")]
    TemplateRenderError,
    #[error("Failed to build template")]
    TemplateBuildError,
}

pub fn build_payment_link_html(
    payment_link_data: PaymentLinkFormData,
) -> Result<String, PaymentLinkError> {
    let (tera, mut context) = build_payment_link_template(payment_link_data)
        .change_context(PaymentLinkError::TemplateBuildError)
        .attach_printable("Failed to build payment link's HTML template")?;

    let payment_link_initiator = include_str!(
        "../../router/src/core/payment_link/payment_link_initiate/payment_link_initiator.js"
    )
    .to_string();
    context.insert("payment_link_initiator", &payment_link_initiator);

    tera.render("payment_link", &context)
        .change_context(PaymentLinkError::TemplateRenderError)
        .attach_printable("Error while rendering open payment link's HTML template")
}

pub fn build_secure_payment_link_html(
    payment_link_data: PaymentLinkFormData,
) -> Result<String, PaymentLinkError> {
    let (tera, mut context) = build_payment_link_template(payment_link_data)
        .change_context(PaymentLinkError::TemplateBuildError)
        .attach_printable("Failed to build payment link's HTML template")?;

    let payment_link_initiator = include_str!(
        "../../router/src/core/payment_link/payment_link_initiate/secure_payment_link_initiator.js"
    )
    .to_string();
    context.insert("payment_link_initiator", &payment_link_initiator);

    tera.render("payment_link", &context)
        .change_context(PaymentLinkError::TemplateRenderError)
        .attach_printable("Error while rendering secure payment link's HTML template")
}

fn build_payment_link_template(
    payment_link_data: PaymentLinkFormData,
) -> Result<(Tera, Context), PaymentLinkError> {
    let mut tera = Tera::default();

    let css_template =
        include_str!("../../router/src/core/payment_link/payment_link_initiate/payment_link.css")
            .to_string();
    let _ = tera.add_raw_template("payment_link_css", &css_template);
    let mut context = Context::new();
    context.insert("css_color_scheme", &payment_link_data.css_script);

    let rendered_css = tera
        .render("payment_link_css", &context)
        .change_context(PaymentLinkError::TemplateRenderError)?;

    let js_template =
        include_str!("../../router/src/core/payment_link/payment_link_initiate/payment_link.js")
            .to_string();
    let _ = tera.add_raw_template("payment_link_js", &js_template);

    context.insert("payment_details_js_script", &payment_link_data.js_script);
    let sdk_origin = payment_link_data
        .sdk_url
        .host_str()
        .ok_or(PaymentLinkError::TemplateBuildError)
        .attach_printable("Host missing for payment link SDK URL")
        .and_then(|host| {
            if host == "localhost" {
                let port = payment_link_data
                    .sdk_url
                    .port()
                    .ok_or(PaymentLinkError::TemplateBuildError)
                    .attach_printable("Port missing for localhost in SDK URL")?;
                Ok(format!(
                    "{}://{}:{}",
                    payment_link_data.sdk_url.scheme(),
                    host,
                    port
                ))
            } else {
                Ok(format!("{}://{}", payment_link_data.sdk_url.scheme(), host))
            }
        })?;
    context.insert("sdk_origin", &sdk_origin);

    let rendered_js = tera
        .render("payment_link_js", &context)
        .change_context(PaymentLinkError::TemplateRenderError)?;

    let logging_template =
        include_str!("../../router/src/services/redirection/assets/redirect_error_logs_push.js")
            .to_string();
    let locale_template = include_str!("../../router/src/core/payment_link/locale.js").to_string();

    let html_template =
        include_str!("../../router/src/core/payment_link/payment_link_initiate/payment_link.html")
            .to_string();
    let _ = tera.add_raw_template("payment_link", &html_template);

    context.insert("rendered_meta_tag_html", &payment_link_data.html_meta_tags);
    context.insert(
        "preload_link_tags",
        &get_preload_link_html_template(&payment_link_data.sdk_url),
    );
    context.insert(
        "hyperloader_sdk_link",
        &get_hyper_loader_sdk(&payment_link_data.sdk_url),
    );
    context.insert("locale_template", &locale_template);
    context.insert("rendered_css", &rendered_css);
    context.insert("rendered_js", &rendered_js);
    context.insert("logging_template", &logging_template);
    context.insert(
        "redirection_log_endpoint",
        payment_link_data
            .redirection_log_endpoint
            .as_ref()
            .map(|endpoint| endpoint.as_str())
            .unwrap_or(""),
    );

    Ok((tera, context))
}

fn get_hyper_loader_sdk(sdk_url: &url::Url) -> String {
    format!("<script src=\"{sdk_url}\" onload=\"initializeSDK()\"></script>")
}

fn get_preload_link_html_template(sdk_url: &url::Url) -> String {
    format!(
        r#"<link rel="preload" href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800" as="style">
            <link rel="preload" href="{sdk_url}" as="script">"#,
    )
}

pub fn get_payment_link_status(
    payment_link_data: PaymentLinkStatusData,
) -> Result<String, PaymentLinkError> {
    let mut tera = Tera::default();

    // Add modification to css template with dynamic data
    let css_template =
        include_str!("../../router/src/core/payment_link/payment_link_status/status.css")
            .to_string();
    let _ = tera.add_raw_template("payment_link_css", &css_template);
    let mut context = Context::new();
    context.insert("css_color_scheme", &payment_link_data.css_script);

    let rendered_css = tera
        .render("payment_link_css", &context)
        .change_context(PaymentLinkError::TemplateRenderError)?;

    //Locale template
    let locale_template = include_str!("../../router/src/core/payment_link/locale.js");

    // Logging template
    let logging_template =
        include_str!("../../router/src/services/redirection/assets/redirect_error_logs_push.js")
            .to_string();

    // Add modification to js template with dynamic data
    let js_template =
        include_str!("../../router/src/core/payment_link/payment_link_status/status.js")
            .to_string();
    let _ = tera.add_raw_template("payment_link_js", &js_template);
    context.insert("payment_details_js_script", &payment_link_data.js_script);

    let rendered_js = tera
        .render("payment_link_js", &context)
        .change_context(PaymentLinkError::TemplateRenderError)?;

    // Make the backend-computed redirection log endpoint available to the
    // status.html template. The status page is rendered separately from the
    // payment initiate page, so it needs its own copy of the endpoint to keep
    // logs routed to the environment that generated the link. An empty string
    // is rendered for the WASM preview, where no real endpoint is available.
    context.insert(
        "redirection_log_endpoint",
        payment_link_data
            .redirection_log_endpoint
            .as_ref()
            .map(|endpoint| endpoint.as_str())
            .unwrap_or(""),
    );

    // Modify Html template with rendered js and rendered css files
    let html_template =
        include_str!("../../router/src/core/payment_link/payment_link_status/status.html")
            .to_string();
    let _ = tera.add_raw_template("payment_link_status", &html_template);

    context.insert("rendered_css", &rendered_css);
    context.insert("locale_template", &locale_template);

    context.insert("rendered_js", &rendered_js);
    context.insert("logging_template", &logging_template);

    tera.render("payment_link_status", &context)
        .change_context(PaymentLinkError::TemplateRenderError)
        .attach_printable("Error while rendering payment link status page")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consts::DEFAULT_MERCHANT_LOGO, get_js_script};

    /// What a page may name: the brand's own hosts and the fonts the pages
    /// load; never fetched, SVG's namespaces and the comment crediting the
    /// colour inversion the scripts use.
    const ALLOWED_HOSTS: [&str; 6] = [
        "sdk.brand.example",
        "api.brand.example",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "www.w3.org",
        "github.com",
    ];

    fn sdk_url() -> url::Url {
        url::Url::parse("https://sdk.brand.example/web/0.134.0/v1/HyperLoader.js")
            .expect("a valid URL")
    }

    fn log_endpoint() -> url::Url {
        url::Url::parse("https://api.brand.example/logs/redirection").expect("a valid URL")
    }

    /// The payment details a link without a logo of its own is rendered with.
    fn js_script(status: &str) -> String {
        get_js_script(&serde_json::json!({
            "merchant_logo": DEFAULT_MERCHANT_LOGO,
            "merchant_name": "Example Shop",
            "payment_id": "pay_example",
            "status": status,
        }))
        .expect("serialises")
    }

    fn link_data() -> PaymentLinkFormData {
        PaymentLinkFormData {
            js_script: js_script("requires_payment_method"),
            css_script: String::new(),
            sdk_url: sdk_url(),
            html_meta_tags: String::new(),
            redirection_log_endpoint: Some(log_endpoint()),
        }
    }

    /// Every host named after `http://` or `https://`, in the page as the
    /// browser reads it: the payment details reach it URL-encoded.
    fn hosts_named(page: &str) -> Vec<String> {
        let page = urlencoding::decode(page).expect("UTF-8").into_owned();
        ["http://", "https://"]
            .iter()
            .flat_map(|scheme| page.match_indices(scheme).map(|(at, _)| at + scheme.len()))
            .filter_map(|start| {
                let host: String = page
                    .get(start..)?
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                    .collect();
                (!host.is_empty()).then_some(host)
            })
            .collect()
    }

    fn assert_carries_no_outside_name(page: &str) {
        let decoded = urlencoding::decode(page).expect("UTF-8").to_lowercase();
        for name in ["hyperswitch", "juspay"] {
            assert!(!decoded.contains(name), "the page names {name}");
        }
        for host in hosts_named(page) {
            assert!(
                ALLOWED_HOSTS.contains(&host.as_str()),
                "the page names the host {host}"
            );
        }
    }

    #[test]
    fn a_payment_link_names_no_outside_host() {
        let page = build_payment_link_html(link_data()).expect("renders");
        assert_carries_no_outside_name(&page);
    }

    #[test]
    fn a_secure_payment_link_names_no_outside_host() {
        let page = build_secure_payment_link_html(link_data()).expect("renders");
        assert_carries_no_outside_name(&page);
    }

    #[test]
    fn a_payment_link_is_titled_payment_until_its_script_names_the_seller() {
        let page = build_payment_link_html(link_data()).expect("renders");
        assert!(page.contains("<title>Payment</title>"));
    }

    /// The default logo is stored in each link's config, which is checked for
    /// injection when the link is created.
    #[test]
    fn the_default_logo_passes_the_link_configs_injection_check() {
        assert!(!common_utils::validation::contains_potential_xss_or_sqli(
            DEFAULT_MERCHANT_LOGO
        ));
    }

    #[test]
    fn a_status_page_names_no_outside_host() {
        for status in ["succeeded", "processing", "failed", "expired"] {
            let page = get_payment_link_status(PaymentLinkStatusData {
                js_script: js_script(status),
                css_script: String::new(),
                redirection_log_endpoint: Some(log_endpoint()),
            })
            .expect("renders");
            assert_carries_no_outside_name(&page);
        }
    }
}
