use common_enums::enums;
use common_utils::{pii::Email, request::Method, types::StringMajorUnit};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::{BankRedirectData, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{ConnectorCustomerResponseData, PaymentsResponseData, RedirectForm},
    types::{ConnectorCustomerRouterData, PaymentsAuthorizeRouterData},
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::ResponseRouterData,
    utils::{self, PaymentsAuthorizeRequestData, RouterData as _},
};

pub struct SaltedgeRouterData<T> {
    pub amount: StringMajorUnit,
    pub router_data: T,
}

impl<T> From<(StringMajorUnit, T)> for SaltedgeRouterData<T> {
    fn from((amount, item): (StringMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

/// A Salt Edge application's API key, and the private key that signs every
/// request. Its public half is uploaded to Salt Edge's dashboard.
pub struct SaltedgeAuthType {
    pub(super) app_id: Secret<String>,
    pub(super) secret: Secret<String>,
    pub(super) private_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for SaltedgeAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                app_id: api_key.to_owned(),
                secret: key1.to_owned(),
                private_key: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// `template_identifier`: the payment scheme, which the currency decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SaltedgeTemplate {
    /// UK Faster Payments, to a sort code and account number.
    #[serde(rename = "FPS")]
    Fps,
    /// SEPA Credit Transfer, to an IBAN.
    #[serde(rename = "SEPA")]
    Sepa,
    /// SEPA Instant Credit Transfer, to an IBAN.
    #[serde(rename = "SEPA_INSTANT")]
    SepaInstant,
}

/// Per-account settings from the connector's metadata (the dashboard's
/// connector form). The creditor is the merchant's own account: the payer's
/// bank pays it directly, and Salt Edge never holds the funds.
#[derive(Debug, Default, Deserialize)]
pub struct SaltedgeConnectorMetadata {
    creditor_name: Option<Secret<String>>,
    creditor_iban: Option<Secret<String>>,
    creditor_sort_code: Option<Secret<String>>,
    creditor_account_number: Option<Secret<String>>,
    /// `SEPA_INSTANT` (the default) or `SEPA`, for EUR payments.
    eur_scheme: Option<String>,
    /// `show` offers Salt Edge's fake and sandbox banks in the widget. Only for
    /// an application in Test status: Live customers must not see them.
    test_banks: Option<String>,
}

impl TryFrom<&Option<common_utils::pii::SecretSerdeValue>> for SaltedgeConnectorMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        connector_metadata: &Option<common_utils::pii::SecretSerdeValue>,
    ) -> Result<Self, Self::Error> {
        match connector_metadata {
            None => Ok(Self::default()),
            Some(_) => utils::to_connector_meta_from_secret(connector_metadata.clone())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "metadata",
                }),
        }
    }
}

/// A form field left empty may be saved as `""`.
fn filled(value: &Option<Secret<String>>) -> Option<String> {
    value
        .as_ref()
        .map(|value| value.peek().trim().to_string())
        .filter(|value| !value.is_empty())
}

/// ISO 13616: a country code, two check digits and up to 30 letters or
/// digits, whose mod-97 remainder (first four characters moved to the end,
/// letters counted 10 to 35) is 1. Catches most typos, which would otherwise
/// pay someone else's account or fail only at the payer's bank.
fn is_valid_iban(iban: &str) -> bool {
    let well_formed = (15..=34).contains(&iban.len())
        && iban
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        && iban.chars().take(2).all(|c| c.is_ascii_uppercase())
        && iban.chars().skip(2).take(2).all(|c| c.is_ascii_digit());
    well_formed
        && iban
            .chars()
            .skip(4)
            .chain(iban.chars().take(4))
            .filter_map(|c| c.to_digit(36))
            .fold(0, |remainder, value| {
                let shift = if value < 10 { 10 } else { 100 };
                (remainder * shift + value) % 97
            })
            == 1
}

/// The creditor's account in the format of the scheme the currency goes by.
#[derive(Debug, PartialEq, Eq)]
pub struct SaltedgeCreditor {
    template: SaltedgeTemplate,
    name: Secret<String>,
    iban: Option<Secret<String>>,
    sort_code: Option<Secret<String>>,
    account_number: Option<Secret<String>>,
}

impl SaltedgeConnectorMetadata {
    /// Run when the connector account is saved, so a mistyped IBAN or scheme
    /// is refused in the dashboard rather than at the first payment.
    pub fn validate(&self) -> Result<(), error_stack::Report<errors::ConnectorError>> {
        if filled(&self.creditor_iban).is_some() {
            self.creditor_iban()?;
        }
        self.eur_template()?;
        Ok(())
    }

    fn creditor_iban(&self) -> Result<Secret<String>, error_stack::Report<errors::ConnectorError>> {
        let iban = filled(&self.creditor_iban)
            .map(|iban| iban.replace(' ', "").to_uppercase())
            .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.creditor_iban (needed for EUR payments)",
            })?;
        if !is_valid_iban(&iban) {
            return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.creditor_iban",
            })
            .attach_printable("the creditor IBAN fails the ISO 13616 check"));
        }
        Ok(Secret::new(iban))
    }

    pub fn include_test_banks(&self) -> bool {
        self.test_banks
            .as_deref()
            .is_some_and(|test_banks| test_banks.trim().eq_ignore_ascii_case("show"))
    }

    fn eur_template(
        &self,
    ) -> Result<SaltedgeTemplate, error_stack::Report<errors::ConnectorError>> {
        match self.eur_scheme.as_deref().map(str::trim) {
            None | Some("") | Some("SEPA_INSTANT") => Ok(SaltedgeTemplate::SepaInstant),
            Some("SEPA") => Ok(SaltedgeTemplate::Sepa),
            Some(_) => Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.eur_scheme (SEPA_INSTANT or SEPA)",
            })),
        }
    }

    /// GBP goes by Faster Payments to a sort code and account number; EUR by
    /// SEPA to an IBAN. Each needs its own account in the connector form, and
    /// any other currency has no scheme here.
    pub fn creditor_for(
        &self,
        currency: enums::Currency,
    ) -> Result<SaltedgeCreditor, error_stack::Report<errors::ConnectorError>> {
        let name =
            filled(&self.creditor_name).ok_or(errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.creditor_name",
            })?;
        match currency {
            enums::Currency::GBP => {
                let sort_code = filled(&self.creditor_sort_code)
                    .map(|sort_code| sort_code.replace(['-', ' '], ""))
                    .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                        config: "metadata.creditor_sort_code (needed for GBP payments)",
                    })?;
                let account_number = filled(&self.creditor_account_number)
                    .map(|account_number| account_number.replace(' ', ""))
                    .ok_or(errors::ConnectorError::InvalidConnectorConfig {
                        config: "metadata.creditor_account_number (needed for GBP payments)",
                    })?;
                Ok(SaltedgeCreditor {
                    template: SaltedgeTemplate::Fps,
                    name: Secret::new(name),
                    iban: None,
                    sort_code: Some(Secret::new(sort_code)),
                    account_number: Some(Secret::new(account_number)),
                })
            }
            enums::Currency::EUR => {
                let iban = self.creditor_iban()?;
                Ok(SaltedgeCreditor {
                    template: self.eur_template()?,
                    name: Secret::new(name),
                    iban: Some(iban),
                    sort_code: None,
                    account_number: None,
                })
            }
            _ => Err(report!(errors::ConnectorError::NotSupported {
                message: format!(
                    "{currency} (Salt Edge pays GBP by Faster Payments and EUR by SEPA)"
                ),
                connector: "saltedge".into(),
            })),
        }
    }
}

/// `POST /api/v6/customers` for a Partner: the payer's email, which Salt Edge
/// keeps unique. A second customer with the same email is `409
/// DuplicatedCustomer`.
#[derive(Debug, Serialize)]
pub struct SaltedgeCustomerRequest {
    data: SaltedgeCustomerRequestData,
}

#[derive(Debug, Serialize)]
pub struct SaltedgeCustomerRequestData {
    email: Email,
}

/// The payer's email, from the payment or else its billing address.
fn payer_email<F, Req, Res>(
    router_data: &RouterData<F, Req, Res>,
    email: &Option<Email>,
) -> Option<Email> {
    email
        .clone()
        .or_else(|| router_data.get_optional_billing_email())
}

impl TryFrom<&ConnectorCustomerRouterData> for SaltedgeCustomerRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &ConnectorCustomerRouterData) -> Result<Self, Self::Error> {
        let email =
            payer_email(item, &item.request.email).ok_or_else(utils::missing_field_err("email"))?;
        Ok(Self {
            data: SaltedgeCustomerRequestData { email },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeCustomerResponse {
    data: SaltedgeCustomer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeCustomer {
    customer_id: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, SaltedgeCustomerResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, SaltedgeCustomerResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let customer_id = item.response.data.customer_id;
        Ok(Self {
            connector_customer: Some(customer_id.clone()),
            response: Ok(PaymentsResponseData::ConnectorCustomerResponse(
                ConnectorCustomerResponseData::new_with_customer_id(customer_id),
            )),
            ..item.data
        })
    }
}

/// Characters Salt Edge says most banks accept in a payment's description,
/// `[A-Za-z0-9.,\-/()+'? ]`. SEPA's own set is close to it.
fn is_remittance_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " .,-/()+'?".contains(c)
}

/// SEPA's remittance information holds 140 characters.
const DESCRIPTION_MAX_LENGTH: usize = 140;

/// The description on the payer's bank statement: the payment's own, without
/// characters banks refuse, else one naming the payment.
pub fn payment_description(description: Option<&str>, end_to_end_id: &str) -> String {
    let cleaned: String = description
        .unwrap_or_default()
        .chars()
        .filter(|c| is_remittance_char(*c))
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let description = if cleaned.chars().count() < 2 {
        format!("Payment {end_to_end_id}")
    } else {
        cleaned
    };
    description.chars().take(DESCRIPTION_MAX_LENGTH).collect()
}

/// An end-to-end id holds 35 characters in both SEPA and Faster Payments.
const END_TO_END_ID_MAX_LENGTH: usize = 35;

/// The payment's reference as the end-to-end id the merchant reconciles by.
/// Hyperswitch's ids carry `_`, which SEPA's character set lacks, so it
/// becomes `-`.
pub fn end_to_end_id(
    reference: &str,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let length = reference.chars().count();
    if length > END_TO_END_ID_MAX_LENGTH {
        return Err(report!(errors::ConnectorError::MaxFieldLengthViolated {
            connector: "saltedge".to_string(),
            field_name: "end_to_end_id".to_string(),
            max_length: END_TO_END_ID_MAX_LENGTH,
            received_length: length,
        }));
    }
    Ok(reference
        .chars()
        .map(|c| {
            if is_remittance_char(c) && c != ' ' {
                c
            } else {
                '-'
            }
        })
        .collect())
}

#[derive(Debug, Serialize)]
pub struct SaltedgePaymentAttributes {
    amount: StringMajorUnit,
    currency_code: enums::Currency,
    end_to_end_id: String,
    description: String,
    customer_ip_address: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer_user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debtor_name: Option<Secret<String>>,
    creditor_name: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creditor_iban: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creditor_sort_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creditor_account_number: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct SaltedgeProviderOptions {
    include_sandboxes: bool,
}

/// Sent back on every callback for this payment.
#[derive(Debug, Serialize)]
pub struct SaltedgeCustomFields {
    reference: String,
}

#[derive(Debug, Serialize)]
pub struct SaltedgeAttemptOptions {
    return_to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale: Option<String>,
    custom_fields: SaltedgeCustomFields,
}

/// `POST /api/v6/payments/create`. Salt Edge answers with `payment_url`, its
/// widget, where the payer picks a bank and authorises the payment there.
#[derive(Debug, Serialize)]
pub struct SaltedgePaymentRequest {
    data: SaltedgePaymentRequestData,
}

#[derive(Debug, Serialize)]
pub struct SaltedgePaymentRequestData {
    customer_id: String,
    template_identifier: SaltedgeTemplate,
    payment_attributes: SaltedgePaymentAttributes,
    provider: SaltedgeProviderOptions,
    attempt: SaltedgeAttemptOptions,
}

impl TryFrom<&SaltedgeRouterData<&PaymentsAuthorizeRouterData>> for SaltedgePaymentRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &SaltedgeRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        match &router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(BankRedirectData::OpenBanking { .. }) => {}
            _ => {
                return Err(report!(errors::ConnectorError::NotImplemented(
                    utils::get_unimplemented_payment_method_error_message("saltedge"),
                )))
            }
        }

        // A Partner's payment must name a Salt Edge customer, which the router
        // creates from the payer's email before this request. It is missing
        // when there was no email, or when Salt Edge already had a customer with
        // it (`DuplicatedCustomer`): a guest paying again, whose earlier customer
        // the router did not keep because there is no Hyperswitch customer to
        // keep it on.
        let customer_id = match router_data.connector_customer.clone() {
            Some(customer_id) => customer_id,
            None if payer_email(router_data, &router_data.request.email).is_none() => {
                return Err(utils::missing_field_err("email")());
            }
            None => return Err(utils::missing_field_err("customer_id")()),
        };

        let metadata = SaltedgeConnectorMetadata::try_from(&router_data.connector_meta_data)?;
        let creditor = metadata.creditor_for(router_data.request.currency)?;
        let end_to_end_id = end_to_end_id(&router_data.connector_request_reference_id)?;
        let browser_info = router_data.request.browser_info.as_ref();

        Ok(Self {
            data: SaltedgePaymentRequestData {
                customer_id,
                template_identifier: creditor.template,
                payment_attributes: SaltedgePaymentAttributes {
                    amount: item.amount.clone(),
                    currency_code: router_data.request.currency,
                    description: payment_description(
                        router_data.description.as_deref(),
                        &end_to_end_id,
                    ),
                    end_to_end_id,
                    customer_ip_address: router_data.request.get_ip_address()?.expose().into(),
                    customer_user_agent: router_data.request.get_optional_user_agent(),
                    debtor_name: router_data.get_optional_billing_full_name(),
                    creditor_name: creditor.name,
                    creditor_iban: creditor.iban,
                    creditor_sort_code: creditor.sort_code,
                    creditor_account_number: creditor.account_number,
                },
                provider: SaltedgeProviderOptions {
                    include_sandboxes: metadata.include_test_banks(),
                },
                attempt: SaltedgeAttemptOptions {
                    return_to: router_data.request.get_router_return_url()?,
                    locale: browser_info
                        .and_then(|browser_info| browser_info.language.as_deref())
                        .and_then(|language| language.split(['-', '_']).next())
                        .filter(|language| !language.is_empty())
                        .map(str::to_lowercase),
                    custom_fields: SaltedgeCustomFields {
                        reference: router_data.connector_request_reference_id.clone(),
                    },
                },
            },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeCreatePaymentResponse {
    data: SaltedgeCreatedPayment,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeCreatedPayment {
    payment_id: String,
    payment_url: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, SaltedgeCreatePaymentResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, SaltedgeCreatePaymentResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let payment = item.response.data;
        let payment_url = url::Url::parse(&payment.payment_url)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        Ok(Self {
            status: enums::AttemptStatus::AuthenticationPending,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.payment_id),
                redirection_data: Box::new(Some(RedirectForm::from((payment_url, Method::Get)))),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            }),
            ..item.data
        })
    }
}

/// A payment's `status`. `executed`, `settled` and `failed` are final; Salt
/// Edge may never report `settled` for a payment it reported `executed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltedgePaymentStatus {
    Initiated,
    InitiatedInfoRequired,
    Authorizing,
    Authorized,
    Executed,
    Settled,
    Failed,
    #[serde(other)]
    Unknown,
}

/// `initiated` waits for the payer at Salt Edge's widget. `executed` means the
/// payer's bank accepted the payment; that is as far as most banks report.
pub fn attempt_status(status: SaltedgePaymentStatus) -> enums::AttemptStatus {
    match status {
        SaltedgePaymentStatus::Initiated | SaltedgePaymentStatus::InitiatedInfoRequired => {
            enums::AttemptStatus::AuthenticationPending
        }
        SaltedgePaymentStatus::Authorizing
        | SaltedgePaymentStatus::Authorized
        | SaltedgePaymentStatus::Unknown => enums::AttemptStatus::Pending,
        SaltedgePaymentStatus::Executed | SaltedgePaymentStatus::Settled => {
            enums::AttemptStatus::Charged
        }
        SaltedgePaymentStatus::Failed => enums::AttemptStatus::Failure,
    }
}

/// `GET /api/v6/payments/{id}` answers `{data: payment}`. A verified callback
/// is turned into the same shape, so both are read the same way; only a
/// callback carries `error_class` and `error_message`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedgePaymentResponse {
    data: SaltedgePayment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaltedgePayment {
    id: String,
    status: SaltedgePaymentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_provider_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

impl SaltedgePayment {
    fn error_response(&self, http_code: u16) -> ErrorResponse {
        ErrorResponse {
            status_code: http_code,
            code: self
                .error_class
                .clone()
                .or_else(|| self.raw_provider_status.clone())
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: self
                .error_message
                .clone()
                .or_else(|| self.error_class.clone())
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: self.error_message.clone(),
            attempt_status: Some(enums::AttemptStatus::Failure),
            connector_transaction_id: Some(self.id.clone()),
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, SaltedgePaymentResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, SaltedgePaymentResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let payment = item.response.data;
        let status = attempt_status(payment.status);

        if status == enums::AttemptStatus::Failure {
            return Ok(Self {
                status,
                response: Err(payment.error_response(item.http_code)),
                ..item.data
            });
        }

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(payment.id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            }),
            ..item.data
        })
    }
}

/// Salt Edge's error body. The v6 reference lists the classes but not the
/// envelope, so both shapes Salt Edge uses elsewhere are read: `{error:
/// {class, message}}` and `{error_class, error_message}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeErrorResponse {
    #[serde(default)]
    pub error: Option<SaltedgeError>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaltedgeError {
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl SaltedgeErrorResponse {
    fn class(&self) -> Option<String> {
        self.error
            .as_ref()
            .and_then(|error| error.class.clone())
            .or_else(|| self.error_class.clone())
    }

    fn message_text(&self) -> Option<String> {
        self.error
            .as_ref()
            .and_then(|error| error.message.clone())
            .or_else(|| self.error_message.clone())
    }

    pub fn code(&self, http_code: u16) -> String {
        self.class().unwrap_or_else(|| http_code.to_string())
    }

    pub fn message(&self) -> String {
        self.message_text()
            .or_else(|| self.class())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string())
    }

    pub fn reason(&self) -> Option<String> {
        self.message_text()
    }
}

/// Salt Edge's Success, Failure and Notify callbacks:
/// `{data: {payment_id, customer_id, status, custom_fields, raw_provider_status,
/// error_class?, error_message?}, meta: {version, time}}`. The Provider changes
/// callback has no `payment_id`.
#[derive(Debug, Deserialize)]
pub struct SaltedgeWebhookBody {
    data: SaltedgeWebhookData,
}

#[derive(Debug, Deserialize)]
pub struct SaltedgeWebhookData {
    #[serde(default)]
    payment_id: Option<String>,
    #[serde(default)]
    status: Option<SaltedgePaymentStatus>,
    #[serde(default)]
    raw_provider_status: Option<String>,
    #[serde(default)]
    error_class: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

impl SaltedgeWebhookBody {
    pub fn event_type(&self) -> api_models::webhooks::IncomingWebhookEvent {
        use api_models::webhooks::IncomingWebhookEvent;

        match (&self.data.payment_id, self.data.status) {
            (Some(_), Some(SaltedgePaymentStatus::Executed | SaltedgePaymentStatus::Settled)) => {
                IncomingWebhookEvent::PaymentIntentSuccess
            }
            (Some(_), Some(SaltedgePaymentStatus::Failed)) => {
                IncomingWebhookEvent::PaymentIntentFailure
            }
            (Some(_), Some(_)) => IncomingWebhookEvent::PaymentIntentProcessing,
            _ => IncomingWebhookEvent::EventNotSupported,
        }
    }

    pub fn object_reference_id(
        &self,
    ) -> Result<api_models::webhooks::ObjectReferenceId, error_stack::Report<errors::ConnectorError>>
    {
        let payment_id = self
            .data
            .payment_id
            .clone()
            .ok_or(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(payment_id),
        ))
    }

    /// The payment as a status lookup would return it, for the payment flow to
    /// read once the callback's signature checks out.
    pub fn resource_object(
        self,
    ) -> Result<SaltedgePaymentResponse, error_stack::Report<errors::ConnectorError>> {
        let not_a_payment = || report!(errors::ConnectorError::WebhookResourceObjectNotFound);
        Ok(SaltedgePaymentResponse {
            data: SaltedgePayment {
                id: self.data.payment_id.ok_or_else(not_a_payment)?,
                status: self.data.status.ok_or_else(not_a_payment)?,
                raw_provider_status: self.data.raw_provider_status,
                error_class: self.data.error_class,
                error_message: self.data.error_message,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use common_enums::enums::{AttemptStatus, Currency};

    use super::*;

    fn metadata(value: serde_json::Value) -> SaltedgeConnectorMetadata {
        SaltedgeConnectorMetadata::try_from(&Some(Secret::new(value))).unwrap()
    }

    fn both_accounts() -> SaltedgeConnectorMetadata {
        metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "de89 3704 0044 0532 0130 00",
            "creditor_sort_code": "12-34-56",
            "creditor_account_number": "1234 5678",
        }))
    }

    #[test]
    fn gbp_goes_by_faster_payments_to_a_sort_code_and_account_number() {
        let creditor = both_accounts().creditor_for(Currency::GBP).unwrap();
        assert_eq!(creditor.template, SaltedgeTemplate::Fps);
        assert_eq!(creditor.sort_code.unwrap().peek(), "123456");
        assert_eq!(creditor.account_number.unwrap().peek(), "12345678");
        assert!(creditor.iban.is_none());
    }

    #[test]
    fn eur_goes_by_sepa_instant_to_an_iban() {
        let creditor = both_accounts().creditor_for(Currency::EUR).unwrap();
        assert_eq!(creditor.template, SaltedgeTemplate::SepaInstant);
        assert_eq!(creditor.iban.unwrap().peek(), "DE89370400440532013000");
        assert!(creditor.sort_code.is_none());
    }

    #[test]
    fn an_account_can_send_eur_by_plain_sepa() {
        let metadata = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "DE89370400440532013000",
            "eur_scheme": "SEPA",
        }));
        assert_eq!(
            metadata.creditor_for(Currency::EUR).unwrap().template,
            SaltedgeTemplate::Sepa
        );
    }

    #[test]
    fn a_currency_without_its_account_is_a_configuration_error() {
        let metadata = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "DE89370400440532013000",
            "creditor_sort_code": "",
        }));
        assert!(matches!(
            metadata
                .creditor_for(Currency::GBP)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::InvalidConnectorConfig { .. }
        ));
    }

    #[test]
    fn ibans_from_several_countries_pass_the_check() {
        for iban in [
            "DE89370400440532013000",
            "GB82WEST12345698765432",
            "NO9386011117947",
            "FR1420041010050500013M02606",
            "MT84MALT011000012345MTLCAST001S",
        ] {
            assert!(is_valid_iban(iban), "{iban}");
        }
    }

    #[test]
    fn an_iban_with_a_typo_fails_the_check() {
        // One digit changed, two digits swapped, a bad country code, too short.
        for iban in [
            "DE89370400440532013001",
            "DE89370400440532031000",
            "D189370400440532013000",
            "DE8937040044",
        ] {
            assert!(!is_valid_iban(iban), "{iban}");
        }
    }

    #[test]
    fn a_mistyped_iban_is_refused_before_salt_edge_is_called() {
        let metadata = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "DE89 3704 0044 0532 0130 01",
        }));
        assert!(matches!(
            metadata
                .creditor_for(Currency::EUR)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::InvalidConnectorConfig {
                config: "metadata.creditor_iban"
            }
        ));
    }

    #[test]
    fn saving_the_account_refuses_a_mistyped_iban_or_scheme() {
        let bad_iban = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "DE89370400440532013001",
        }));
        assert!(bad_iban.validate().is_err());
        let bad_scheme = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "eur_scheme": "SEPA_FAST",
        }));
        assert!(bad_scheme.validate().is_err());
    }

    #[test]
    fn saving_a_gbp_only_account_needs_no_iban() {
        let metadata = metadata(serde_json::json!({
            "creditor_name": "Pinnacle Ltd",
            "creditor_iban": "",
            "creditor_sort_code": "12-34-56",
            "creditor_account_number": "12345678",
        }));
        assert!(metadata.validate().is_ok());
        assert!(both_accounts().validate().is_ok());
    }

    #[test]
    fn another_currency_is_not_supported() {
        assert!(matches!(
            both_accounts()
                .creditor_for(Currency::PLN)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));
    }

    #[test]
    fn test_banks_are_hidden_unless_the_account_shows_them() {
        assert!(!both_accounts().include_test_banks());
        assert!(metadata(serde_json::json!({"test_banks": "show"})).include_test_banks());
        assert!(!metadata(serde_json::json!({"test_banks": "hide"})).include_test_banks());
    }

    #[test]
    fn statuses_map_to_attempt_statuses() {
        let cases = [
            (
                SaltedgePaymentStatus::Initiated,
                AttemptStatus::AuthenticationPending,
            ),
            (
                SaltedgePaymentStatus::InitiatedInfoRequired,
                AttemptStatus::AuthenticationPending,
            ),
            (SaltedgePaymentStatus::Authorizing, AttemptStatus::Pending),
            (SaltedgePaymentStatus::Authorized, AttemptStatus::Pending),
            (SaltedgePaymentStatus::Executed, AttemptStatus::Charged),
            (SaltedgePaymentStatus::Settled, AttemptStatus::Charged),
            (SaltedgePaymentStatus::Failed, AttemptStatus::Failure),
        ];
        for (status, expected) in cases {
            assert_eq!(attempt_status(status), expected, "{status:?}");
        }
    }

    #[test]
    fn a_status_salt_edge_adds_later_is_still_pending() {
        let status: SaltedgePaymentStatus = serde_json::from_str("\"rejected_later\"").unwrap();
        assert_eq!(attempt_status(status), AttemptStatus::Pending);
    }

    #[test]
    fn a_description_keeps_only_what_banks_accept() {
        assert_eq!(
            payment_description(Some("Order #42: café & co"), "pay-1"),
            "Order 42 caf co"
        );
    }

    #[test]
    fn a_payment_without_a_description_is_named_by_its_reference() {
        assert_eq!(payment_description(None, "pay-1"), "Payment pay-1");
        assert_eq!(payment_description(Some("#"), "pay-1"), "Payment pay-1");
    }

    #[test]
    fn a_long_description_is_cut_at_140_characters() {
        let description = "a".repeat(200);
        assert_eq!(payment_description(Some(&description), "pay-1").len(), 140);
    }

    #[test]
    fn the_end_to_end_id_is_the_reference_in_seps_characters() {
        assert_eq!(
            end_to_end_id("pay_AXr4vWTIZ8V9gt165OR3_1").unwrap(),
            "pay-AXr4vWTIZ8V9gt165OR3-1"
        );
    }

    #[test]
    fn an_end_to_end_id_over_35_characters_is_refused() {
        assert!(end_to_end_id(&"a".repeat(36)).is_err());
        assert!(end_to_end_id(&"a".repeat(35)).is_ok());
    }

    #[test]
    fn both_error_envelopes_are_read() {
        let nested: SaltedgeErrorResponse = serde_json::from_str(
            r#"{"error":{"class":"DuplicatedCustomer","message":"The customer already exists"}}"#,
        )
        .unwrap();
        assert_eq!(nested.code(409), "DuplicatedCustomer");
        assert_eq!(nested.message(), "The customer already exists");

        let flat: SaltedgeErrorResponse =
            serde_json::from_str(r#"{"error_class":"PaymentNotFound"}"#).unwrap();
        assert_eq!(flat.code(404), "PaymentNotFound");
        assert_eq!(flat.message(), "PaymentNotFound");
    }

    fn callback(body: &str) -> SaltedgeWebhookBody {
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn callbacks_map_to_payment_events() {
        use api_models::webhooks::IncomingWebhookEvent;
        let success = callback(
            r#"{"data":{"payment_id":"111","customer_id":"222","status":"executed","custom_fields":{},"raw_provider_status":"ACTC"},"meta":{"version":"6","time":"2024-10-01T08:16:12.799Z"}}"#,
        );
        assert_eq!(
            success.event_type(),
            IncomingWebhookEvent::PaymentIntentSuccess
        );

        let failure = callback(
            r#"{"data":{"payment_id":"111","customer_id":"222","status":"failed","error_class":"Unfinished","error_message":"Payment abandoned.","custom_fields":{},"raw_provider_status":null},"meta":{"version":"6","time":"2024-10-01T08:16:12.799Z"}}"#,
        );
        assert_eq!(
            failure.event_type(),
            IncomingWebhookEvent::PaymentIntentFailure
        );
        let payment = failure.resource_object().unwrap().data;
        assert_eq!(payment.error_response(200).code, "Unfinished");
        assert_eq!(payment.error_response(200).message, "Payment abandoned.");

        let notify = callback(
            r#"{"data":{"payment_id":"111","customer_id":"222","status":"authorizing","custom_fields":{},"raw_provider_status":"ACCP"},"meta":{"version":"6","time":"2024-10-01T08:16:12.799Z"}}"#,
        );
        assert_eq!(
            notify.event_type(),
            IncomingWebhookEvent::PaymentIntentProcessing
        );
    }

    #[test]
    fn a_provider_change_is_acknowledged_and_ignored() {
        use api_models::webhooks::IncomingWebhookEvent;
        let provider_change = callback(
            r#"{"data":{"provider_status":"inactive","provider_code":"fake_client_xf"},"meta":{"version":5,"time":"2023-09-21T09:49:13.472Z"}}"#,
        );
        assert_eq!(
            provider_change.event_type(),
            IncomingWebhookEvent::EventNotSupported
        );
        assert!(provider_change.object_reference_id().is_err());
    }

    #[test]
    fn a_callback_reads_back_as_a_status_lookup() {
        let resource = callback(
            r#"{"data":{"payment_id":"111","status":"settled"},"meta":{"version":"6","time":"t"}}"#,
        )
        .resource_object()
        .unwrap();
        let as_lookup: SaltedgePaymentResponse =
            serde_json::from_value(serde_json::to_value(resource).unwrap()).unwrap();
        assert_eq!(as_lookup.data.id, "111");
        assert_eq!(as_lookup.data.status, SaltedgePaymentStatus::Settled);
    }
}
