//! Another Hyperswitch deployment as the processor: its v1 merchant API, called
//! server to server with a secret API key of a merchant account it keeps for us.

use common_enums::enums;
use common_utils::{crypto::GenerateDigest, request::Method, types::MinorUnit};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::{CardRedirectData, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::{BrowserInformation, ResponseId},
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use time::PrimitiveDateTime;

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, PaymentsAuthorizeRequestData, RouterData as _},
};

/// The target's code for a resource it already has under the id we sent.
pub const DUPLICATE_ERROR_CODE: &str = "HE_01";
/// The target's code for a payment in the wrong state for the call, such as a
/// capture of a payment that is not waiting for one.
pub const UNEXPECTED_STATE_ERROR_CODE: &str = "IR_14";
/// What the target's ids may be: up to 64 of `[A-Za-z0-9_-]`.
const MAX_REFERENCE_LENGTH: usize = 64;
/// How long a payment link on the target stays open, in seconds. The router's
/// payment sync gives up after about 26 minutes, so a link has to close before.
const PAYMENT_LINK_EXPIRY_SECONDS: u32 = 900;

/// The error a missing or malformed Platform URL gives.
const PLATFORM_URL_CONFIG: &str =
    "metadata.platform_url (the target's https API URL, e.g. https://api.platform.example)";

pub struct HyperswitchRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for HyperswitchRouterData<T> {
    fn from((amount, item): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

pub struct HyperswitchAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for HyperswitchAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// Per-account settings from the connector's metadata (the dashboard's connector
/// form). Every account names the deployment it pays through: there is no
/// default target.
#[derive(Debug, Default, Deserialize)]
pub struct HyperswitchConnectorMetadata {
    pub platform_url: Option<String>,
    /// The target's business profile. Unset, the target uses its merchant's
    /// default profile, which it only has while there is one profile.
    pub profile_id: Option<String>,
}

impl TryFrom<&Option<common_utils::pii::SecretSerdeValue>> for HyperswitchConnectorMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    /// Also checks the Platform URL, so a missing or malformed one is refused
    /// when the account is saved rather than on its first payment.
    fn try_from(
        connector_metadata: &Option<common_utils::pii::SecretSerdeValue>,
    ) -> Result<Self, Self::Error> {
        let metadata: Self = match connector_metadata {
            None => Self::default(),
            Some(_) => utils::to_connector_meta_from_secret(connector_metadata.clone())
                .change_context(errors::ConnectorError::InvalidConnectorConfig {
                    config: "metadata",
                })?,
        };
        check_platform_url(metadata.platform_url().ok_or_else(invalid_platform_url)?)?;
        Ok(metadata)
    }
}

impl HyperswitchConnectorMetadata {
    fn platform_url(&self) -> Option<&str> {
        non_empty(self.platform_url.as_deref())
    }

    pub fn profile_id(&self) -> Option<String> {
        non_empty(self.profile_id.as_deref()).map(str::to_string)
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn invalid_platform_url() -> error_stack::Report<errors::ConnectorError> {
    report!(errors::ConnectorError::InvalidConnectorConfig {
        config: PLATFORM_URL_CONFIG,
    })
}

/// An https URL naming a host, with an optional path prefix for a deployment
/// served below one. No credentials, query or fragment.
fn check_platform_url(raw: &str) -> Result<(), error_stack::Report<errors::ConnectorError>> {
    let url = url::Url::parse(raw).map_err(|_| invalid_platform_url())?;
    let well_formed = url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    if well_formed {
        Ok(())
    } else {
        Err(invalid_platform_url())
    }
}

/// The base URL this account's requests go to, without a trailing slash.
pub fn platform_base_url(
    connector_metadata: &Option<common_utils::pii::SecretSerdeValue>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let metadata = HyperswitchConnectorMetadata::try_from(connector_metadata)?;
    let url = metadata.platform_url().ok_or_else(invalid_platform_url)?;
    Ok(url.trim_end_matches('/').to_string())
}

/// The `payment_id` the target gets for one attempt: the attempt's own id, which is
/// unique per attempt, so a retry is a new payment there and a lost answer can be
/// looked up by it. An attempt id longer than the target allows (a long
/// merchant-chosen payment id) is replaced by a stable digest of it.
pub fn reference_for_attempt(attempt_id: &str) -> String {
    if attempt_id.len() <= MAX_REFERENCE_LENGTH {
        return attempt_id.to_string();
    }
    let digest = common_utils::crypto::Sha256
        .generate_digest(attempt_id.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();
    format!("hs-{}", digest.get(..40).unwrap_or(&digest))
}

#[derive(Debug, Serialize)]
pub struct HyperswitchCard {
    card_number: cards::CardNumber,
    card_exp_month: Secret<String>,
    card_exp_year: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card_holder_name: Option<Secret<String>>,
    card_cvc: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct HyperswitchCardData {
    card: HyperswitchCard,
}

/// What every `POST /payments` carries.
#[derive(Debug, Serialize)]
pub struct HyperswitchPaymentFields {
    payment_id: String,
    amount: MinorUnit,
    currency: enums::Currency,
    capture_method: enums::CaptureMethod,
    return_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing: Option<api_models::payments::Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Our own payment id, so a payment can be found on the target by it.
    merchant_order_reference_id: String,
}

/// A card we hold, confirmed at once. 3DS comes back as a redirect the payer follows.
#[derive(Debug, Serialize)]
pub struct HyperswitchCardPaymentRequest {
    #[serde(flatten)]
    fields: HyperswitchPaymentFields,
    confirm: bool,
    payment_method: enums::PaymentMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_method_type: Option<enums::PaymentMethodType>,
    payment_method_data: HyperswitchCardData,
    authentication_type: enums::AuthenticationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    browser_info: Option<BrowserInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_partial_authorization: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct HyperswitchPaymentLinkConfig {
    /// Straight back to us once paid, without the target's status page.
    skip_status_screen: bool,
}

/// Card redirect: an unconfirmed payment with a payment link, where the payer
/// enters the card on the target's own page. We never see the card.
#[derive(Debug, Serialize)]
pub struct HyperswitchPaymentLinkRequest {
    #[serde(flatten)]
    fields: HyperswitchPaymentFields,
    confirm: bool,
    payment_link: bool,
    payment_link_config: HyperswitchPaymentLinkConfig,
    session_expiry: u32,
    allowed_payment_method_types: Vec<enums::PaymentMethodType>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HyperswitchPaymentsRequest {
    Card(Box<HyperswitchCardPaymentRequest>),
    PaymentLink(HyperswitchPaymentLinkRequest),
}

impl TryFrom<&HyperswitchRouterData<&PaymentsAuthorizeRouterData>> for HyperswitchPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &HyperswitchRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let capture_method = match router_data.request.capture_method {
            None | Some(enums::CaptureMethod::Automatic) => enums::CaptureMethod::Automatic,
            Some(enums::CaptureMethod::Manual) => enums::CaptureMethod::Manual,
            Some(other) => Err(errors::ConnectorError::NotSupported {
                message: format!("capture method {other}"),
                connector: "hyperswitch".into(),
            })?,
        };
        let metadata = HyperswitchConnectorMetadata::try_from(&router_data.connector_meta_data)?;
        let fields = HyperswitchPaymentFields {
            payment_id: router_data.connector_request_reference_id.clone(),
            amount: item.amount,
            currency: router_data.request.currency,
            capture_method,
            return_url: router_data.request.get_router_return_url()?,
            profile_id: metadata.profile_id(),
            billing: billing(router_data),
            description: router_data.description.clone(),
            merchant_order_reference_id: router_data.payment_id.clone(),
        };

        match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                Ok(Self::Card(Box::new(HyperswitchCardPaymentRequest {
                    fields,
                    confirm: true,
                    payment_method: enums::PaymentMethod::Card,
                    payment_method_type: router_data.request.payment_method_type,
                    payment_method_data: HyperswitchCardData {
                        card: HyperswitchCard {
                            card_number: card.card_number.clone(),
                            card_exp_month: card.card_exp_month.clone(),
                            card_exp_year: card.card_exp_year.clone(),
                            card_holder_name: card.card_holder_name.clone(),
                            card_cvc: card.card_cvc.clone(),
                        },
                    },
                    authentication_type: router_data.auth_type,
                    browser_info: router_data.request.browser_info.clone(),
                    enable_partial_authorization: router_data
                        .request
                        .enable_partial_authorization
                        .map(|enabled| *enabled)
                        .filter(|enabled| *enabled),
                })))
            }
            PaymentMethodData::CardRedirect(CardRedirectData::CardRedirect {}) => {
                Ok(Self::PaymentLink(HyperswitchPaymentLinkRequest {
                    fields,
                    confirm: false,
                    payment_link: true,
                    payment_link_config: HyperswitchPaymentLinkConfig {
                        skip_status_screen: true,
                    },
                    session_expiry: PAYMENT_LINK_EXPIRY_SECONDS,
                    allowed_payment_method_types: vec![
                        enums::PaymentMethodType::Credit,
                        enums::PaymentMethodType::Debit,
                    ],
                }))
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("hyperswitch"),
            ))?,
        }
    }
}

/// The billing address as the payer gave it, with the payment's email when the
/// address has none: the target's processor may need either.
fn billing(router_data: &PaymentsAuthorizeRouterData) -> Option<api_models::payments::Address> {
    let mut billing = router_data
        .get_optional_billing()
        .cloned()
        .map(api_models::payments::Address::from);
    if let Some(address) = billing.as_mut() {
        if address.email.is_none() {
            address.email = router_data.request.email.clone();
        }
    } else if let Some(email) = router_data.request.email.clone() {
        billing = Some(api_models::payments::Address {
            address: None,
            phone: None,
            email: Some(email),
        });
    }
    billing
}

/// `POST /payments/{payment_id}/capture`.
#[derive(Debug, Serialize)]
pub struct HyperswitchCaptureRequest {
    amount_to_capture: MinorUnit,
}

impl From<&HyperswitchRouterData<&PaymentsCaptureRouterData>> for HyperswitchCaptureRequest {
    fn from(item: &HyperswitchRouterData<&PaymentsCaptureRouterData>) -> Self {
        Self {
            amount_to_capture: item.amount,
        }
    }
}

/// `POST /payments/{payment_id}/cancel`.
#[derive(Debug, Serialize)]
pub struct HyperswitchCancelRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    cancellation_reason: Option<String>,
}

impl From<&PaymentsCancelRouterData> for HyperswitchCancelRequest {
    fn from(item: &PaymentsCancelRouterData) -> Self {
        Self {
            cancellation_reason: item.request.cancellation_reason.clone(),
        }
    }
}

/// The target's payment status (its `IntentStatus`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HyperswitchPaymentStatus {
    Succeeded,
    Failed,
    Cancelled,
    CancelledPostCapture,
    Processing,
    RequiresCustomerAction,
    RequiresMerchantAction,
    RequiresPaymentMethod,
    RequiresConfirmation,
    RequiresCapture,
    PartiallyCaptured,
    PartiallyCapturedAndCapturable,
    PartiallyAuthorizedAndRequiresCapture,
    PartiallyCapturedAndProcessing,
    Conflicted,
    Expired,
    Review,
    #[serde(other)]
    Unknown,
}

/// The target's `next_action`. Only a redirect is something the payer can follow
/// from here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HyperswitchNextAction {
    RedirectToUrl {
        redirect_to_url: String,
    },
    RedirectInsidePopup {
        popup_url: String,
    },
    #[serde(other)]
    Other,
}

impl HyperswitchNextAction {
    fn redirect_url(&self) -> Option<&str> {
        match self {
            Self::RedirectToUrl { redirect_to_url } => Some(redirect_to_url),
            Self::RedirectInsidePopup { popup_url } => Some(popup_url),
            Self::Other => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperswitchPaymentLink {
    link: String,
}

/// The target's payment (`PaymentsResponse`), as `POST /payments`, its capture
/// and cancel, `GET /payments/{id}` and its payment webhooks carry it. Only the
/// fields read here; serialised back for the webhook's payment sync to read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperswitchPaymentsResponse {
    pub payment_id: String,
    pub status: HyperswitchPaymentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_capturable: Option<MinorUnit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_received: Option<MinorUnit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<HyperswitchNextAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_link: Option<HyperswitchPaymentLink>,
    #[serde(
        default,
        with = "common_utils::custom_serde::iso8601::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_on: Option<PrimitiveDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_error_message: Option<String>,
}

/// The attempt's status from the target's. `on_payment_link` is a card-redirect
/// attempt, whose payer is on the target's page while the target waits for a
/// payment method; `link_expired` is that page closed.
///
/// The router only syncs a payment while it is processing, waits on the payer
/// or the merchant, or waits for a capture. So nothing maps to a status the
/// router would stop syncing on while the target is still deciding.
pub fn attempt_status(
    status: HyperswitchPaymentStatus,
    on_payment_link: bool,
    link_expired: bool,
) -> enums::AttemptStatus {
    use HyperswitchPaymentStatus as Status;
    match status {
        Status::Succeeded => enums::AttemptStatus::Charged,
        Status::Failed | Status::Expired => enums::AttemptStatus::Failure,
        Status::Cancelled => enums::AttemptStatus::Voided,
        Status::CancelledPostCapture => enums::AttemptStatus::VoidedPostCharge,
        Status::RequiresCustomerAction => enums::AttemptStatus::AuthenticationPending,
        Status::RequiresCapture => enums::AttemptStatus::Authorized,
        Status::PartiallyCaptured => enums::AttemptStatus::PartialCharged,
        Status::PartiallyCapturedAndCapturable => enums::AttemptStatus::PartialChargedAndChargeable,
        Status::PartiallyAuthorizedAndRequiresCapture => enums::AttemptStatus::PartiallyAuthorized,
        // A payment link waits for the payer until it closes. Anything else that
        // still waits for a payment method lost it: the target declined it.
        Status::RequiresPaymentMethod | Status::RequiresConfirmation
            if on_payment_link && !link_expired =>
        {
            enums::AttemptStatus::AuthenticationPending
        }
        Status::RequiresPaymentMethod | Status::RequiresConfirmation => {
            enums::AttemptStatus::Failure
        }
        Status::Conflicted | Status::RequiresMerchantAction => enums::AttemptStatus::Unresolved,
        Status::Processing
        | Status::PartiallyCapturedAndProcessing
        | Status::Review
        | Status::Unknown => enums::AttemptStatus::Pending,
    }
}

/// Whether a payment link has closed by `now`.
pub fn link_expired(expires_on: Option<PrimitiveDateTime>, now: PrimitiveDateTime) -> bool {
    expires_on.is_some_and(|expires_on| now >= expires_on)
}

impl HyperswitchPaymentsResponse {
    fn waits_on_payment_method(&self) -> bool {
        matches!(
            self.status,
            HyperswitchPaymentStatus::RequiresPaymentMethod
                | HyperswitchPaymentStatus::RequiresConfirmation
        )
    }

    /// Why the payment failed, from the target's error, else its unified error.
    fn failure(
        &self,
        status_code: u16,
        on_payment_link: bool,
        status: enums::AttemptStatus,
    ) -> ErrorResponse {
        let (code, message) = if on_payment_link && self.waits_on_payment_method() {
            (
                "payment_link_expired".to_string(),
                "The payer did not pay on the target's payment link before it closed".to_string(),
            )
        } else {
            (
                self.error_code
                    .clone()
                    .or_else(|| self.unified_code.clone())
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                self.error_message
                    .clone()
                    .or_else(|| self.unified_message.clone())
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            )
        };
        ErrorResponse {
            status_code,
            code,
            message: message.clone(),
            reason: Some(message),
            attempt_status: Some(status),
            connector_transaction_id: Some(self.payment_id.clone()),
            connector_response_reference_id: Some(self.payment_id.clone()),
            network_advice_code: None,
            network_decline_code: self.issuer_error_code.clone(),
            network_error_message: self.issuer_error_message.clone(),
            connector_metadata: None,
        }
    }

    /// Where to send the payer: the target's 3DS redirect, or its payment link.
    fn redirection(
        &self,
        status: enums::AttemptStatus,
    ) -> Result<Option<RedirectForm>, error_stack::Report<errors::ConnectorError>> {
        if status != enums::AttemptStatus::AuthenticationPending {
            return Ok(None);
        }
        let url = match (&self.next_action, &self.payment_link) {
            (Some(next_action), _) => Some(next_action.redirect_url().ok_or_else(|| {
                report!(errors::ConnectorError::NotSupported {
                    message: "a next action other than a redirect".to_string(),
                    connector: "hyperswitch".into(),
                })
            })?),
            (None, Some(payment_link)) => Some(payment_link.link.as_str()),
            // A sync while the payer is still away: they already have the redirect.
            (None, None) => None,
        };
        url.map(|url| {
            url::Url::parse(url)
                .map(|url| RedirectForm::from((url, Method::Get)))
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        })
        .transpose()
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, HyperswitchPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, HyperswitchPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        // A card-redirect attempt, or any payment the target made with a link.
        let on_payment_link = item.data.payment_method == enums::PaymentMethod::CardRedirect
            || response.payment_link.is_some();
        let status = attempt_status(
            response.status,
            on_payment_link,
            link_expired(response.expires_on, common_utils::date_time::now()),
        );
        let minor_amount_captured = response.amount_received.or(item.data.minor_amount_captured);
        let minor_amount_capturable = response
            .amount_capturable
            .or(item.data.minor_amount_capturable);

        if status == enums::AttemptStatus::Failure {
            return Ok(Self {
                status,
                response: Err(response.failure(item.http_code, on_payment_link, status)),
                ..item.data
            });
        }

        let redirection_data = response.redirection(status)?;
        Ok(Self {
            status,
            amount_captured: minor_amount_captured.map(|amount| amount.get_amount_as_i64()),
            minor_amount_captured,
            minor_amount_capturable,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.payment_id.clone()),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(response.payment_id),
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            }),
            ..item.data
        })
    }
}

/// `POST /refunds`. The amount is always sent, so a full refund is explicit too.
#[derive(Debug, Serialize)]
pub struct HyperswitchRefundRequest {
    payment_id: String,
    refund_id: String,
    amount: MinorUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl<F> TryFrom<&HyperswitchRouterData<&RefundsRouterData<F>>> for HyperswitchRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &HyperswitchRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            payment_id: item.router_data.request.connector_transaction_id.clone(),
            // Our refund id on the target too: refund sync looks it up by it.
            refund_id: item.router_data.request.refund_id.clone(),
            amount: item.amount,
            reason: item.router_data.request.reason.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HyperswitchRefundStatus {
    Succeeded,
    Failed,
    Pending,
    Review,
    #[serde(other)]
    Unknown,
}

impl From<HyperswitchRefundStatus> for enums::RefundStatus {
    fn from(status: HyperswitchRefundStatus) -> Self {
        match status {
            HyperswitchRefundStatus::Succeeded => Self::Success,
            HyperswitchRefundStatus::Failed => Self::Failure,
            HyperswitchRefundStatus::Review => Self::ManualReview,
            HyperswitchRefundStatus::Pending | HyperswitchRefundStatus::Unknown => Self::Pending,
        }
    }
}

/// The target's refund (`RefundResponse`), from `POST /refunds` and
/// `GET /refunds/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperswitchRefundResponse {
    pub refund_id: String,
    pub status: HyperswitchRefundStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_error_message: Option<String>,
}

impl<F> TryFrom<RefundsResponseRouterData<F, HyperswitchRefundResponse>> for RefundsRouterData<F> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<F, HyperswitchRefundResponse>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let refund_status = enums::RefundStatus::from(response.status);

        // The router records an error with a 2xx status as a definite refund failure.
        let refund_response = if refund_status == enums::RefundStatus::Failure {
            let message = response
                .error_message
                .or(response.unified_message)
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
            Err(ErrorResponse {
                status_code: item.http_code,
                code: response
                    .error_code
                    .or(response.unified_code)
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: message.clone(),
                reason: Some(message),
                attempt_status: None,
                connector_transaction_id: Some(response.refund_id),
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: response.issuer_error_code,
                network_error_message: response.issuer_error_message,
                connector_metadata: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: response.refund_id,
                refund_status,
            })
        };

        Ok(Self {
            response: refund_response,
            ..item.data
        })
    }
}

/// The target's error body: `{"error": {"type", "code", "message", "reason"}}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HyperswitchErrorResponse {
    pub error: HyperswitchErrorBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HyperswitchErrorBody {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

/// The target's outgoing webhook: `content.object` is the payment or the refund,
/// the same as a lookup returns.
#[derive(Debug, Deserialize)]
pub struct HyperswitchWebhookBody {
    pub event_type: String,
    pub content: HyperswitchWebhookContent,
}

#[derive(Debug, Deserialize)]
pub struct HyperswitchWebhookContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub object: serde_json::Value,
}

/// The target's webhook signature: hex HMAC-SHA512 of the body with the
/// profile's payment response hash key.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-Webhook-Signature-512";

const PAYMENT_CONTENT: &str = "payment_details";
const REFUND_CONTENT: &str = "refund_details";

impl HyperswitchWebhookBody {
    pub fn event_type(&self) -> api_models::webhooks::IncomingWebhookEvent {
        webhook_event(&self.event_type)
    }

    fn is_refund(&self) -> bool {
        self.content.content_type == REFUND_CONTENT
    }

    fn payment(
        &self,
    ) -> Result<HyperswitchPaymentsResponse, error_stack::Report<errors::ConnectorError>> {
        if self.content.content_type != PAYMENT_CONTENT {
            return Err(report!(
                errors::ConnectorError::WebhookResourceObjectNotFound
            ));
        }
        serde_json::from_value(self.content.object.clone())
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)
    }

    fn refund(
        &self,
    ) -> Result<HyperswitchRefundResponse, error_stack::Report<errors::ConnectorError>> {
        serde_json::from_value(self.content.object.clone())
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)
    }

    /// The payment by the target's id for it, which we keep as the connector's
    /// transaction id; a refund by ours, which the target was given.
    pub fn object_reference_id(
        &self,
    ) -> Result<api_models::webhooks::ObjectReferenceId, error_stack::Report<errors::ConnectorError>>
    {
        if self.is_refund() {
            return Ok(api_models::webhooks::ObjectReferenceId::RefundId(
                api_models::webhooks::RefundIdType::RefundId(self.refund()?.refund_id),
            ));
        }
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(self.payment()?.payment_id),
        ))
    }

    /// What the payment or refund flow reads: the object in the same form a
    /// lookup's answer has.
    pub fn resource_object(
        &self,
    ) -> Result<
        Box<dyn hyperswitch_masking::ErasedMaskSerialize>,
        error_stack::Report<errors::ConnectorError>,
    > {
        if self.is_refund() {
            Ok(Box::new(self.refund()?))
        } else {
            Ok(Box::new(self.payment()?))
        }
    }
}

/// The target's event types and ours. Events about disputes, mandates, payouts
/// and the rest are not about anything this connector created.
pub fn webhook_event(event_type: &str) -> api_models::webhooks::IncomingWebhookEvent {
    use api_models::webhooks::IncomingWebhookEvent as Event;
    match event_type {
        "payment_succeeded" => Event::PaymentIntentSuccess,
        "payment_failed" => Event::PaymentIntentFailure,
        "payment_processing" => Event::PaymentIntentProcessing,
        "payment_cancelled" | "payment_cancelled_post_capture" => Event::PaymentIntentCancelled,
        "payment_authorized" | "payment_partially_authorized" => {
            Event::PaymentIntentAuthorizationSuccess
        }
        "payment_captured" => Event::PaymentIntentCaptureSuccess,
        "payment_expired" => Event::PaymentIntentExpired,
        "action_required" => Event::PaymentActionRequired,
        "refund_succeeded" => Event::RefundSuccess,
        "refund_failed" => Event::RefundFailure,
        "refund_review" => Event::RefundReview,
        _ => Event::EventNotSupported,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::str::FromStr;

    use common_enums::enums::{AttemptStatus, RefundStatus};
    use common_utils::types::MinorUnit;
    use hyperswitch_masking::Secret;

    use super::{
        attempt_status, link_expired, platform_base_url, reference_for_attempt, webhook_event,
        HyperswitchCard, HyperswitchCardData, HyperswitchCardPaymentRequest,
        HyperswitchConnectorMetadata, HyperswitchPaymentFields, HyperswitchPaymentLinkConfig,
        HyperswitchPaymentLinkRequest, HyperswitchPaymentStatus as Status,
        HyperswitchPaymentsRequest, HyperswitchPaymentsResponse, HyperswitchRefundStatus,
        HyperswitchWebhookBody,
    };

    const PLATFORM: &str = "https://api.platform.example";

    fn metadata(value: serde_json::Value) -> Option<common_utils::pii::SecretSerdeValue> {
        Some(common_utils::pii::SecretSerdeValue::new(value))
    }

    #[test]
    fn an_account_uses_its_platform_url() {
        let url = platform_base_url(&metadata(serde_json::json!({ "platform_url": PLATFORM })));
        assert_eq!(url.unwrap(), PLATFORM);
    }

    #[test]
    fn a_path_prefix_is_kept_without_its_trailing_slash() {
        let url = platform_base_url(&metadata(
            serde_json::json!({ "platform_url": "https://platform.example/api/" }),
        ));
        assert_eq!(url.unwrap(), "https://platform.example/api");
    }

    #[test]
    fn an_account_without_a_platform_url_is_refused() {
        assert!(platform_base_url(&None).is_err());
        assert!(platform_base_url(&metadata(serde_json::json!({ "platform_url": " " }))).is_err());
    }

    #[test]
    fn plain_http_credentials_and_queries_are_refused() {
        for url in [
            "http://api.platform.example",
            "https://user:secret@api.platform.example",
            "https://api.platform.example?x=1",
            "https://api.platform.example#x",
            "api.platform.example",
        ] {
            let result = platform_base_url(&metadata(serde_json::json!({ "platform_url": url })));
            assert!(result.is_err(), "{url} was accepted");
        }
    }

    #[test]
    fn a_profile_id_is_optional() {
        let without = HyperswitchConnectorMetadata::try_from(&metadata(
            serde_json::json!({ "platform_url": PLATFORM, "profile_id": "" }),
        ))
        .unwrap();
        assert_eq!(without.profile_id(), None);
        let with = HyperswitchConnectorMetadata::try_from(&metadata(
            serde_json::json!({ "platform_url": PLATFORM, "profile_id": "pro_abc" }),
        ))
        .unwrap();
        assert_eq!(with.profile_id(), Some("pro_abc".to_string()));
    }

    #[test]
    fn an_attempt_id_is_the_reference_on_the_target() {
        assert_eq!(reference_for_attempt("pay_abc_1"), "pay_abc_1");
        let longest = "a".repeat(64);
        assert_eq!(reference_for_attempt(&longest), longest);
    }

    #[test]
    fn a_too_long_attempt_id_becomes_a_stable_digest() {
        let long = format!("{}_1", "a".repeat(64));
        let reference = reference_for_attempt(&long);
        assert_eq!(reference.len(), 43);
        assert!(reference.starts_with("hs-"));
        assert_eq!(reference, reference_for_attempt(&long));
        assert_ne!(
            reference,
            reference_for_attempt(&format!("{}_2", "a".repeat(64)))
        );
    }

    fn fields() -> HyperswitchPaymentFields {
        HyperswitchPaymentFields {
            payment_id: "pay_abc_1".to_string(),
            amount: MinorUnit::new(1050),
            currency: common_enums::Currency::EUR,
            capture_method: common_enums::CaptureMethod::Manual,
            return_url:
                "https://api.brand.example/payments/pay_abc/m/redirect/response/hyperswitch"
                    .to_string(),
            profile_id: None,
            billing: None,
            description: None,
            merchant_order_reference_id: "pay_abc".to_string(),
        }
    }

    #[test]
    fn a_card_payment_is_confirmed_with_the_card() {
        let request = HyperswitchPaymentsRequest::Card(Box::new(HyperswitchCardPaymentRequest {
            fields: fields(),
            confirm: true,
            payment_method: common_enums::PaymentMethod::Card,
            payment_method_type: Some(common_enums::PaymentMethodType::Credit),
            payment_method_data: HyperswitchCardData {
                card: HyperswitchCard {
                    card_number: cards::CardNumber::from_str("4111111111111111").unwrap(),
                    card_exp_month: Secret::new("12".to_string()),
                    card_exp_year: Secret::new("2030".to_string()),
                    card_holder_name: None,
                    card_cvc: Secret::new("123".to_string()),
                },
            },
            authentication_type: common_enums::AuthenticationType::ThreeDs,
            browser_info: None,
            enable_partial_authorization: None,
        }));
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["payment_id"], "pay_abc_1");
        assert_eq!(json["amount"], 1050);
        assert_eq!(json["confirm"], true);
        assert_eq!(json["capture_method"], "manual");
        assert_eq!(json["authentication_type"], "three_ds");
        assert_eq!(json["payment_method"], "card");
        assert_eq!(
            json["payment_method_data"]["card"]["card_number"],
            "4111111111111111"
        );
        assert!(json.get("profile_id").is_none());
        assert!(json.get("payment_link").is_none());
    }

    #[test]
    fn a_card_redirect_opens_a_payment_link_without_a_card() {
        let request = HyperswitchPaymentsRequest::PaymentLink(HyperswitchPaymentLinkRequest {
            fields: fields(),
            confirm: false,
            payment_link: true,
            payment_link_config: HyperswitchPaymentLinkConfig {
                skip_status_screen: true,
            },
            session_expiry: 900,
            allowed_payment_method_types: vec![
                common_enums::PaymentMethodType::Credit,
                common_enums::PaymentMethodType::Debit,
            ],
        });
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["confirm"], false);
        assert_eq!(json["payment_link"], true);
        assert_eq!(json["payment_link_config"]["skip_status_screen"], true);
        assert_eq!(json["session_expiry"], 900);
        assert_eq!(
            json["allowed_payment_method_types"],
            serde_json::json!(["credit", "debit"])
        );
        assert!(json.get("payment_method_data").is_none());
    }

    #[test]
    fn final_and_capture_statuses_map_one_to_one() {
        for (status, expected) in [
            (Status::Succeeded, AttemptStatus::Charged),
            (Status::Failed, AttemptStatus::Failure),
            (Status::Expired, AttemptStatus::Failure),
            (Status::Cancelled, AttemptStatus::Voided),
            (
                Status::CancelledPostCapture,
                AttemptStatus::VoidedPostCharge,
            ),
            (Status::RequiresCapture, AttemptStatus::Authorized),
            (Status::PartiallyCaptured, AttemptStatus::PartialCharged),
            (
                Status::PartiallyCapturedAndCapturable,
                AttemptStatus::PartialChargedAndChargeable,
            ),
            (
                Status::PartiallyAuthorizedAndRequiresCapture,
                AttemptStatus::PartiallyAuthorized,
            ),
            (
                Status::RequiresCustomerAction,
                AttemptStatus::AuthenticationPending,
            ),
        ] {
            assert_eq!(attempt_status(status, false, false), expected, "{status:?}");
        }
    }

    #[test]
    fn undecided_statuses_keep_the_payment_syncing() {
        for status in [
            Status::Processing,
            Status::PartiallyCapturedAndProcessing,
            Status::Review,
            Status::Unknown,
        ] {
            assert_eq!(attempt_status(status, false, false), AttemptStatus::Pending);
        }
        for status in [Status::Conflicted, Status::RequiresMerchantAction] {
            assert_eq!(
                attempt_status(status, false, false),
                AttemptStatus::Unresolved
            );
        }
    }

    #[test]
    fn a_payment_link_waits_for_the_payer_until_it_closes() {
        assert_eq!(
            attempt_status(Status::RequiresPaymentMethod, true, false),
            AttemptStatus::AuthenticationPending
        );
        assert_eq!(
            attempt_status(Status::RequiresPaymentMethod, true, true),
            AttemptStatus::Failure
        );
    }

    #[test]
    fn a_card_payment_still_waiting_for_a_payment_method_failed() {
        assert_eq!(
            attempt_status(Status::RequiresPaymentMethod, false, false),
            AttemptStatus::Failure
        );
    }

    #[test]
    fn a_link_closes_at_its_expiry() {
        let now = time::macros::datetime!(2026-11-09 12:00);
        assert!(!link_expired(None, now));
        assert!(!link_expired(
            Some(time::macros::datetime!(2026-11-09 12:15)),
            now
        ));
        assert!(link_expired(Some(now), now));
    }

    fn response(json: serde_json::Value) -> HyperswitchPaymentsResponse {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn three_ds_redirects_the_payer() {
        let response = response(serde_json::json!({
            "payment_id": "pay_abc_1",
            "status": "requires_customer_action",
            "next_action": {
                "type": "redirect_to_url",
                "redirect_to_url": "https://api.platform.example/payments/redirect/pay_abc_1/m/a"
            }
        }));
        let redirect = response
            .redirection(AttemptStatus::AuthenticationPending)
            .unwrap();
        assert!(redirect.is_some());
    }

    #[test]
    fn a_next_action_we_cannot_follow_is_refused() {
        let response = response(serde_json::json!({
            "payment_id": "pay_abc_1",
            "status": "requires_customer_action",
            "next_action": { "type": "three_ds_invoke", "three_ds_data": {} }
        }));
        assert!(response
            .redirection(AttemptStatus::AuthenticationPending)
            .is_err());
    }

    #[test]
    fn a_payment_link_is_where_the_payer_goes() {
        let response = response(serde_json::json!({
            "payment_id": "pay_abc_1",
            "status": "requires_payment_method",
            "payment_link": {
                "link": "https://pay.platform.example/payment_link/m/pay_abc_1?locale=en",
                "payment_link_id": "plink_1"
            },
            "expires_on": "2026-11-09T12:15:00.000Z"
        }));
        assert!(response.expires_on.is_some());
        assert!(response
            .redirection(AttemptStatus::AuthenticationPending)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_decline_carries_the_targets_error() {
        let response = response(serde_json::json!({
            "payment_id": "pay_abc_1",
            "status": "failed",
            "error_code": "card_declined",
            "error_message": "Card declined",
            "unified_code": "UE_9000"
        }));
        let error = response.failure(200, false, AttemptStatus::Failure);
        assert_eq!(error.code, "card_declined");
        assert_eq!(error.message, "Card declined");
        assert_eq!(error.connector_transaction_id.as_deref(), Some("pay_abc_1"));
    }

    #[test]
    fn a_closed_payment_link_says_so() {
        let response = response(serde_json::json!({
            "payment_id": "pay_abc_1",
            "status": "requires_payment_method"
        }));
        let error = response.failure(200, true, AttemptStatus::Failure);
        assert_eq!(error.code, "payment_link_expired");
    }

    #[test]
    fn refund_statuses() {
        for (status, expected) in [
            (HyperswitchRefundStatus::Succeeded, RefundStatus::Success),
            (HyperswitchRefundStatus::Failed, RefundStatus::Failure),
            (HyperswitchRefundStatus::Pending, RefundStatus::Pending),
            (HyperswitchRefundStatus::Review, RefundStatus::ManualReview),
            (HyperswitchRefundStatus::Unknown, RefundStatus::Pending),
        ] {
            assert_eq!(RefundStatus::from(status), expected);
        }
    }

    #[test]
    fn webhook_events() {
        use api_models::webhooks::IncomingWebhookEvent as Event;
        for (event, expected) in [
            ("payment_succeeded", Event::PaymentIntentSuccess),
            ("payment_failed", Event::PaymentIntentFailure),
            ("payment_processing", Event::PaymentIntentProcessing),
            ("payment_cancelled", Event::PaymentIntentCancelled),
            (
                "payment_cancelled_post_capture",
                Event::PaymentIntentCancelled,
            ),
            (
                "payment_authorized",
                Event::PaymentIntentAuthorizationSuccess,
            ),
            ("payment_captured", Event::PaymentIntentCaptureSuccess),
            ("payment_expired", Event::PaymentIntentExpired),
            ("action_required", Event::PaymentActionRequired),
            ("refund_succeeded", Event::RefundSuccess),
            ("refund_failed", Event::RefundFailure),
            ("refund_review", Event::RefundReview),
            ("dispute_opened", Event::EventNotSupported),
        ] {
            assert_eq!(webhook_event(event), expected, "{event}");
        }
    }

    fn webhook(content_type: &str, object: serde_json::Value) -> HyperswitchWebhookBody {
        serde_json::from_value(serde_json::json!({
            "merchant_id": "merchant_1",
            "event_id": "evt_1",
            "event_type": "payment_succeeded",
            "content": { "type": content_type, "object": object },
            "timestamp": "2026-11-09T12:00:00.000Z"
        }))
        .unwrap()
    }

    #[test]
    fn a_payment_webhook_names_the_payment_by_the_targets_id() {
        let body = webhook(
            "payment_details",
            serde_json::json!({ "payment_id": "pay_abc_1", "status": "succeeded" }),
        );
        assert!(matches!(
            body.object_reference_id().unwrap(),
            api_models::webhooks::ObjectReferenceId::PaymentId(
                api_models::payments::PaymentIdType::ConnectorTransactionId(id)
            ) if id == "pay_abc_1"
        ));
    }

    #[test]
    fn a_refund_webhook_names_the_refund_by_our_id() {
        let body = webhook(
            "refund_details",
            serde_json::json!({ "refund_id": "ref_abc", "payment_id": "pay_abc_1", "status": "succeeded" }),
        );
        assert!(matches!(
            body.object_reference_id().unwrap(),
            api_models::webhooks::ObjectReferenceId::RefundId(
                api_models::webhooks::RefundIdType::RefundId(id)
            ) if id == "ref_abc"
        ));
    }

    #[test]
    fn a_webhook_about_something_else_has_no_payment() {
        let body = webhook(
            "dispute_details",
            serde_json::json!({ "dispute_id": "dp_1" }),
        );
        assert!(body.object_reference_id().is_err());
    }
}
