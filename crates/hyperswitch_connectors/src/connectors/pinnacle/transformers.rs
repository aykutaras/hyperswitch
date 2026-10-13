use common_enums::enums;
use common_utils::{pii::Email, request::Method, types::StringMajorUnit};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, CardData, PaymentsAuthorizeRequestData, RouterData as _},
};

pub struct PinnacleRouterData<T> {
    pub amount: StringMajorUnit,
    pub router_data: T,
}

impl<T> From<(StringMajorUnit, T)> for PinnacleRouterData<T> {
    fn from((amount, item): (StringMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

/// `POST /v1/payment`. payment-api decides on 3DS itself; no field asks for it or skips it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnaclePaymentsRequest {
    number: cards::CardNumber,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvv: Secret<String>,
    reference_no: String,
    return_url: String,
    amount: StringMajorUnit,
    currency: enums::Currency,
    email: Email,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<Secret<String>>,
    billing_first_name: Secret<String>,
    billing_last_name: Secret<String>,
    billing_address1: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address2: Option<Secret<String>>,
    billing_city: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_state: Option<Secret<String>>,
    billing_postcode: Secret<String>,
    billing_country: enums::CountryAlpha2,
    billing_phone: Secret<String>,
}

impl TryFrom<&PinnacleRouterData<&PaymentsAuthorizeRouterData>> for PinnaclePaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &PinnacleRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let card = match &router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("pinnacle"),
            ))?,
        };
        let email = router_data
            .get_billing_email()
            .ok()
            .or_else(|| router_data.request.email.clone())
            .ok_or_else(utils::missing_field_err(
                "payment_method_data.billing.email",
            ))?;

        Ok(Self {
            number: card.card_number.clone(),
            expiry_month: card.get_card_expiry_month_2_digit()?,
            expiry_year: card.get_expiry_year_4_digit(),
            cvv: card.card_cvc.clone(),
            reference_no: router_data.connector_request_reference_id.clone(),
            return_url: router_data.request.get_router_return_url()?,
            amount: item.amount.clone(),
            currency: router_data.request.currency,
            email,
            ip: router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|browser_info| browser_info.ip_address)
                .map(|ip_address| Secret::new(ip_address.to_string())),
            billing_first_name: router_data.get_billing_first_name()?,
            billing_last_name: router_data.get_billing_last_name()?,
            billing_address1: router_data.get_billing_line1()?,
            billing_address2: router_data.get_optional_billing_line2(),
            billing_city: router_data.get_billing_city()?,
            billing_state: router_data.get_optional_billing_state(),
            billing_postcode: router_data.get_billing_zip()?,
            billing_country: router_data.get_billing_country()?,
            billing_phone: router_data.get_billing_phone_number()?,
        })
    }
}

pub struct PinnacleAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PinnacleAuthType {
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

/// Per-account settings from the connector's metadata (the dashboard's
/// connector form). payment-api resolves the white-label tenant from the host
/// it is called on, so `platform_url` is how an account picks its tenant, the
/// field Archipel uses for its per-account endpoint. Unset, the deployment's
/// `connectors.pinnacle.base_url` is used.
#[derive(Debug, Default, Deserialize)]
pub struct PinnacleConnectorMetadata {
    pub platform_url: Option<String>,
}

impl TryFrom<&Option<common_utils::pii::SecretSerdeValue>> for PinnacleConnectorMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    /// Also checks the URL's form, so a typo is refused when the account is
    /// saved rather than on its first payment.
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
        if let Some(url) = metadata.platform_url() {
            check_platform_url(url)?;
        }
        Ok(metadata)
    }
}

impl PinnacleConnectorMetadata {
    fn platform_url(&self) -> Option<&str> {
        self.platform_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }
}

/// An https URL naming a host and nothing the connector adds itself: no
/// credentials, query, fragment or path (requests go to `/v1/...`).
fn check_platform_url(raw: &str) -> Result<(), error_stack::Report<errors::ConnectorError>> {
    let invalid = || {
        report!(errors::ConnectorError::InvalidConnectorConfig {
            config: "metadata.platform_url (an https URL with no path, e.g. https://api.prod.pinnacle-soft.io)",
        })
    };
    let url = url::Url::parse(raw).map_err(|_| invalid())?;
    let well_formed = url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    if well_formed {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// The base URL requests for this account go to: its own `platform_url`, else
/// the deployment's default.
pub fn tenant_base_url(
    default_base_url: &str,
    connector_metadata: &Option<common_utils::pii::SecretSerdeValue>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let metadata = PinnacleConnectorMetadata::try_from(connector_metadata)?;
    Ok(metadata
        .platform_url()
        .unwrap_or(default_base_url)
        .to_string())
}

/// payment-api's transaction status. `DECLINED`, `CANCELLED` and `ERROR` are final.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PinnacleTransactionStatus {
    Approved,
    Pending,
    Waiting,
    Declined,
    Cancelled,
    Error,
}

/// Body of `POST /v1/payment` and of `GET /v1/payment/status`. Only the payment
/// response carries `redirectUrl`, and only while 3DS is waiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnacleTransactionResponse {
    uuid: String,
    status: PinnacleTransactionStatus,
    reference_no: Option<String>,
    message: Option<String>,
    failure_code: Option<String>,
    error_reason: Option<String>,
    redirect_url: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, PinnacleTransactionResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PinnacleTransactionResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let status = match response.status {
            PinnacleTransactionStatus::Approved => enums::AttemptStatus::Charged,
            PinnacleTransactionStatus::Waiting if response.redirect_url.is_some() => {
                enums::AttemptStatus::AuthenticationPending
            }
            // A status lookup carries no redirectUrl. While payment-api still waits on 3DS,
            // the customer has not finished it: the payment still needs their action.
            // payment-api never gives up on one of these, so it stays WAITING for good if
            // the customer never comes back; nothing here or there turns it into a failure.
            PinnacleTransactionStatus::Waiting
                if item.data.status == enums::AttemptStatus::AuthenticationPending =>
            {
                enums::AttemptStatus::AuthenticationPending
            }
            PinnacleTransactionStatus::Waiting | PinnacleTransactionStatus::Pending => {
                enums::AttemptStatus::Pending
            }
            PinnacleTransactionStatus::Declined
            | PinnacleTransactionStatus::Cancelled
            | PinnacleTransactionStatus::Error => enums::AttemptStatus::Failure,
        };

        if status == enums::AttemptStatus::Failure {
            return Ok(Self {
                status,
                response: Err(ErrorResponse {
                    status_code: item.http_code,
                    code: response
                        .failure_code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error_reason.or(response.message),
                    attempt_status: Some(status),
                    connector_transaction_id: Some(response.uuid),
                    connector_response_reference_id: response.reference_no,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    connector_metadata: None,
                }),
                ..item.data
            });
        }

        let redirection_data = match (status, response.redirect_url) {
            (enums::AttemptStatus::AuthenticationPending, Some(redirect_url)) => {
                let redirect_url = url::Url::parse(&redirect_url)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                Some(RedirectForm::from((redirect_url, Method::Get)))
            }
            _ => None,
        };

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(response.uuid),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: response.reference_no,
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

/// `POST /v1/refund`. The amount is always sent, so a full refund is explicit too.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnacleRefundRequest {
    uuid: String,
    amount: StringMajorUnit,
    reference_no: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl<F> TryFrom<&PinnacleRouterData<&RefundsRouterData<F>>> for PinnacleRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PinnacleRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            uuid: item.router_data.request.connector_transaction_id.clone(),
            amount: item.amount.clone(),
            // Refund sync finds the refund by this reference.
            reference_no: item.router_data.request.refund_id.clone(),
            reason: item.router_data.request.reason.clone(),
        })
    }
}

/// Body of `POST /v1/refund`, and of `GET /v1/payment/status` for the refund's reference.
/// Its `uuid` is the payment's: payment-api copies the payment row to make the refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnacleRefundResponse {
    uuid: String,
    status: PinnacleTransactionStatus,
    message: Option<String>,
    failure_code: Option<String>,
}

impl<F> TryFrom<RefundsResponseRouterData<F, PinnacleRefundResponse>> for RefundsRouterData<F> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<F, PinnacleRefundResponse>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let refund_status = match response.status {
            PinnacleTransactionStatus::Approved => enums::RefundStatus::Success,
            PinnacleTransactionStatus::Pending | PinnacleTransactionStatus::Waiting => {
                enums::RefundStatus::Pending
            }
            PinnacleTransactionStatus::Declined
            | PinnacleTransactionStatus::Cancelled
            | PinnacleTransactionStatus::Error => enums::RefundStatus::Failure,
        };

        // The router records an error with a 2xx status as a definite refund failure.
        let refund_response = if refund_status == enums::RefundStatus::Failure {
            Err(ErrorResponse {
                status_code: item.http_code,
                code: response
                    .failure_code
                    .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                message: response
                    .message
                    .clone()
                    .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                reason: response.message,
                attempt_status: None,
                connector_transaction_id: Some(response.uuid),
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: response.uuid,
                refund_status,
            })
        };

        Ok(Self {
            response: refund_response,
            ..item.data
        })
    }
}

/// payment-api renders every error as `{"status": "ERROR", "message": ...}`, adding
/// `errors` (field name to messages) when validation fails.
#[derive(Debug, Serialize, Deserialize)]
pub struct PinnacleErrorResponse {
    pub message: Option<String>,
    pub errors: Option<serde_json::Value>,
}

impl PinnacleErrorResponse {
    pub fn reason(&self) -> Option<String> {
        match &self.errors {
            Some(serde_json::Value::Object(fields)) => Some(
                fields
                    .iter()
                    .map(|(field, messages)| match messages {
                        serde_json::Value::Array(messages) => format!(
                            "{field}: {}",
                            messages
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .collect::<Vec<_>>()
                                .join(" ")
                        ),
                        other => format!("{field}: {other}"),
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            Some(other) => Some(other.to_string()),
            None => self.message.clone(),
        }
    }
}

/// Body of payment-api's `transaction.status_changed` notification: the transaction's
/// own fields at the top level, the same ones a status lookup returns, beside
/// `transaction` and `customerInfo` copies we do not need. Serialised back for the
/// payment or refund flow to read, so the names have to stay as they arrive.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnacleWebhookBody {
    uuid: String,
    status: PinnacleTransactionStatus,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_no: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
}

/// payment-api's operation for a refund. Everything else is a payment.
const REFUND_OPERATION: &str = "REFUND";

impl PinnacleWebhookBody {
    fn is_refund(&self) -> bool {
        self.operation == REFUND_OPERATION
    }

    pub fn event_type(&self) -> api_models::webhooks::IncomingWebhookEvent {
        use api_models::webhooks::IncomingWebhookEvent;

        let final_status = matches!(
            self.status,
            PinnacleTransactionStatus::Declined
                | PinnacleTransactionStatus::Cancelled
                | PinnacleTransactionStatus::Error
        );
        match (self.is_refund(), self.status, final_status) {
            (true, PinnacleTransactionStatus::Approved, _) => IncomingWebhookEvent::RefundSuccess,
            (true, _, true) => IncomingWebhookEvent::RefundFailure,
            (false, PinnacleTransactionStatus::Approved, _) => {
                IncomingWebhookEvent::PaymentIntentSuccess
            }
            (false, _, true) => IncomingWebhookEvent::PaymentIntentFailure,
            // PENDING and WAITING say nothing new. payment-api does not notify while a
            // 3DS payment is still waiting: its listener skips the `3D` operation.
            (true, _, false) => IncomingWebhookEvent::EventNotSupported,
            (false, _, false) => IncomingWebhookEvent::PaymentIntentProcessing,
        }
    }

    /// By the reference we sent, never by `uuid`, which a refund shares with its payment.
    pub fn object_reference_id(
        &self,
    ) -> Result<api_models::webhooks::ObjectReferenceId, error_stack::Report<errors::ConnectorError>>
    {
        let reference = self
            .reference_no
            .clone()
            .ok_or_else(utils::missing_field_err("referenceNo"))?;
        Ok(if self.is_refund() {
            api_models::webhooks::ObjectReferenceId::RefundId(
                api_models::webhooks::RefundIdType::RefundId(reference),
            )
        } else {
            api_models::webhooks::ObjectReferenceId::PaymentId(
                api_models::payments::PaymentIdType::PaymentAttemptId(reference),
            )
        })
    }
}

/// What payment-api signs: six fields of the payload plus the request id and timestamp
/// from the headers, as JSON with the keys sorted and an HMAC-SHA256 over it
/// (`notification-module`, `IpnSignature::generate`). The values are taken from the body
/// as they arrived, so a number stays a number and a string stays a string. The keys are
/// inserted already sorted, so the result does not depend on how serde_json orders a map.
/// A non-ASCII value would not match, because PHP escapes those and serde_json does not;
/// none of the signed fields carries one today.
pub fn webhook_signature_message(
    body: &serde_json::Value,
    request_id: &str,
    timestamp: i64,
) -> Result<Vec<u8>, error_stack::Report<errors::ConnectorError>> {
    fn signed_field(
        body: &serde_json::Value,
        field: &str,
    ) -> Result<serde_json::Value, error_stack::Report<errors::ConnectorError>> {
        body.get(field).cloned().ok_or_else(|| {
            report!(errors::ConnectorError::WebhookSourceVerificationFailed).attach_printable(
                format!("signed field {field} missing from the webhook body"),
            )
        })
    }

    let mut signed = serde_json::Map::new();
    signed.insert("amount".to_string(), signed_field(body, "amount")?);
    signed.insert("currency".to_string(), signed_field(body, "currency")?);
    signed.insert(
        "referenceNo".to_string(),
        signed_field(body, "referenceNo")?,
    );
    signed.insert(
        "requestId".to_string(),
        serde_json::Value::String(request_id.to_string()),
    );
    signed.insert("returnUrl".to_string(), signed_field(body, "returnUrl")?);
    signed.insert("status".to_string(), signed_field(body, "status")?);
    signed.insert(
        "timestamp".to_string(),
        serde_json::Value::Number(timestamp.into()),
    );
    signed.insert("uuid".to_string(), signed_field(body, "uuid")?);

    serde_json::to_vec(&serde_json::Value::Object(signed))
        .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use hyperswitch_masking::Secret;

    use super::tenant_base_url;

    const DEFAULT: &str = "https://api.prod.pinnacle-soft.io";

    fn metadata(platform_url: &str) -> Option<common_utils::pii::SecretSerdeValue> {
        Some(Secret::new(
            serde_json::json!({ "platform_url": platform_url }),
        ))
    }

    #[test]
    fn an_account_without_metadata_uses_the_default() {
        assert_eq!(tenant_base_url(DEFAULT, &None).unwrap(), DEFAULT);
    }

    #[test]
    fn an_account_without_a_platform_url_uses_the_default() {
        let metadata = Some(Secret::new(serde_json::json!({})));
        assert_eq!(tenant_base_url(DEFAULT, &metadata).unwrap(), DEFAULT);
    }

    #[test]
    fn an_empty_platform_url_uses_the_default() {
        assert_eq!(tenant_base_url(DEFAULT, &metadata("  ")).unwrap(), DEFAULT);
    }

    #[test]
    fn an_accounts_platform_url_is_used() {
        assert_eq!(
            tenant_base_url(DEFAULT, &metadata("https://api.brand.example/")).unwrap(),
            "https://api.brand.example/"
        );
    }

    #[test]
    fn plain_http_is_refused() {
        assert!(tenant_base_url(DEFAULT, &metadata("http://api.brand.example")).is_err());
    }

    #[test]
    fn a_path_is_refused() {
        assert!(tenant_base_url(DEFAULT, &metadata("https://api.brand.example/v1")).is_err());
    }

    #[test]
    fn credentials_in_the_url_are_refused() {
        assert!(tenant_base_url(DEFAULT, &metadata("https://user:pw@api.brand.example")).is_err());
    }
}
