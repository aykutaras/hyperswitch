use common_enums::enums;
use common_utils::{pii::Email, request::Method, types::FloatMajorUnit};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    address::PhoneDetails,
    payment_method_data::{
        BankRedirectData, BankTransferData, CardRedirectData, GiftCardData, PayLaterData,
        PaymentMethodData, RealTimePaymentData, UpiData, VoucherData, WalletData,
    },
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, PaymentsAuthorizeRequestData, RouterData as _},
};

pub struct PaytechRouterData<T> {
    pub amount: FloatMajorUnit,
    pub router_data: T,
}

impl<T> From<(FloatMajorUnit, T)> for PaytechRouterData<T> {
    fn from((amount, item): (FloatMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

pub struct PaytechAuthType {
    /// The shop's API key, sent as a bearer token.
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaytechAuthType {
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
/// connector form). Each white-label brand of the PayPlane engine has its own
/// host (`engine[-sandbox].<brand>`), so `platform_url` is how an account picks
/// its brand, the field Archipel uses for its per-account endpoint. Unset, the
/// deployment's `connectors.paytech.base_url` is used.
#[derive(Debug, Default, Deserialize)]
pub struct PaytechConnectorMetadata {
    pub platform_url: Option<String>,
}

impl TryFrom<&Option<common_utils::pii::SecretSerdeValue>> for PaytechConnectorMetadata {
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

impl PaytechConnectorMetadata {
    fn platform_url(&self) -> Option<&str> {
        self.platform_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }
}

/// An https URL naming a host and nothing the connector adds itself: no
/// credentials, query, fragment or path (requests go to `/api/v1/...`).
fn check_platform_url(raw: &str) -> Result<(), error_stack::Report<errors::ConnectorError>> {
    let invalid = || {
        report!(errors::ConnectorError::InvalidConnectorConfig {
            config:
                "metadata.platform_url (an https URL with no path, e.g. https://engine.pay.tech)",
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
pub fn brand_base_url(
    default_base_url: &str,
    connector_metadata: &Option<common_utils::pii::SecretSerdeValue>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let metadata = PaytechConnectorMetadata::try_from(connector_metadata)?;
    Ok(metadata
        .platform_url()
        .unwrap_or(default_base_url)
        .to_string())
}

/// `paymentType`. The API reference lists the first three; `CHARGEBACK` arrives
/// in webhooks too, as a payment object of its own whose `parentPaymentId` is
/// the sale (payment-api, `PayTechPaymentType`). Anything newer is `Unknown`
/// rather than a webhook that fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaytechPaymentType {
    Deposit,
    Withdrawal,
    Refund,
    Chargeback,
    #[serde(other)]
    Unknown,
}

/// `state`. COMPLETED, DECLINED and CANCELLED are final; AUTHORIZED is final
/// for a pre-authorization, which this connector does not request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaytechPaymentState {
    Checkout,
    Pending,
    Authorized,
    Cancelled,
    Declined,
    Completed,
    AwaitingApproval,
    #[serde(other)]
    Unknown,
}

impl PaytechPaymentState {
    fn is_failure(self) -> bool {
        matches!(self, Self::Declined | Self::Cancelled)
    }
}

/// The `paymentMethod` values this connector sends: the ones with a payment
/// method type of their own in Hyperswitch, plus `BASIC_CARD` for PayTech's
/// card page. The other methods PayTech lists have no Hyperswitch type. A card
/// typed into Hyperswitch's own checkout goes through the pinnacle connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaytechPaymentMethod {
    Ach,
    Alfamart,
    Alipay,
    Bancontact,
    BasicCard,
    Bizum,
    Blik,
    Boleto,
    Cashapp,
    Crypto,
    Dana,
    Duitnow,
    Efecty,
    Eft,
    Eps,
    Fpx,
    Gcash,
    Giropay,
    Gopay,
    Ideal,
    Interac,
    Kakaopay,
    Klarna,
    Mbway,
    Mifinity,
    MomopayVn,
    Multibanco,
    OpenBanking,
    Oxxo,
    P24,
    Pagoefectivo,
    Paypal,
    Paysafecard,
    Pix,
    Promptpay,
    Pse,
    Qris,
    Revolut,
    Sepa,
    Skrill,
    Sofort,
    Swish,
    TouchNGo,
    Trustly,
    Twint,
    Upi,
    Vipps,
    Wechat,
}

impl TryFrom<&PaymentMethodData> for PaytechPaymentMethod {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(payment_method_data: &PaymentMethodData) -> Result<Self, Self::Error> {
        let method = match payment_method_data {
            // PayTech's card page, opened with BASIC_CARD and no card details: the
            // customer enters a card there, or pays with the Apple Pay or Google Pay
            // button it carries (PayTech's Apple Pay and Google Pay docs).
            PaymentMethodData::CardRedirect(CardRedirectData::CardRedirect { .. }) => {
                Self::BasicCard
            }
            PaymentMethodData::Wallet(wallet) => match wallet {
                WalletData::ApplePayRedirect { .. } | WalletData::GooglePayRedirect { .. } => {
                    Self::BasicCard
                }
                WalletData::AliPayQr { .. } | WalletData::AliPayRedirect { .. } => Self::Alipay,
                WalletData::CashappQr { .. } => Self::Cashapp,
                WalletData::DanaRedirect { .. } => Self::Dana,
                WalletData::GcashRedirect { .. } => Self::Gcash,
                WalletData::GoPayRedirect { .. } => Self::Gopay,
                WalletData::KakaoPayRedirect { .. } => Self::Kakaopay,
                WalletData::MbWayRedirect { .. } => Self::Mbway,
                WalletData::Mifinity { .. } => Self::Mifinity,
                WalletData::MomoRedirect { .. } => Self::MomopayVn,
                WalletData::PaypalRedirect { .. } => Self::Paypal,
                WalletData::RevolutPay { .. } => Self::Revolut,
                WalletData::Skrill { .. } => Self::Skrill,
                WalletData::SwishQr { .. } => Self::Swish,
                WalletData::TouchNGoRedirect { .. } => Self::TouchNGo,
                WalletData::TwintRedirect { .. } => Self::Twint,
                WalletData::VippsRedirect { .. } => Self::Vipps,
                WalletData::WeChatPayQr { .. } | WalletData::WeChatPayRedirect { .. } => {
                    Self::Wechat
                }
                _ => return Err(unsupported_payment_method()),
            },
            PaymentMethodData::BankRedirect(bank_redirect) => match bank_redirect {
                BankRedirectData::BancontactCard { .. } => Self::Bancontact,
                BankRedirectData::Bizum { .. } => Self::Bizum,
                BankRedirectData::Blik { .. } => Self::Blik,
                BankRedirectData::Eft { .. } => Self::Eft,
                BankRedirectData::Eps { .. } => Self::Eps,
                BankRedirectData::Giropay { .. } => Self::Giropay,
                BankRedirectData::Ideal { .. } => Self::Ideal,
                BankRedirectData::Interac { .. } => Self::Interac,
                BankRedirectData::OnlineBankingFpx { .. } => Self::Fpx,
                BankRedirectData::OpenBanking { .. } => Self::OpenBanking,
                BankRedirectData::Przelewy24 { .. } => Self::P24,
                BankRedirectData::Sofort { .. } => Self::Sofort,
                BankRedirectData::Trustly { .. } => Self::Trustly,
                _ => return Err(unsupported_payment_method()),
            },
            PaymentMethodData::BankTransfer(bank_transfer) => match bank_transfer.as_ref() {
                BankTransferData::AchBankTransfer { .. } => Self::Ach,
                BankTransferData::MultibancoBankTransfer { .. } => Self::Multibanco,
                BankTransferData::Pix { .. } => Self::Pix,
                BankTransferData::Pse { .. } => Self::Pse,
                BankTransferData::SepaBankTransfer { .. } => Self::Sepa,
                _ => return Err(unsupported_payment_method()),
            },
            PaymentMethodData::Voucher(voucher) => match voucher {
                VoucherData::Alfamart { .. } => Self::Alfamart,
                VoucherData::Boleto { .. } => Self::Boleto,
                VoucherData::Efecty => Self::Efecty,
                VoucherData::Oxxo => Self::Oxxo,
                VoucherData::PagoEfectivo => Self::Pagoefectivo,
                _ => return Err(unsupported_payment_method()),
            },
            PaymentMethodData::RealTimePayment(real_time_payment) => {
                match real_time_payment.as_ref() {
                    RealTimePaymentData::DuitNow { .. } => Self::Duitnow,
                    RealTimePaymentData::PromptPay { .. } => Self::Promptpay,
                    RealTimePaymentData::Qris { .. } => Self::Qris,
                    _ => return Err(unsupported_payment_method()),
                }
            }
            PaymentMethodData::PayLater(PayLaterData::KlarnaRedirect { .. }) => Self::Klarna,
            PaymentMethodData::Upi(UpiData::UpiCollect { .. } | UpiData::UpiIntent { .. }) => {
                Self::Upi
            }
            PaymentMethodData::GiftCard(gift_card) => match gift_card.as_ref() {
                GiftCardData::PaySafeCard { .. } => Self::Paysafecard,
                _ => return Err(unsupported_payment_method()),
            },
            PaymentMethodData::Crypto(_) => Self::Crypto,
            _ => return Err(unsupported_payment_method()),
        };
        Ok(method)
    }
}

fn unsupported_payment_method() -> error_stack::Report<errors::ConnectorError> {
    report!(errors::ConnectorError::NotImplemented(
        utils::get_unimplemented_payment_method_error_message("paytech"),
    ))
}

/// Brazilian document types PayTech names in its reference values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PaytechDocumentType {
    #[serde(rename = "BR_CPF")]
    BrCpf,
    #[serde(rename = "BR_CNPJ")]
    BrCnpj,
}

/// A CPF has 11 digits and a CNPJ 14, so the number says which one it is when
/// the payment does not.
fn brazilian_document(
    number: &Secret<String>,
    kind: Option<common_types::customers::DocumentKind>,
) -> Option<(PaytechDocumentType, Secret<String>)> {
    let digits: String = number.peek().chars().filter(char::is_ascii_digit).collect();
    let document_type = match kind {
        Some(common_types::customers::DocumentKind::Cpf) => PaytechDocumentType::BrCpf,
        Some(common_types::customers::DocumentKind::Cnpj) => PaytechDocumentType::BrCnpj,
        Some(_) => return None,
        None => match digits.len() {
            11 => PaytechDocumentType::BrCpf,
            14 => PaytechDocumentType::BrCnpj,
            _ => return None,
        },
    };
    Some((document_type, Secret::new(digits)))
}

/// The customer's document, for the methods whose data carries one.
fn customer_document(
    payment_method_data: &PaymentMethodData,
) -> Option<(PaytechDocumentType, Secret<String>)> {
    match payment_method_data {
        PaymentMethodData::Voucher(VoucherData::Boleto(boleto)) => boleto
            .social_security_number
            .as_ref()
            .and_then(|number| brazilian_document(number, boleto.document_type)),
        PaymentMethodData::BankTransfer(bank_transfer) => match bank_transfer.as_ref() {
            BankTransferData::Pix { cpf, cnpj, .. } => cpf
                .as_ref()
                .and_then(|cpf| {
                    brazilian_document(cpf, Some(common_types::customers::DocumentKind::Cpf))
                })
                .or_else(|| {
                    cnpj.as_ref().and_then(|cnpj| {
                        brazilian_document(cnpj, Some(common_types::customers::DocumentKind::Cnpj))
                    })
                }),
            _ => None,
        },
        _ => None,
    }
}

/// PayTech wants the international number without the `+`, with a space
/// between the dialling code and the number: `357 123123123`.
fn paytech_phone(phone: &PhoneDetails) -> Option<Secret<String>> {
    let number = phone.number.as_ref()?.peek().trim().to_string();
    let code = phone
        .country_code
        .as_deref()?
        .trim()
        .trim_start_matches('+')
        .to_string();
    if number.is_empty() || code.is_empty() {
        return None;
    }
    Some(Secret::new(format!("{code} {number}")))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_type: Option<PaytechDocumentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_number: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechBillingAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    address_line1: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_line2: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<enums::CountryAlpha2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<Secret<String>>,
}

/// `POST /api/v1/payments` for a deposit. PayTech answers with a `redirectUrl`
/// to its checkout page, where the customer completes the payment.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechPaymentsRequest {
    reference_id: String,
    payment_type: PaytechPaymentType,
    payment_method: PaytechPaymentMethod,
    amount: FloatMajorUnit,
    currency: enums::Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    customer: PaytechCustomer,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address: Option<PaytechBillingAddress>,
    return_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_url: Option<String>,
}

impl TryFrom<&PaytechRouterData<&PaymentsAuthorizeRouterData>> for PaytechPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &PaytechRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        let payment_method_data = &router_data.request.payment_method_data;
        let payment_method = PaytechPaymentMethod::try_from(payment_method_data)?;

        let email = router_data
            .get_optional_billing_email()
            .or_else(|| router_data.request.email.clone());
        let browser_info = router_data.request.browser_info.as_ref();
        let document = customer_document(payment_method_data);
        let customer = PaytechCustomer {
            reference_id: router_data
                .customer_id
                .as_ref()
                .map(|customer_id| customer_id.get_string_repr().to_string())
                .or_else(|| email.as_ref().map(|email| email.peek().to_string())),
            first_name: router_data.get_optional_billing_first_name(),
            last_name: router_data.get_optional_billing_last_name(),
            email,
            phone: router_data
                .get_optional_billing()
                .and_then(|billing| billing.phone.as_ref())
                .and_then(paytech_phone),
            locale: browser_info
                .and_then(|browser_info| browser_info.language.as_deref())
                .and_then(|language| language.split(['-', '_']).next())
                .filter(|language| !language.is_empty())
                .map(str::to_lowercase),
            ip: browser_info
                .and_then(|browser_info| browser_info.ip_address)
                .map(|ip_address| Secret::new(ip_address.to_string())),
            document_type: document.as_ref().map(|(document_type, _)| *document_type),
            document_number: document.map(|(_, number)| number),
        };

        let billing_address = router_data
            .get_optional_billing()
            .and_then(|billing| billing.address.as_ref())
            .map(|_| PaytechBillingAddress {
                address_line1: router_data.get_optional_billing_line1(),
                address_line2: router_data.get_optional_billing_line2(),
                city: router_data.get_optional_billing_city(),
                country_code: router_data.get_optional_billing_country(),
                postal_code: router_data.get_optional_billing_zip(),
                state: router_data.get_optional_billing_state(),
            });

        Ok(Self {
            reference_id: router_data.connector_request_reference_id.clone(),
            payment_type: PaytechPaymentType::Deposit,
            payment_method,
            amount: item.amount,
            currency: router_data.request.currency,
            description: router_data.description.clone(),
            customer,
            billing_address,
            return_url: router_data.request.get_router_return_url()?,
            webhook_url: router_data.request.webhook_url.clone(),
        })
    }
}

/// Every payment endpoint answers `{timestamp, status, result}`. A webhook
/// carries the `result` alone; it is wrapped in this before the payment or
/// refund flow reads it, so both are read the same way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechPaymentResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    result: PaytechPaymentResult,
}

impl From<PaytechPaymentResult> for PaytechPaymentResponse {
    fn from(result: PaytechPaymentResult) -> Self {
        Self {
            timestamp: None,
            status: None,
            result,
        }
    }
}

/// A payment object: a deposit, a refund or a chargeback, each with its own
/// `id`. Serialised back for the payment or refund flow to read, so the names
/// have to stay as they arrive.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechPaymentResult {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_type: Option<PaytechPaymentType>,
    state: PaytechPaymentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_result_code: Option<String>,
}

impl PaytechPaymentResult {
    /// PayTech's own message, with the provider's result after it when there is
    /// one. That field is free text more often than a code (payment-api,
    /// `mapExternalResultCode`).
    fn reason(&self) -> Option<String> {
        match (&self.error_message, &self.external_result_code) {
            (Some(message), Some(external)) => {
                Some(format!("{message}; provider result: {external}"))
            }
            (Some(message), None) => Some(message.clone()),
            (None, external) => external.clone(),
        }
    }

    fn error_response(
        &self,
        http_code: u16,
        attempt_status: Option<enums::AttemptStatus>,
    ) -> ErrorResponse {
        ErrorResponse {
            status_code: http_code,
            code: self
                .error_code
                .clone()
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message: self
                .error_message
                .clone()
                .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
            reason: self.reason(),
            attempt_status,
            connector_transaction_id: Some(self.id.clone()),
            connector_response_reference_id: self.reference_id.clone(),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

/// A deposit's state as a payment attempt status. `previous` is the attempt's
/// status before this response: a status lookup carries no `redirectUrl`, and
/// a payment still at PayTech's checkout page is still waiting for the customer.
fn attempt_status(
    state: PaytechPaymentState,
    has_redirect: bool,
    previous: enums::AttemptStatus,
) -> enums::AttemptStatus {
    match state {
        PaytechPaymentState::Completed => enums::AttemptStatus::Charged,
        PaytechPaymentState::Authorized => enums::AttemptStatus::Authorized,
        PaytechPaymentState::Declined | PaytechPaymentState::Cancelled => {
            enums::AttemptStatus::Failure
        }
        PaytechPaymentState::Checkout | PaytechPaymentState::Pending
            if has_redirect || previous == enums::AttemptStatus::AuthenticationPending =>
        {
            enums::AttemptStatus::AuthenticationPending
        }
        PaytechPaymentState::Checkout
        | PaytechPaymentState::Pending
        | PaytechPaymentState::AwaitingApproval
        | PaytechPaymentState::Unknown => enums::AttemptStatus::Pending,
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, PaytechPaymentResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PaytechPaymentResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let result = item.response.result;
        let status = attempt_status(
            result.state,
            result.redirect_url.is_some(),
            item.data.status,
        );

        if status == enums::AttemptStatus::Failure {
            return Ok(Self {
                status,
                response: Err(result.error_response(item.http_code, Some(status))),
                ..item.data
            });
        }

        let redirection_data = match (status, &result.redirect_url) {
            (enums::AttemptStatus::AuthenticationPending, Some(redirect_url)) => {
                let redirect_url = url::Url::parse(redirect_url)
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                Some(RedirectForm::from((redirect_url, Method::Get)))
            }
            _ => None,
        };

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(result.id),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: result.reference_id,
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            }),
            ..item.data
        })
    }
}

/// `POST /api/v1/payments` for a refund: a payment object of its own, pointing
/// at the deposit. The amount is always sent, so a full refund is explicit too.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaytechRefundRequest {
    reference_id: String,
    payment_type: PaytechPaymentType,
    amount: FloatMajorUnit,
    currency: enums::Currency,
    parent_payment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_url: Option<String>,
}

impl<F> TryFrom<&PaytechRouterData<&RefundsRouterData<F>>> for PaytechRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaytechRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let request = &item.router_data.request;
        Ok(Self {
            reference_id: request.refund_id.clone(),
            payment_type: PaytechPaymentType::Refund,
            amount: item.amount,
            currency: request.currency,
            parent_payment_id: request.connector_transaction_id.clone(),
            webhook_url: request.webhook_url.clone(),
        })
    }
}

/// Refunds are asynchronous: they usually come back PENDING and finish by
/// webhook (payment-api's experience with the same engine).
fn refund_status(state: PaytechPaymentState) -> enums::RefundStatus {
    match state {
        PaytechPaymentState::Completed => enums::RefundStatus::Success,
        PaytechPaymentState::Declined | PaytechPaymentState::Cancelled => {
            enums::RefundStatus::Failure
        }
        PaytechPaymentState::Checkout
        | PaytechPaymentState::Pending
        | PaytechPaymentState::Authorized
        | PaytechPaymentState::AwaitingApproval
        | PaytechPaymentState::Unknown => enums::RefundStatus::Pending,
    }
}

impl<F> TryFrom<RefundsResponseRouterData<F, PaytechPaymentResponse>> for RefundsRouterData<F> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<F, PaytechPaymentResponse>,
    ) -> Result<Self, Self::Error> {
        let result = item.response.result;
        let refund_status = refund_status(result.state);

        // The router records an error with a 2xx status as a definite refund failure.
        let response = if refund_status == enums::RefundStatus::Failure {
            Err(result.error_response(item.http_code, None))
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: result.id,
                refund_status,
            })
        };

        Ok(Self {
            response,
            ..item.data
        })
    }
}

/// A 400 carries `errors` (the fields that failed validation); a 401 or 404
/// only `status`, `error` and `message`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaytechErrorResponse {
    pub status: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub errors: Option<serde_json::Value>,
}

impl PaytechErrorResponse {
    pub fn code(&self, http_code: u16) -> String {
        self.error
            .clone()
            .unwrap_or_else(|| self.status.unwrap_or(http_code).to_string())
    }

    pub fn message(&self) -> String {
        self.message
            .clone()
            .or_else(|| self.error.clone())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string())
    }

    pub fn reason(&self) -> Option<String> {
        match &self.errors {
            Some(serde_json::Value::Array(errors)) if !errors.is_empty() => Some(
                errors
                    .iter()
                    .map(|error| match error {
                        serde_json::Value::String(error) => error.clone(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            _ => self.message.clone(),
        }
    }
}

/// The webhook body: the payment object alone, signed with the shop's signing
/// key (HMAC-SHA256 of the raw body, hex, in `Signature`).
pub type PaytechWebhookBody = PaytechPaymentResult;

impl PaytechPaymentResult {
    pub fn event_type(&self) -> api_models::webhooks::IncomingWebhookEvent {
        use api_models::webhooks::IncomingWebhookEvent;

        match (self.payment_type, self.state) {
            (Some(PaytechPaymentType::Deposit), PaytechPaymentState::Completed) => {
                IncomingWebhookEvent::PaymentIntentSuccess
            }
            (Some(PaytechPaymentType::Deposit), PaytechPaymentState::Authorized) => {
                IncomingWebhookEvent::PaymentIntentAuthorizationSuccess
            }
            (Some(PaytechPaymentType::Deposit), state) if state.is_failure() => {
                IncomingWebhookEvent::PaymentIntentFailure
            }
            (Some(PaytechPaymentType::Deposit), _) => IncomingWebhookEvent::PaymentIntentProcessing,
            (Some(PaytechPaymentType::Refund), PaytechPaymentState::Completed) => {
                IncomingWebhookEvent::RefundSuccess
            }
            (Some(PaytechPaymentType::Refund), state) if state.is_failure() => {
                IncomingWebhookEvent::RefundFailure
            }
            // Chargebacks are left alone until PayTech says what their states mean:
            // payment-api notes that a CHARGEBACK carrying DECLINED is a finished
            // dispute, not a declined sale.
            _ => IncomingWebhookEvent::EventNotSupported,
        }
    }

    /// By PayTech's id, which every payment object has its own of. A chargeback
    /// points at the sale through `parentPaymentId`.
    pub fn object_reference_id(
        &self,
    ) -> Result<api_models::webhooks::ObjectReferenceId, error_stack::Report<errors::ConnectorError>>
    {
        use api_models::{
            payments::PaymentIdType,
            webhooks::{ObjectReferenceId, RefundIdType},
        };

        Ok(match self.payment_type {
            Some(PaytechPaymentType::Refund) => {
                ObjectReferenceId::RefundId(RefundIdType::ConnectorRefundId(self.id.clone()))
            }
            Some(PaytechPaymentType::Chargeback) => {
                ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(
                    self.parent_payment_id
                        .clone()
                        .ok_or_else(utils::missing_field_err("parentPaymentId"))?,
                ))
            }
            _ => {
                ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(self.id.clone()))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use common_enums::enums::{AttemptStatus, Currency, RefundStatus};
    use common_utils::types::{AmountConvertor, FloatMajorUnitForConnector, MinorUnit};
    use hyperswitch_masking::{PeekInterface, Secret};

    use super::*;

    const DEFAULT: &str = "https://engine.pay.tech";

    fn metadata(platform_url: &str) -> Option<common_utils::pii::SecretSerdeValue> {
        Some(Secret::new(
            serde_json::json!({ "platform_url": platform_url }),
        ))
    }

    #[test]
    fn an_account_without_a_platform_url_uses_the_default() {
        assert_eq!(brand_base_url(DEFAULT, &None).unwrap(), DEFAULT);
    }

    #[test]
    fn an_accounts_platform_url_picks_its_brand() {
        assert_eq!(
            brand_base_url(DEFAULT, &metadata("https://engine.brand.example")).unwrap(),
            "https://engine.brand.example"
        );
    }

    #[test]
    fn a_platform_url_with_a_path_is_refused() {
        assert!(brand_base_url(DEFAULT, &metadata("https://engine.pay.tech/api/v1")).is_err());
    }

    #[test]
    fn payment_methods_are_sent_under_paytechs_names() {
        let names = [
            (PaytechPaymentMethod::P24, "P24"),
            (PaytechPaymentMethod::TouchNGo, "TOUCH_N_GO"),
            (PaytechPaymentMethod::MomopayVn, "MOMOPAY_VN"),
            (PaytechPaymentMethod::OpenBanking, "OPEN_BANKING"),
            (PaytechPaymentMethod::Pagoefectivo, "PAGOEFECTIVO"),
            (PaytechPaymentMethod::Ideal, "IDEAL"),
        ];
        for (method, name) in names {
            assert_eq!(serde_json::to_value(method).unwrap(), name);
        }
    }

    #[test]
    fn a_card_typed_into_hyperswitch_is_not_paytechs_to_take() {
        let card = PaymentMethodData::Card(Default::default());
        assert!(PaytechPaymentMethod::try_from(&card).is_err());
    }

    #[test]
    fn cards_apple_pay_and_google_pay_open_paytechs_card_page() {
        use hyperswitch_domain_models::payment_method_data::{
            ApplePayRedirectData, GooglePayRedirectData,
        };
        let redirects = [
            PaymentMethodData::CardRedirect(CardRedirectData::CardRedirect {}),
            PaymentMethodData::Wallet(WalletData::ApplePayRedirect(Box::new(
                ApplePayRedirectData {},
            ))),
            PaymentMethodData::Wallet(WalletData::GooglePayRedirect(Box::new(
                GooglePayRedirectData {},
            ))),
        ];
        for payment_method_data in redirects {
            let method = PaytechPaymentMethod::try_from(&payment_method_data).unwrap();
            assert_eq!(serde_json::to_value(method).unwrap(), "BASIC_CARD");
        }
    }

    #[test]
    fn amounts_are_major_units_for_each_currency_exponent() {
        let amount = |minor, currency| {
            let major = FloatMajorUnitForConnector
                .convert(MinorUnit::new(minor), currency)
                .unwrap();
            serde_json::to_string(&major).unwrap()
        };
        assert_eq!(amount(1112, Currency::EUR), "11.12");
        assert_eq!(amount(1500, Currency::JPY), "1500.0");
        assert_eq!(amount(1234, Currency::KWD), "1.234");
    }

    #[test]
    fn a_phone_is_sent_without_the_plus_and_with_a_space() {
        let phone = PhoneDetails {
            number: Some(Secret::new("5321234567".to_string())),
            country_code: Some("+90".to_string()),
        };
        assert_eq!(paytech_phone(&phone).unwrap().peek(), "90 5321234567");
    }

    #[test]
    fn a_phone_without_a_dialling_code_is_left_out() {
        let phone = PhoneDetails {
            number: Some(Secret::new("5321234567".to_string())),
            country_code: None,
        };
        assert!(paytech_phone(&phone).is_none());
    }

    #[test]
    fn a_brazilian_document_is_told_apart_by_its_length() {
        let cpf = brazilian_document(&Secret::new("123.456.789-09".to_string()), None).unwrap();
        assert_eq!(cpf.0, PaytechDocumentType::BrCpf);
        assert_eq!(cpf.1.peek(), "12345678909");
        let cnpj =
            brazilian_document(&Secret::new("12.345.678/0001-95".to_string()), None).unwrap();
        assert_eq!(cnpj.0, PaytechDocumentType::BrCnpj);
    }

    #[test]
    fn a_payment_at_the_checkout_page_waits_for_the_customer() {
        assert_eq!(
            attempt_status(PaytechPaymentState::Checkout, true, AttemptStatus::Started),
            AttemptStatus::AuthenticationPending
        );
        // A later lookup has no redirectUrl; the customer still has to finish.
        assert_eq!(
            attempt_status(
                PaytechPaymentState::Checkout,
                false,
                AttemptStatus::AuthenticationPending
            ),
            AttemptStatus::AuthenticationPending
        );
    }

    #[test]
    fn final_states_end_the_payment() {
        let status = |state| attempt_status(state, false, AttemptStatus::Pending);
        assert_eq!(
            status(PaytechPaymentState::Completed),
            AttemptStatus::Charged
        );
        assert_eq!(
            status(PaytechPaymentState::Declined),
            AttemptStatus::Failure
        );
        assert_eq!(
            status(PaytechPaymentState::Cancelled),
            AttemptStatus::Failure
        );
        assert_eq!(
            status(PaytechPaymentState::AwaitingApproval),
            AttemptStatus::Pending
        );
    }

    #[test]
    fn a_pending_refund_stays_pending() {
        assert_eq!(
            refund_status(PaytechPaymentState::Pending),
            RefundStatus::Pending
        );
        assert_eq!(
            refund_status(PaytechPaymentState::Completed),
            RefundStatus::Success
        );
        assert_eq!(
            refund_status(PaytechPaymentState::Declined),
            RefundStatus::Failure
        );
    }

    fn webhook(body: serde_json::Value) -> PaytechWebhookBody {
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn webhooks_say_what_happened_to_a_deposit_or_a_refund() {
        use api_models::webhooks::IncomingWebhookEvent;
        let completed_deposit = webhook(serde_json::json!({
            "id": "p1", "paymentType": "DEPOSIT", "state": "COMPLETED"
        }));
        assert_eq!(
            completed_deposit.event_type(),
            IncomingWebhookEvent::PaymentIntentSuccess
        );
        let cancelled_deposit = webhook(serde_json::json!({
            "id": "p1", "paymentType": "DEPOSIT", "state": "CANCELLED",
            "errorCode": "1.04", "errorMessage": "Cancelled by Timeout"
        }));
        assert_eq!(
            cancelled_deposit.event_type(),
            IncomingWebhookEvent::PaymentIntentFailure
        );
        let completed_refund = webhook(serde_json::json!({
            "id": "r1", "paymentType": "REFUND", "state": "COMPLETED", "parentPaymentId": "p1"
        }));
        assert_eq!(
            completed_refund.event_type(),
            IncomingWebhookEvent::RefundSuccess
        );
    }

    #[test]
    fn chargebacks_and_unknown_types_are_not_acted_on() {
        use api_models::webhooks::IncomingWebhookEvent;
        let chargeback = webhook(serde_json::json!({
            "id": "c1", "paymentType": "CHARGEBACK", "state": "DECLINED", "parentPaymentId": "p1"
        }));
        assert_eq!(
            chargeback.event_type(),
            IncomingWebhookEvent::EventNotSupported
        );
        let unknown = webhook(serde_json::json!({
            "id": "x1", "paymentType": "SOMETHING_NEW", "state": "SOMETHING_ELSE"
        }));
        assert_eq!(
            unknown.event_type(),
            IncomingWebhookEvent::EventNotSupported
        );
    }

    #[test]
    fn a_refund_webhook_finds_the_refund_by_paytechs_id() {
        let refund = webhook(serde_json::json!({
            "id": "r1", "paymentType": "REFUND", "state": "COMPLETED", "parentPaymentId": "p1"
        }));
        assert!(matches!(
            refund.object_reference_id().unwrap(),
            api_models::webhooks::ObjectReferenceId::RefundId(
                api_models::webhooks::RefundIdType::ConnectorRefundId(id)
            ) if id == "r1"
        ));
    }
}
