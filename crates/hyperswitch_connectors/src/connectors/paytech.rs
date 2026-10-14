pub mod transformers;

use std::sync::LazyLock;

use common_enums::{enums, CallConnectorAction, PaymentAction};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsSyncRouterData, RefundSyncRouterData,
        RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorRedirectResponse,
        ConnectorSpecifications, ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{ExposeInterface, Mask};
use transformers as paytech;

use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, RefundsRequestData},
};

#[derive(Clone)]
pub struct Paytech {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Paytech {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &FloatMajorUnitForConnector,
        }
    }

    /// `/api/v1/payments[/{id}]` on the brand the account names, else on the
    /// deployment's default (`paytech::brand_base_url`). Deposits and refunds
    /// are both created at `/api/v1/payments` and looked up by their own id.
    fn payments_url(
        &self,
        connectors: &Connectors,
        connector_meta_data: &Option<common_utils::pii::SecretSerdeValue>,
        id: Option<&str>,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = paytech::brand_base_url(self.base_url(connectors), connector_meta_data)?;
        let base_url = base_url.trim_end_matches('/');
        Ok(match id {
            Some(id) => format!("{base_url}/api/v1/payments/{}", urlencoding::encode(id)),
            None => format!("{base_url}/api/v1/payments"),
        })
    }
}

impl api::Payment for Paytech {}
impl api::PaymentSession for Paytech {}
impl api::ConnectorAccessToken for Paytech {}
impl api::MandateSetup for Paytech {}
impl api::PaymentAuthorize for Paytech {}
impl api::PaymentSync for Paytech {}
impl api::PaymentCapture for Paytech {}
impl api::PaymentVoid for Paytech {}
impl api::Refund for Paytech {}
impl api::RefundExecute for Paytech {}
impl api::RefundSync for Paytech {}
impl api::PaymentToken for Paytech {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Paytech
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Paytech
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut header = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            ),
            (
                headers::ACCEPT.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
        ];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Paytech {
    fn id(&self) -> &'static str {
        "paytech"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        // `amount` is a JSON number in major units: 11.12 for EUR 11.12.
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.paytech.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = paytech::PaytechAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.expose()).into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: paytech::PaytechErrorResponse = match res
            .response
            .parse_struct("PaytechErrorResponse")
        {
            Ok(response) => response,
            Err(_) => return utils::handle_json_response_deserialization_failure(res, "paytech"),
        };

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code(res.status_code),
            message: response.message(),
            reason: response.reason(),
            attempt_status: None,
            connector_transaction_id: None,
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        })
    }
}

impl ConnectorValidation for Paytech {}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Paytech {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Paytech {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Paytech {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Paytech {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.payments_url(connectors, &req.connector_meta_data, None)
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let connector_router_data = paytech::PaytechRouterData::from((amount, req));
        let connector_req = paytech::PaytechPaymentsRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: paytech::PaytechPaymentResponse = res
            .response
            .parse_struct("Paytech PaymentsAuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Paytech {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        self.payments_url(connectors, &req.connector_meta_data, Some(&payment_id))
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        let response: paytech::PaytechPaymentResponse = res
            .response
            .parse_struct("Paytech PaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Paytech {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Paytech {}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Paytech {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.payments_url(connectors, &req.connector_meta_data, None)
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let refund_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;

        let connector_router_data = paytech::PaytechRouterData::from((refund_amount, req));
        let connector_req = paytech::PaytechRefundRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(types::RefundExecuteType::get_headers(
                self, req, connectors,
            )?)
            .set_body(types::RefundExecuteType::get_request_body(
                self, req, connectors,
            )?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let response: paytech::PaytechPaymentResponse = res
            .response
            .parse_struct("Paytech RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Paytech {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // A refund is a payment object of its own, looked up by its own id.
        let refund_id = req.request.get_connector_refund_id()?;
        self.payments_url(connectors, &req.connector_meta_data, Some(&refund_id))
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: paytech::PaytechPaymentResponse = res
            .response
            .parse_struct("Paytech RefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorRedirectResponse for Paytech {
    fn get_flow_type(
        &self,
        _query_params: &str,
        _json_payload: Option<serde_json::Value>,
        action: PaymentAction,
    ) -> CustomResult<CallConnectorAction, errors::ConnectorError> {
        // When the customer comes back from PayTech's checkout page, look the
        // outcome up straight away instead of leaving it to the next scheduled
        // payment sync.
        match action {
            PaymentAction::PSync
            | PaymentAction::CompleteAuthorize
            | PaymentAction::PaymentAuthenticateCompleteAuthorize => {
                Ok(CallConnectorAction::Trigger)
            }
        }
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Paytech {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let signature = utils::get_header_key_value("Signature", request.headers)?;
        hex::decode(signature.trim())
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // The signature covers the body exactly as it was sent.
        Ok(request.body.to_vec())
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let body: paytech::PaytechWebhookBody = request
            .body
            .parse_struct("PaytechWebhookBody")
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;

        body.object_reference_id()
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let body: paytech::PaytechWebhookBody = request
            .body
            .parse_struct("PaytechWebhookBody")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

        Ok(body.event_type())
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        // Handed to the payment or refund flow once the signature checks out, and
        // read there the way a status lookup's body is read, so it gets the same
        // `{result: ...}` envelope.
        let body: paytech::PaytechWebhookBody = request
            .body
            .parse_struct("PaytechWebhookBody")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        Ok(Box::new(paytech::PaytechPaymentResponse::from(body)))
    }
}

/// The payment method types the connector maps to a PayTech `paymentMethod`
/// (`PaytechPaymentMethod`). PayTech decides per shop which of them are on.
const PAYTECH_PAYMENT_METHOD_TYPES: [(enums::PaymentMethod, enums::PaymentMethodType); 48] = [
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::AliPay,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Cashapp,
    ),
    (enums::PaymentMethod::Wallet, enums::PaymentMethodType::Dana),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Gcash,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::GoPay,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::KakaoPay,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::MbWay,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Mifinity,
    ),
    (enums::PaymentMethod::Wallet, enums::PaymentMethodType::Momo),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Paypal,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::RevolutPay,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Skrill,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Swish,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::TouchNGo,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Twint,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Vipps,
    ),
    (
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::WeChatPay,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::BancontactCard,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Bizum,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Blik,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Eft,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Eps,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Giropay,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Ideal,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Interac,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::OnlineBankingFpx,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::OpenBanking,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Przelewy24,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Sofort,
    ),
    (
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::Trustly,
    ),
    (
        enums::PaymentMethod::BankTransfer,
        enums::PaymentMethodType::Ach,
    ),
    (
        enums::PaymentMethod::BankTransfer,
        enums::PaymentMethodType::Multibanco,
    ),
    (
        enums::PaymentMethod::BankTransfer,
        enums::PaymentMethodType::Pix,
    ),
    (
        enums::PaymentMethod::BankTransfer,
        enums::PaymentMethodType::Pse,
    ),
    (
        enums::PaymentMethod::BankTransfer,
        enums::PaymentMethodType::SepaBankTransfer,
    ),
    (
        enums::PaymentMethod::Voucher,
        enums::PaymentMethodType::Alfamart,
    ),
    (
        enums::PaymentMethod::Voucher,
        enums::PaymentMethodType::Boleto,
    ),
    (
        enums::PaymentMethod::Voucher,
        enums::PaymentMethodType::Efecty,
    ),
    (
        enums::PaymentMethod::Voucher,
        enums::PaymentMethodType::Oxxo,
    ),
    (
        enums::PaymentMethod::Voucher,
        enums::PaymentMethodType::PagoEfectivo,
    ),
    (
        enums::PaymentMethod::RealTimePayment,
        enums::PaymentMethodType::DuitNow,
    ),
    (
        enums::PaymentMethod::RealTimePayment,
        enums::PaymentMethodType::PromptPay,
    ),
    (
        enums::PaymentMethod::RealTimePayment,
        enums::PaymentMethodType::Qris,
    ),
    (
        enums::PaymentMethod::PayLater,
        enums::PaymentMethodType::Klarna,
    ),
    (
        enums::PaymentMethod::Upi,
        enums::PaymentMethodType::UpiCollect,
    ),
    (
        enums::PaymentMethod::Upi,
        enums::PaymentMethodType::UpiIntent,
    ),
    (
        enums::PaymentMethod::GiftCard,
        enums::PaymentMethodType::PaySafeCard,
    ),
    (
        enums::PaymentMethod::Crypto,
        enums::PaymentMethodType::CryptoCurrency,
    ),
];

static PAYTECH_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut paytech_supported_payment_methods = SupportedPaymentMethods::new();

    for (payment_method, payment_method_type) in PAYTECH_PAYMENT_METHOD_TYPES {
        paytech_supported_payment_methods.add(
            payment_method,
            payment_method_type,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                // The API refunds any deposit; whether a method's provider
                // accepts the refund is PayTech's to answer, per payment.
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );
    }

    paytech_supported_payment_methods
});

static PAYTECH_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "PayTech",
    description: "pay.tech's PayPlane engine: local and alternative payment methods through its checkout page, and refunds",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Alpha,
};

static PAYTECH_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 2] =
    [enums::EventClass::Payments, enums::EventClass::Refunds];

impl ConnectorSpecifications for Paytech {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&PAYTECH_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*PAYTECH_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&PAYTECH_SUPPORTED_WEBHOOK_FLOWS)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use common_utils::crypto::VerifySignature;
    use hyperswitch_interfaces::webhooks::{IncomingWebhook, IncomingWebhookRequestDetails};

    use super::Paytech;

    const SIGNING_KEY: &[u8] = b"test-signing-key";
    const BODY: &[u8] =
        br#"{"id":"9e9003d7f3324fc6828481c665d8bab5","paymentType":"DEPOSIT","state":"COMPLETED"}"#;
    /// Computed outside Rust, the way PayTech and payment-api do it:
    /// `hmac.new(SIGNING_KEY, BODY, hashlib.sha256).hexdigest()`.
    const SIGNATURE: &str = "48d2b8bac50c303d489c558200c548960b6d8ed1f567a16e35f8d877a6dbfa15";

    fn verifies(signature: &str, body: &[u8]) -> bool {
        let mut headers = actix_web::http::header::HeaderMap::new();
        headers.insert(
            actix_web::http::header::HeaderName::from_static("signature"),
            actix_web::http::header::HeaderValue::from_str(signature).unwrap(),
        );
        let request = IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: http::Uri::from_static("/webhooks"),
            headers: &headers,
            body,
            query_params: String::new(),
        };
        let secrets = api_models::webhooks::ConnectorWebhookSecrets {
            secret: SIGNING_KEY.to_vec(),
            additional_secret: None,
        };
        let merchant_id = common_utils::id_type::MerchantId::get_merchant_id_not_found();
        let connector = Paytech::new();
        let signature = connector
            .get_webhook_source_verification_signature(&request, &secrets)
            .unwrap();
        let message = connector
            .get_webhook_source_verification_message(&request, &merchant_id, &secrets)
            .unwrap();
        common_utils::crypto::HmacSha256
            .verify_signature(&secrets.secret, &signature, &message)
            .unwrap()
    }

    #[test]
    fn a_webhook_signed_with_the_shops_signing_key_is_accepted() {
        assert!(verifies(SIGNATURE, BODY));
    }

    #[test]
    fn a_webhook_whose_body_was_changed_is_refused() {
        let changed =
            br#"{"id":"9e9003d7f3324fc6828481c665d8bab5","paymentType":"DEPOSIT","state":"DECLINED"}"#;
        assert!(!verifies(SIGNATURE, changed));
    }
}
