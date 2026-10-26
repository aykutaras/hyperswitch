pub mod transformers;

use std::sync::LazyLock;

use base64::Engine;
use common_enums::{enums, CallConnectorAction, PaymentAction};
use common_utils::{
    consts, crypto, date_time,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
        CreateConnectorCustomer,
    },
    router_request_types::{
        AccessTokenRequestData, ConnectorCustomerData, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData,
        PaymentsSyncData, RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        ConnectorCustomerRouterData, PaymentsAuthorizeRouterData, PaymentsSyncRouterData,
        RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorIntegration, ConnectorRedirectResponse,
        ConnectorSpecifications, ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{ExposeInterface, Mask, Maskable, PeekInterface, Secret};
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};
use transformers as saltedge;

use crate::{constants::headers, types::ResponseRouterData, utils};

/// How long a signed request stays valid. Salt Edge suggests a minute and
/// refuses more than an hour (`ExpiresAtInvalid`).
const SIGNATURE_LIFETIME_SECONDS: i64 = 60;

/// The key Salt Edge signs its callbacks with, `Signature-key-version` 6.0,
/// as published in its docs (docs.saltedge.com/v6, Callbacks, Request
/// identification).
const SALTEDGE_CALLBACK_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8qxSS5BmftHK/eyW+o98
NR89TyDmz1V8e6yyFdoMPddEYN4Bcidkk2whoJEc/T/AKghHQ9Nq+DuebnRYYcSJ
YT99VbR1PpIw2R9i8z+DZ79hoizy6z+rwxGANnJOr5BDF5HUKJ8uKS9yGRieojFv
Y9j+rxH6Fj6P90bO4d2igYYspKVoI3Zb3hWS0LrWN+JXAaW9qcOmQPTgO0WG0MUK
gB3NNMfN7gMIkl3chbaULiEgVciP2qZTIGb1b7IDr5+fA9oVVGaXiybdieGHIa4J
S7JNTf0JjWrIKd2DaczKULnghqNQsnoCu+S8BurEOJR5EN1BBfQBPlbSh+ru1zgZ
AQIDAQAB
-----END PUBLIC KEY-----";

#[derive(Clone)]
pub struct Saltedge {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Saltedge {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }

    fn api_url(&self, connectors: &Connectors, path: &str) -> String {
        format!(
            "{}/api/v6/{path}",
            self.base_url(connectors).trim_end_matches('/')
        )
    }

    /// The API key, and `Expires-at` with the `Signature` over this exact
    /// request. Salt Edge requires the signature from a Live application and
    /// checks it whenever it is sent, so every environment signs.
    fn signed_headers(
        &self,
        auth_type: &ConnectorAuthType,
        method: Method,
        url: &str,
        body: Option<RequestContent>,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = saltedge::SaltedgeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        let expires_at = (date_time::now_unix_timestamp() + SIGNATURE_LIFETIME_SECONDS).to_string();
        let body = body
            .map(|body| body.get_inner_value().expose())
            .unwrap_or_default();
        let signature = sign(
            &auth.private_key,
            &signing_string(&expires_at, method, url, &body),
        )?;

        let mut headers = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::ACCEPT.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            ("Expires-at".to_string(), expires_at.into()),
            ("Signature".to_string(), signature.into_masked()),
        ];
        headers.append(&mut self.get_auth_header(auth_type)?);
        Ok(headers)
    }
}

/// What Salt Edge's request signature covers:
/// `Expires-at|request_method|original_url|post_body`, the body empty for a
/// GET.
fn signing_string(expires_at: &str, method: Method, url: &str, body: &str) -> String {
    format!("{expires_at}|{method}|{url}|{body}")
}

/// The private key as PEM, PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE
/// KEY`), whose line breaks a one-line form field may have turned into spaces.
fn rsa_key_pair(private_key: &str) -> CustomResult<RsaKeyPair, errors::ConnectorError> {
    let invalid = || {
        report!(errors::ConnectorError::InvalidConnectorConfig {
            config: "Private key (an RSA private key in PEM)",
        })
    };
    // `-----BEGIN …-----<base64>-----END …-----` splits into five parts.
    let parts: Vec<&str> = private_key.split("-----").collect();
    let base64_body = match parts.as_slice() {
        [_, _, body, _, _] => body,
        _ => private_key,
    };
    let der = consts::BASE64_ENGINE
        .decode(
            base64_body
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .map_err(|_| invalid())?;
    if private_key.contains("RSA PRIVATE KEY") {
        RsaKeyPair::from_der(&der).map_err(|_| invalid())
    } else {
        RsaKeyPair::from_pkcs8(&der)
            .or_else(|_| RsaKeyPair::from_der(&der))
            .map_err(|_| invalid())
    }
}

/// Base64 of the RSA-SHA256 (PKCS#1 v1.5) signature of `message`.
fn sign(
    private_key: &Secret<String>,
    message: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let key_pair = rsa_key_pair(private_key.peek())?;
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .map_err(|_| report!(errors::ConnectorError::RequestEncodingFailed))?;
    Ok(consts::BASE64_ENGINE.encode(signature))
}

/// The URL Salt Edge called, as it signed it: its application's callback URL,
/// which reaches the router through the ingress with host and path unchanged.
fn callback_url(request: &webhooks::IncomingWebhookRequestDetails<'_>) -> String {
    if request.uri.scheme().is_some() && request.uri.authority().is_some() {
        return request.uri.to_string();
    }
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let scheme = header("x-forwarded-proto").unwrap_or("https");
    let host = header("x-forwarded-host")
        .or_else(|| header("host"))
        .unwrap_or_default();
    let path = request
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    format!("{scheme}://{host}{path}")
}

impl api::Payment for Saltedge {}
impl api::PaymentSession for Saltedge {}
impl api::ConnectorAccessToken for Saltedge {}
impl api::MandateSetup for Saltedge {}
impl api::PaymentAuthorize for Saltedge {}
impl api::PaymentSync for Saltedge {}
impl api::PaymentCapture for Saltedge {}
impl api::PaymentVoid for Saltedge {}
impl api::Refund for Saltedge {}
impl api::RefundExecute for Saltedge {}
impl api::RefundSync for Saltedge {}
impl api::PaymentToken for Saltedge {}
impl api::ConnectorCustomer for Saltedge {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Saltedge
{
}

impl ConnectorCommon for Saltedge {
    fn id(&self) -> &'static str {
        "saltedge"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        // `amount` is a string in major units: "10.50" for EUR 10.50.
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.saltedge.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        let auth = saltedge::SaltedgeAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            ("App-id".to_string(), auth.app_id.expose().into_masked()),
            ("Secret".to_string(), auth.secret.expose().into_masked()),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: saltedge::SaltedgeErrorResponse = match res
            .response
            .parse_struct("SaltedgeErrorResponse")
        {
            Ok(response) => response,
            Err(_) => return utils::handle_json_response_deserialization_failure(res, "saltedge"),
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

impl ConnectorValidation for Saltedge {}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Saltedge {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Saltedge {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Saltedge
{
}

impl ConnectorIntegration<CreateConnectorCustomer, ConnectorCustomerData, PaymentsResponseData>
    for Saltedge
{
    fn get_headers(
        &self,
        req: &ConnectorCustomerRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.signed_headers(
            &req.connector_auth_type,
            Method::Post,
            &self.get_url(req, connectors)?,
            Some(self.get_request_body(req, connectors)?),
        )
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &ConnectorCustomerRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.api_url(connectors, "customers"))
    }

    fn get_request_body(
        &self,
        req: &ConnectorCustomerRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = saltedge::SaltedgeCustomerRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &ConnectorCustomerRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::ConnectorCustomerType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::ConnectorCustomerType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::ConnectorCustomerType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &ConnectorCustomerRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<ConnectorCustomerRouterData, errors::ConnectorError> {
        let response: saltedge::SaltedgeCustomerResponse = res
            .response
            .parse_struct("SaltedgeCustomerResponse")
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

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Saltedge {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.signed_headers(
            &req.connector_auth_type,
            Method::Post,
            &self.get_url(req, connectors)?,
            Some(self.get_request_body(req, connectors)?),
        )
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(self.api_url(connectors, "payments/create"))
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

        let connector_router_data = saltedge::SaltedgeRouterData::from((amount, req));
        let connector_req = saltedge::SaltedgePaymentRequest::try_from(&connector_router_data)?;
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
        let response: saltedge::SaltedgeCreatePaymentResponse = res
            .response
            .parse_struct("SaltedgeCreatePaymentResponse")
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

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Saltedge {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.signed_headers(
            &req.connector_auth_type,
            Method::Get,
            &self.get_url(req, connectors)?,
            None,
        )
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
        Ok(self.api_url(
            connectors,
            &format!("payments/{}", urlencoding::encode(&payment_id)),
        ))
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
        let response: saltedge::SaltedgePaymentResponse = res
            .response
            .parse_struct("SaltedgePaymentResponse")
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

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Saltedge {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Saltedge {}

/// The payer's bank pays the merchant directly and Salt Edge never holds the
/// funds, so there is nothing to refund through it: a refund is a transfer
/// from the merchant's own bank.
fn refunds_not_supported() -> error_stack::Report<errors::ConnectorError> {
    report!(errors::ConnectorError::NotSupported {
        message: "Refunds (pay the customer back from the merchant's bank)".to_string(),
        connector: "saltedge".into(),
    })
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Saltedge {
    fn build_request(
        &self,
        _req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(refunds_not_supported())
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Saltedge {
    fn build_request(
        &self,
        _req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(refunds_not_supported())
    }
}

impl ConnectorRedirectResponse for Saltedge {
    fn get_flow_type(
        &self,
        _query_params: &str,
        _json_payload: Option<serde_json::Value>,
        action: PaymentAction,
    ) -> CustomResult<CallConnectorAction, errors::ConnectorError> {
        // When the payer comes back from Salt Edge's widget, look the payment up
        // straight away instead of leaving it to the next scheduled sync.
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
impl webhooks::IncomingWebhook for Saltedge {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::RsaSha256))
    }

    /// Salt Edge signs every application's callbacks with its own key, so there
    /// is nothing to configure per account. `RsaSha256` takes the PEM base64'd.
    async fn get_webhook_source_verification_merchant_secret(
        &self,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_name: &str,
        _connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<api_models::webhooks::ConnectorWebhookSecrets, errors::ConnectorError> {
        Ok(api_models::webhooks::ConnectorWebhookSecrets {
            secret: consts::BASE64_ENGINE
                .encode(SALTEDGE_CALLBACK_PUBLIC_KEY)
                .into_bytes(),
            additional_secret: None,
        })
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // Base64, which `RsaSha256` decodes itself.
        let signature = utils::get_header_key_value("Signature", request.headers)?;
        Ok(signature.trim().as_bytes().to_vec())
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // `callback_url|post_body`. Should the URL not match what Salt Edge
        // signed, verification fails and the router looks the payment up
        // instead of trusting the body.
        let mut message = format!("{}|", callback_url(request)).into_bytes();
        message.extend_from_slice(request.body);
        Ok(message)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let body: saltedge::SaltedgeWebhookBody = request
            .body
            .parse_struct("SaltedgeWebhookBody")
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;

        body.object_reference_id()
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let body: saltedge::SaltedgeWebhookBody = request
            .body
            .parse_struct("SaltedgeWebhookBody")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

        Ok(body.event_type())
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let body: saltedge::SaltedgeWebhookBody = request
            .body
            .parse_struct("SaltedgeWebhookBody")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        Ok(Box::new(body.resource_object()?))
    }
}

static SALTEDGE_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut saltedge_supported_payment_methods = SupportedPaymentMethods::new();

        saltedge_supported_payment_methods.add(
            enums::PaymentMethod::BankRedirect,
            enums::PaymentMethodType::OpenBanking,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::NotSupported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        saltedge_supported_payment_methods
    });

static SALTEDGE_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Salt Edge",
    description: "Salt Edge's open banking gateway: Pay by bank from the payer's own bank, by Faster Payments in GBP and SEPA in EUR, straight to the merchant's account",
    connector_type: enums::HyperswitchConnectorCategory::AlternativePaymentMethod,
    integration_status: enums::ConnectorIntegrationStatus::Alpha,
};

static SALTEDGE_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Saltedge {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&SALTEDGE_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*SALTEDGE_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&SALTEDGE_SUPPORTED_WEBHOOK_FLOWS)
    }

    /// Salt Edge's Partner API needs a customer for every payment, created from
    /// the payer's email. The router keeps its id on the Hyperswitch customer.
    fn should_call_connector_customer(
        &self,
        _payment_attempt: &hyperswitch_domain_models::payments::payment_attempt::PaymentAttempt,
    ) -> api::ConnectorCustomerAction {
        api::ConnectorCustomerAction::CallConnectorCustomer
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use common_utils::crypto::VerifySignature;
    use hyperswitch_interfaces::webhooks::{IncomingWebhook, IncomingWebhookRequestDetails};

    use super::*;

    // A throwaway 2048-bit key made for these tests with
    // `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`, and the
    // same key in PKCS#1 (`openssl pkey -traditional`). It signs nothing real.
    const TEST_PRIVATE_KEY_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6gYC8nHtQX2ao
cZwEv5tLmGF050r90lujfGcGBwzjpu6kP3+ov02PhmwY6rGc0mqwkiMGZVz7TpN4
dVJ7GjTldwwORKYpG4JXwTvpjADsQ4qc/W00QuDSDjXpyyQqv98iM8JulO6AqsXD
bvZGaIOMU4zc6PokRbh1nN3c4QO6G2y4ypPGhpoCYr3esjMToEWMzhKB14b6rsju
ZnrjLHncyN1Q5G0OpkR1CWQQj6p4bkfAWWL447wofBAOjJukkf8pS8RjUNwOAYQ3
bToQ5lh8522j+ySGSYzvN4a3555Rgo/JYLusLcWdLdpz58Q1Uinc1ox1oBch4FFi
A4r8JyMbAgMBAAECggEABtnuCD+5WfT/OO3ffN8rDcZdwiUjAJsDKcjOog6NPymp
N5hrkJ/icgTOoMWyW5/xMmZT6g68MTEsQq8QphwK2GkcpMOJ1RXBHocnM8ekWwmK
JIU8x0AzsRO7kEiZngZpZIDBQj2vW0Oquyiu3FxHhNam5JCca8ux4IQwNEaB1ArQ
vR0Qke2P5cXlh2k2nl5aupfJEigRTZbL+OCIfk4NyxiIbq8TwElIvNc/OW58x2IK
RKqEJx5vhcvWMfoOE/5VDENzUcbvyALQ4TRcWlsG82ZgwQD8hFIEUwQkEjhFz0TP
JVP8n1+OtgBJm7Cry0N0MJgAl52ms3IDWE847h284QKBgQDwrX8oVvYLL06SlRDh
sXHDcVfpT8qZEOSiAptNeGcvCSl1rfsXzsNGg8N1jz7fb/kziyCMq0yzK3rD0V8C
6doS76xy43D+vMEg7CeFchB81DMmeYzPr/qJxjvPuCF9fRs6h+leviz9Wecj3fKz
DN07wRKAhL3xA68j2HgFlDeHoQKBgQDGYSCZvsUNbuFqXUa3xln9FqzMozqNFEJ2
fm2d76Fk3NbNUnfvLt6TmEXfHu8Mp7ZaJ2vlmdKDns7KNj1hpJxFe4zBEr+IXJ5z
xhAbXp9Go55Nt8bn3W3wtSK68sO7irOH2zYvbveuhg3rRt408k5jjLnD/kFxqIKm
/XE7JgtBOwKBgQDLk1U9P+E6MLebUS9IWBlMIbEkjfNmaV2ak+3dJ3zP0kYZXiJH
TwLpwEYySAn8YPA+4u2TTsm/u4VJ4O0mv7tPzR7mxu8q6WnKeTYssAC2NZ9WafXr
LoUSyHSLDMp3JL1FUvTYyK+xVLwoIHJLdRQkmPkXcDBhjqY0AcPzpB0cQQKBgQCq
qhJ+0hT6aoK4m8hj/9uZFTHR1zde+af4AupQ7j/d4vNUrncJqTvIpD6wJg+nxnzl
cHatjzkBDNWAN0t1PkVGrXS5AWUPbgbPOPzQXwYNomNlHw6amO+lHl/jj0h+hmPP
I/KougGQ/jjpSQ2PZUm08PM7vvgUTNEh0nXgWeli0wKBgHap700Kr/CQI2At8umL
x52XfcM2uYNU+iO9idQBeGD9tly/uYV/pMkLRGDMOCbk4ieJ1GP4x+W64EuQwVus
oNAzNELHzv6PRS0Ike8d+U/jMeIzYHuI4ELX5q026Pu18k6QRhgHrrVuGVnTW61H
5daw54yzORNPiMD19gI0ZAaQ
-----END PRIVATE KEY-----";

    const TEST_PRIVATE_KEY_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuoGAvJx7UF9mqHGcBL+bS5hhdOdK/dJbo3xnBgcM46bupD9/
qL9Nj4ZsGOqxnNJqsJIjBmVc+06TeHVSexo05XcMDkSmKRuCV8E76YwA7EOKnP1t
NELg0g416cskKr/fIjPCbpTugKrFw272RmiDjFOM3Oj6JEW4dZzd3OEDuhtsuMqT
xoaaAmK93rIzE6BFjM4SgdeG+q7I7mZ64yx53MjdUORtDqZEdQlkEI+qeG5HwFli
+OO8KHwQDoybpJH/KUvEY1DcDgGEN206EOZYfOdto/skhkmM7zeGt+eeUYKPyWC7
rC3FnS3ac+fENVIp3NaMdaAXIeBRYgOK/CcjGwIDAQABAoIBAAbZ7gg/uVn0/zjt
33zfKw3GXcIlIwCbAynIzqIOjT8pqTeYa5Cf4nIEzqDFsluf8TJmU+oOvDExLEKv
EKYcCthpHKTDidUVwR6HJzPHpFsJiiSFPMdAM7ETu5BImZ4GaWSAwUI9r1tDqrso
rtxcR4TWpuSQnGvLseCEMDRGgdQK0L0dEJHtj+XF5YdpNp5eWrqXyRIoEU2Wy/jg
iH5ODcsYiG6vE8BJSLzXPzlufMdiCkSqhCceb4XL1jH6DhP+VQxDc1HG78gC0OE0
XFpbBvNmYMEA/IRSBFMEJBI4Rc9EzyVT/J9fjrYASZuwq8tDdDCYAJedprNyA1hP
OO4dvOECgYEA8K1/KFb2Cy9OkpUQ4bFxw3FX6U/KmRDkogKbTXhnLwkpda37F87D
RoPDdY8+32/5M4sgjKtMsyt6w9FfAunaEu+scuNw/rzBIOwnhXIQfNQzJnmMz6/6
icY7z7ghfX0bOofpXr4s/VnnI93yswzdO8ESgIS98QOvI9h4BZQ3h6ECgYEAxmEg
mb7FDW7hal1Gt8ZZ/RaszKM6jRRCdn5tne+hZNzWzVJ37y7ek5hF3x7vDKe2Widr
5ZnSg57OyjY9YaScRXuMwRK/iFyec8YQG16fRqOeTbfG591t8LUiuvLDu4qzh9s2
L273roYN60beNPJOY4y5w/5BcaiCpv1xOyYLQTsCgYEAy5NVPT/hOjC3m1EvSFgZ
TCGxJI3zZmldmpPt3Sd8z9JGGV4iR08C6cBGMkgJ/GDwPuLtk07Jv7uFSeDtJr+7
T80e5sbvKulpynk2LLAAtjWfVmn16y6FEsh0iwzKdyS9RVL02MivsVS8KCByS3UU
JJj5F3AwYY6mNAHD86QdHEECgYEAqqoSftIU+mqCuJvIY//bmRUx0dc3Xvmn+ALq
UO4/3eLzVK53Cak7yKQ+sCYPp8Z85XB2rY85AQzVgDdLdT5FRq10uQFlD24Gzzj8
0F8GDaJjZR8OmpjvpR5f449IfoZjzyPyqLoBkP446UkNj2VJtPDzO774FEzRIdJ1
4FnpYtMCgYB2qe9NCq/wkCNgLfLpi8edl33DNrmDVPojvYnUAXhg/bZcv7mFf6TJ
C0RgzDgm5OInidRj+MfluuBLkMFbrKDQMzRCx87+j0UtCJHvHflP4zHiM2B7iOBC
1+atNuj7tfJOkEYYB661bhlZ01utR+XWsOeMszkTT4jA9fYCNGQGkA==
-----END RSA PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoGAvJx7UF9mqHGcBL+b
S5hhdOdK/dJbo3xnBgcM46bupD9/qL9Nj4ZsGOqxnNJqsJIjBmVc+06TeHVSexo0
5XcMDkSmKRuCV8E76YwA7EOKnP1tNELg0g416cskKr/fIjPCbpTugKrFw272RmiD
jFOM3Oj6JEW4dZzd3OEDuhtsuMqTxoaaAmK93rIzE6BFjM4SgdeG+q7I7mZ64yx5
3MjdUORtDqZEdQlkEI+qeG5HwFli+OO8KHwQDoybpJH/KUvEY1DcDgGEN206EOZY
fOdto/skhkmM7zeGt+eeUYKPyWC7rC3FnS3ac+fENVIp3NaMdaAXIeBRYgOK/Ccj
GwIDAQAB
-----END PUBLIC KEY-----";

    const REQUEST_BODY: &str = r#"{"data":{"email":"payer@example.com"}}"#;

    /// Computed outside Rust: `printf '%s' "1413802718|POST|https://www.saltedge.com/api/v6/customers|$REQUEST_BODY"
    /// | openssl dgst -sha256 -sign key.pem | base64`. PKCS#1 v1.5 signatures are
    /// deterministic, so the connector must produce exactly this.
    const REQUEST_SIGNATURE: &str = "LVK5ENQ+3a51P0ACiKUEudFBvAvYLj6mqZ/y/RxnW32dXld7W+KUDzk7P5YCFXQalL+aMvENeqm9oTsKtxHM+GxvrnZdHPNnnbvCZmPh17iYPGgGMqIGFCuCb8kitePJDjj9V6KXuFyHsC0H0BQJd3uubhnhzXikspBewDZg9dbglPjgCzCK/Qy80p+rRcxW9DlNmbXI7cAqzJZ1cIP6vvMvX34zKuhjo/j0rJyq75f5MZevzvKhQcQMxe7WW28aBAApIFBcrZkR9ZO3qRuGZQ8ZlmMIORGeudxL/gDe9RUG0M2NqW6kWkNQvJyCxXtsMA5OEAKfcuHXEZOVo20ogQ==";

    const CALLBACK_BODY: &[u8] = br#"{"data":{"payment_id":"111","customer_id":"222","status":"executed","custom_fields":{},"raw_provider_status":"ACTC"},"meta":{"version":"6","time":"2024-10-01T08:16:12.799Z"}}"#;

    /// The same, over `https://api.example.com/webhooks/merchant_1/mca_1|$CALLBACK_BODY`:
    /// the test key standing in for Salt Edge's.
    const CALLBACK_SIGNATURE: &str = "t392FEzQPRyy5rRbSp5UbuVhuQW5BamnOht2OlHQcpDzAAsXCUrFXnHwOcF2Z+2KJomS/MIjmPgTAZw9w3ttK/igMvtbP+hMFvJQ9CzC4oczkSlu3dALxUEPbMd0qElBpl5CTZ+7Llxl8M1aYI/7kkALBQlgAJl+3Cbw3uXTKjMNZdkX/XIBP0U3sVCkHfzWYHLuuS4/b51AA884W368UaRUnkR/GgsDLB5qALg78biL1JoSeUJFqxUMXDDnXYhmqRSfHyr9DphyNLFO/HBF8a19MwmB5JKcdXMLDhgbvaFbVvwpv56zBcnjgbQ/LHGtuenVDn0DV1klkkNwo/OboQ==";

    fn signed_request(private_key: &str) -> String {
        sign(
            &Secret::new(private_key.to_string()),
            &signing_string(
                "1413802718",
                Method::Post,
                "https://www.saltedge.com/api/v6/customers",
                REQUEST_BODY,
            ),
        )
        .unwrap()
    }

    #[test]
    fn a_request_is_signed_as_openssl_signs_it() {
        assert_eq!(signed_request(TEST_PRIVATE_KEY_PKCS8), REQUEST_SIGNATURE);
    }

    #[test]
    fn a_pkcs1_key_signs_the_same() {
        assert_eq!(signed_request(TEST_PRIVATE_KEY_PKCS1), REQUEST_SIGNATURE);
    }

    #[test]
    fn a_key_pasted_without_its_line_breaks_signs_the_same() {
        assert_eq!(
            signed_request(&TEST_PRIVATE_KEY_PKCS8.replace('\n', " ")),
            REQUEST_SIGNATURE
        );
    }

    #[test]
    fn a_key_that_is_not_one_is_a_configuration_error() {
        let error = sign(&Secret::new("not a key".to_string()), "message").unwrap_err();
        assert!(matches!(
            error.current_context(),
            errors::ConnectorError::InvalidConnectorConfig { .. }
        ));
    }

    #[test]
    fn a_get_is_signed_with_an_empty_body() {
        assert_eq!(
            signing_string(
                "1413802718",
                Method::Get,
                "https://www.saltedge.com/api/v6/payments/1",
                ""
            ),
            "1413802718|GET|https://www.saltedge.com/api/v6/payments/1|"
        );
    }

    fn callback_verifies(signature: &str, body: &[u8], host: &str) -> bool {
        let mut headers = actix_web::http::header::HeaderMap::new();
        for (name, value) in [
            ("signature", signature),
            ("host", host),
            ("x-forwarded-proto", "https"),
        ] {
            headers.insert(
                actix_web::http::header::HeaderName::from_static(name),
                actix_web::http::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        let request = IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: http::Uri::from_static("/webhooks/merchant_1/mca_1"),
            headers: &headers,
            body,
            query_params: String::new(),
        };
        let secrets = api_models::webhooks::ConnectorWebhookSecrets {
            secret: consts::BASE64_ENGINE.encode(TEST_PUBLIC_KEY).into_bytes(),
            additional_secret: None,
        };
        let merchant_id = common_utils::id_type::MerchantId::get_merchant_id_not_found();
        let connector = Saltedge::new();
        let signature = connector
            .get_webhook_source_verification_signature(&request, &secrets)
            .unwrap();
        let message = connector
            .get_webhook_source_verification_message(&request, &merchant_id, &secrets)
            .unwrap();
        crypto::RsaSha256
            .verify_signature(&secrets.secret, &signature, &message)
            .unwrap_or(false)
    }

    #[test]
    fn a_callback_signed_over_its_url_and_body_is_accepted() {
        assert!(callback_verifies(
            CALLBACK_SIGNATURE,
            CALLBACK_BODY,
            "api.example.com"
        ));
    }

    #[test]
    fn a_callback_whose_body_was_changed_is_refused() {
        let changed = String::from_utf8(CALLBACK_BODY.to_vec())
            .unwrap()
            .replace("executed", "settled");
        assert!(!callback_verifies(
            CALLBACK_SIGNATURE,
            changed.as_bytes(),
            "api.example.com"
        ));
    }

    #[test]
    fn a_callback_signed_for_another_url_is_refused() {
        assert!(!callback_verifies(
            CALLBACK_SIGNATURE,
            CALLBACK_BODY,
            "api.elsewhere.example.com"
        ));
    }
}
