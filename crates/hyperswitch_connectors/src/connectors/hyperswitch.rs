pub mod transformers;

use std::sync::LazyLock;

use common_enums::{enums, CallConnectorAction, PaymentAction};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
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
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsSyncRouterData, RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorRedirectResponse,
        ConnectorSpecifications, ConnectorValidation,
    },
    configs::Connectors,
    consts::NO_ERROR_MESSAGE,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{ExposeInterface, Mask};
use transformers as hyperswitch;

use crate::{constants::headers, types::ResponseRouterData, utils};

/// Another Hyperswitch deployment as the processor, through its v1 merchant API.
#[derive(Clone)]
pub struct Hyperswitch {
    amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl Hyperswitch {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }

    /// An endpoint of the deployment this account names. There is no default
    /// target: `connectors.hyperswitch.base_url` is a placeholder and never used.
    fn api_url(
        &self,
        connector_meta_data: &Option<common_utils::pii::SecretSerdeValue>,
        path: &str,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/{path}",
            hyperswitch::platform_base_url(connector_meta_data)?
        ))
    }

    /// The target's error, with the attempt left `attempt_status` when its code is
    /// `code` rather than failed, so a sync can read the real outcome.
    fn error_leaving_attempt(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
        code: &str,
        attempt_status: enums::AttemptStatus,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        if error.code == code {
            error.attempt_status = Some(attempt_status);
        }
        Ok(error)
    }
}

impl api::Payment for Hyperswitch {}
impl api::PaymentSession for Hyperswitch {}
impl api::ConnectorAccessToken for Hyperswitch {}
impl api::MandateSetup for Hyperswitch {}
impl api::PaymentAuthorize for Hyperswitch {}
impl api::PaymentSync for Hyperswitch {}
impl api::PaymentCapture for Hyperswitch {}
impl api::PaymentVoid for Hyperswitch {}
impl api::Refund for Hyperswitch {}
impl api::RefundExecute for Hyperswitch {}
impl api::RefundSync for Hyperswitch {}
impl api::PaymentToken for Hyperswitch {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Hyperswitch
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Hyperswitch
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

impl ConnectorCommon for Hyperswitch {
    fn id(&self) -> &'static str {
        "hyperswitch"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.hyperswitch.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = hyperswitch::HyperswitchAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::API_KEY.to_string(),
            auth.api_key.expose().into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: hyperswitch::HyperswitchErrorResponse =
            match res.response.parse_struct("HyperswitchErrorResponse") {
                Ok(response) => response,
                Err(_) => {
                    return utils::handle_json_response_deserialization_failure(res, "hyperswitch")
                }
            };

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let error = response.error;
        let message = error
            .message
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
        Ok(ErrorResponse {
            status_code: res.status_code,
            code: error.code.unwrap_or_else(|| res.status_code.to_string()),
            reason: error.reason.or_else(|| Some(message.clone())),
            message,
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

impl ConnectorValidation for Hyperswitch {
    /// A payment is looked up by our reference when the target's answer never
    /// came, so a sync needs no transaction id.
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Hyperswitch {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Hyperswitch {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Hyperswitch
{
}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Hyperswitch {
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
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.api_url(&req.connector_meta_data, "payments")
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
        let connector_router_data = hyperswitch::HyperswitchRouterData::from((amount, req));
        let connector_req =
            hyperswitch::HyperswitchPaymentsRequest::try_from(&connector_router_data)?;
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
        let response: hyperswitch::HyperswitchPaymentsResponse = res
            .response
            .parse_struct("Hyperswitch PaymentsAuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    /// The target already has a payment with this attempt's reference: an earlier
    /// call for it got there even though its answer did not come back. The
    /// payment stays pending, and a sync by the reference reads its outcome.
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.error_leaving_attempt(
            res,
            event_builder,
            hyperswitch::DUPLICATE_ERROR_CODE,
            enums::AttemptStatus::Pending,
        )
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Hyperswitch {
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

    /// By the target's id for the payment, which is our reference for the attempt;
    /// by that reference itself when the target's answer never came.
    /// `force_sync` makes the target ask its own processor.
    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let payment_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .unwrap_or_else(|_| req.connector_request_reference_id.clone());
        self.api_url(
            &req.connector_meta_data,
            &format!(
                "payments/{}?force_sync=true",
                urlencoding::encode(&payment_id)
            ),
        )
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
        let response: hyperswitch::HyperswitchPaymentsResponse = res
            .response
            .parse_struct("Hyperswitch PaymentsSyncResponse")
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

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Hyperswitch {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
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
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.api_url(
            &req.connector_meta_data,
            &format!(
                "payments/{}/capture",
                urlencoding::encode(&req.request.connector_transaction_id)
            ),
        )
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture,
            req.request.currency,
        )?;
        let connector_router_data = hyperswitch::HyperswitchRouterData::from((amount, req));
        let connector_req = hyperswitch::HyperswitchCaptureRequest::from(&connector_router_data);
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsCaptureType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCaptureType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCaptureRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCaptureRouterData, errors::ConnectorError> {
        let response: hyperswitch::HyperswitchPaymentsResponse = res
            .response
            .parse_struct("Hyperswitch PaymentsCaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    /// The payment was not in a state to capture: its status on the target is not
    /// what we have. Left pending rather than failed, so a sync corrects it.
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.error_leaving_attempt(
            res,
            event_builder,
            hyperswitch::UNEXPECTED_STATE_ERROR_CODE,
            enums::AttemptStatus::Pending,
        )
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Hyperswitch {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
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
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.api_url(
            &req.connector_meta_data,
            &format!(
                "payments/{}/cancel",
                urlencoding::encode(&req.request.connector_transaction_id)
            ),
        )
    }

    fn get_request_body(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = hyperswitch::HyperswitchCancelRequest::from(req);
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsVoidType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        let response: hyperswitch::HyperswitchPaymentsResponse = res
            .response
            .parse_struct("Hyperswitch PaymentsCancelResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    /// As for a capture: the target's state differs from ours, so a sync decides.
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.error_leaving_attempt(
            res,
            event_builder,
            hyperswitch::UNEXPECTED_STATE_ERROR_CODE,
            enums::AttemptStatus::Pending,
        )
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Hyperswitch {
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
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.api_url(&req.connector_meta_data, "refunds")
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
        let connector_router_data = hyperswitch::HyperswitchRouterData::from((refund_amount, req));
        let connector_req =
            hyperswitch::HyperswitchRefundRequest::try_from(&connector_router_data)?;
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
        let response: hyperswitch::HyperswitchRefundResponse = res
            .response
            .parse_struct("Hyperswitch RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    /// The target already has a refund with our refund id: an earlier call got
    /// there even though its answer did not come back, and the money may have
    /// moved. The router marks a refund failed on any error below 500 and leaves
    /// it as it is on a 500, so a duplicate is reported as one, and refund sync,
    /// which looks the refund up by the same id, reads its outcome. Marked failed,
    /// it would invite a second refund of the same money.
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        if error.code == hyperswitch::DUPLICATE_ERROR_CODE {
            error.status_code = 500;
        }
        Ok(error)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Hyperswitch {
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

    /// By our refund id, which the target was given as its own.
    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.api_url(
            &req.connector_meta_data,
            &format!(
                "refunds/{}?force_sync=true",
                urlencoding::encode(&req.request.refund_id)
            ),
        )
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
        let response: hyperswitch::HyperswitchRefundResponse = res
            .response
            .parse_struct("Hyperswitch RefundSyncResponse")
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

impl ConnectorRedirectResponse for Hyperswitch {
    fn get_flow_type(
        &self,
        _query_params: &str,
        _json_payload: Option<serde_json::Value>,
        action: PaymentAction,
    ) -> CustomResult<CallConnectorAction, errors::ConnectorError> {
        // When the payer comes back through the target, from 3DS, a card page,
        // Klarna or the bank, look the outcome up at once. The return's query
        // carries a status, but the lookup is what decides.
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
impl webhooks::IncomingWebhook for Hyperswitch {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::HmacSha512))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let signature =
            utils::get_header_key_value(hyperswitch::WEBHOOK_SIGNATURE_HEADER, request.headers)?;
        hex::decode(signature).change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    /// The target signs the body exactly as it sends it.
    fn get_webhook_source_verification_message(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(request.body.to_vec())
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let body: hyperswitch::HyperswitchWebhookBody = request
            .body
            .parse_struct("HyperswitchWebhookBody")
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        body.object_reference_id()
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let body: hyperswitch::HyperswitchWebhookBody = request
            .body
            .parse_struct("HyperswitchWebhookBody")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        Ok(body.event_type())
    }

    /// The payment or refund in the form a lookup returns it, which the payment
    /// sync or refund flow then reads.
    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let body: hyperswitch::HyperswitchWebhookBody = request
            .body
            .parse_struct("HyperswitchWebhookBody")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        body.resource_object()
    }
}

static HYPERSWITCH_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let supported_capture_methods = vec![
            enums::CaptureMethod::Automatic,
            enums::CaptureMethod::Manual,
        ];

        // The target's processors decide which networks they take.
        let supported_card_networks = vec![
            common_enums::CardNetwork::Visa,
            common_enums::CardNetwork::Mastercard,
            common_enums::CardNetwork::AmericanExpress,
            common_enums::CardNetwork::Discover,
            common_enums::CardNetwork::JCB,
            common_enums::CardNetwork::DinersClub,
            common_enums::CardNetwork::UnionPay,
        ];

        let card_details = PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: supported_capture_methods.clone(),
            specific_features: Some(
                api_models::feature_matrix::PaymentMethodSpecificFeatures::Card({
                    api_models::feature_matrix::CardSpecificFeatures {
                        three_ds: enums::FeatureStatus::Supported,
                        no_three_ds: enums::FeatureStatus::Supported,
                        supported_card_networks,
                    }
                }),
            ),
        };

        let mut hyperswitch_supported_payment_methods = SupportedPaymentMethods::new();
        hyperswitch_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Credit,
            card_details.clone(),
        );
        hyperswitch_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Debit,
            card_details,
        );
        // Confirmed on the target at once: its processor's own page takes the card.
        hyperswitch_supported_payment_methods.add(
            enums::PaymentMethod::CardRedirect,
            enums::PaymentMethodType::CardRedirect,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: None,
            },
        );
        // Confirmed on the target at once: the payer goes straight to Klarna.
        hyperswitch_supported_payment_methods.add(
            enums::PaymentMethod::PayLater,
            enums::PaymentMethodType::Klarna,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods,
                specific_features: None,
            },
        );
        // Likewise straight to the bank. A bank payment has no later capture.
        hyperswitch_supported_payment_methods.add(
            enums::PaymentMethod::BankRedirect,
            enums::PaymentMethodType::OpenBanking,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        hyperswitch_supported_payment_methods
    });

static HYPERSWITCH_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Hyperswitch",
    description: "Another Hyperswitch deployment as the processor: card payments with 3D Secure, card redirect, Klarna and open banking straight to the provider, manual capture and refunds",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Beta,
};

static HYPERSWITCH_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 2] =
    [enums::EventClass::Payments, enums::EventClass::Refunds];

impl ConnectorSpecifications for Hyperswitch {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&HYPERSWITCH_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*HYPERSWITCH_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&HYPERSWITCH_SUPPORTED_WEBHOOK_FLOWS)
    }

    /// Always the attempt's own id, never the payment's: the target refuses a
    /// payment id it has seen, and each attempt is a payment there.
    #[cfg(feature = "v1")]
    fn generate_connector_request_reference_id(
        &self,
        _payment_intent: &hyperswitch_domain_models::payments::PaymentIntent,
        payment_attempt: &hyperswitch_domain_models::payments::payment_attempt::PaymentAttempt,
        _is_config_enabled_to_send_payment_id_as_connector_request_id: bool,
    ) -> String {
        hyperswitch::reference_for_attempt(&payment_attempt.attempt_id)
    }
}
