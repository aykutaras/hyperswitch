//! Feature tests against another Hyperswitch deployment, the target.
//!
//! They call the real target, so they need:
//! - `CONNECTOR_AUTH_FILE_PATH`: a TOML file with `[hyperswitch]` /
//!   `api_key = "<the secret API key of the target merchant>"`;
//! - `HYPERSWITCH_PLATFORM_URL`: the target's API URL, e.g.
//!   `https://api.platform.example`;
//! - `HYPERSWITCH_PROFILE_ID` (optional): the target profile, when its merchant
//!   has more than one.
//!
//! The target merchant routes cards to the target's dummy connector, whose
//! cards are used here: 4111111111111111 approves, 4000000000000002 declines
//! and 4000003800000446 asks for 3DS. Klarna must be enabled on that dummy
//! connector too, and card redirect on a processor with its own card page
//! (Pinnacle or PayTech there): the dummy connector has none. Completing 3DS,
//! paying on the card page or on Klarna's needs a browser, so those are tested
//! end to end, not here, as is open banking, which needs a real bank behind the
//! target's processor.
//! The dummy connector has no manual capture or void: those tests are ignored
//! until the target routes to a processor that has them.

use std::str::FromStr;

use common_utils::{pii::Email, types::MinorUnit};
use hyperswitch_domain_models::payment_method_data::{
    Card, CardRedirectData, PayLaterData, PaymentMethodData,
};
use hyperswitch_masking::Secret;
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions, PaymentInfo};

#[derive(Clone, Copy)]
struct HyperswitchTest;
impl ConnectorActions for HyperswitchTest {}
impl utils::Connector for HyperswitchTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Hyperswitch;
        utils::construct_connector_data_old(
            Box::new(Hyperswitch::new()),
            types::Connector::Hyperswitch,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .hyperswitch
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "hyperswitch".to_string()
    }
}

static CONNECTOR: HyperswitchTest = HyperswitchTest {};

const APPROVED_CARD: &str = "4111111111111111";
const DECLINED_CARD: &str = "4000000000000002";
const THREE_DS_CARD: &str = "4000003800000446";
const RETURN_URL: &str = "https://brand.example/return";

/// The account's metadata: the target to call, and its profile when one is given.
fn payment_info(auth_type: enums::AuthenticationType) -> Option<PaymentInfo> {
    let platform_url = std::env::var("HYPERSWITCH_PLATFORM_URL")
        .expect("HYPERSWITCH_PLATFORM_URL: the target's API URL");
    let mut metadata = serde_json::json!({ "platform_url": platform_url });
    if let Ok(profile_id) = std::env::var("HYPERSWITCH_PROFILE_ID") {
        metadata["profile_id"] = serde_json::Value::String(profile_id);
    }
    Some(PaymentInfo {
        auth_type: Some(auth_type),
        connector_meta_data: Some(metadata),
        ..Default::default()
    })
}

fn get_default_payment_info() -> Option<PaymentInfo> {
    payment_info(enums::AuthenticationType::NoThreeDs)
}

fn payment_data(
    card_number: &str,
    minor_amount: i64,
    capture_method: enums::CaptureMethod,
) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::Card(Card {
            card_number: cards::CardNumber::from_str(card_number).unwrap(),
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2030".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..utils::CCardType::default().0
        }),
        amount: minor_amount,
        minor_amount: MinorUnit::new(minor_amount),
        capture_method: Some(capture_method),
        email: Some(Email::from_str("customer@brand.example").unwrap()),
        router_return_url: Some(RETURN_URL.to_string()),
        ..utils::PaymentAuthorizeType::default().0
    })
}

fn card_payment(card_number: &str, minor_amount: i64) -> Option<types::PaymentsAuthorizeData> {
    payment_data(card_number, minor_amount, enums::CaptureMethod::Automatic)
}

/// Card redirect: no card here; the page of the target's processor takes it.
fn card_redirect_data(minor_amount: i64) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::CardRedirect(CardRedirectData::CardRedirect {}),
        amount: minor_amount,
        minor_amount: MinorUnit::new(minor_amount),
        email: Some(Email::from_str("customer@brand.example").unwrap()),
        router_return_url: Some(RETURN_URL.to_string()),
        ..utils::PaymentAuthorizeType::default().0
    })
}

/// Klarna: confirmed on the target at once, which sends the payer to Klarna.
fn klarna_data(minor_amount: i64) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::PayLater(PayLaterData::KlarnaRedirect {}),
        payment_method_type: Some(enums::PaymentMethodType::Klarna),
        amount: minor_amount,
        minor_amount: MinorUnit::new(minor_amount),
        email: Some(Email::from_str("customer@brand.example").unwrap()),
        router_return_url: Some(RETURN_URL.to_string()),
        ..utils::PaymentAuthorizeType::default().0
    })
}

fn refund_data(payment_minor_amount: i64, refund_minor_amount: i64) -> Option<types::RefundsData> {
    Some(types::RefundsData {
        payment_amount: payment_minor_amount,
        minor_payment_amount: MinorUnit::new(payment_minor_amount),
        refund_amount: refund_minor_amount,
        minor_refund_amount: MinorUnit::new(refund_minor_amount),
        ..utils::PaymentRefundType::default().0
    })
}

fn sync_data(connector_transaction_id: types::ResponseId) -> Option<types::PaymentsSyncData> {
    Some(types::PaymentsSyncData {
        connector_transaction_id,
        capture_method: Some(enums::CaptureMethod::Automatic),
        ..Default::default()
    })
}

fn redirection_of(response: &types::PaymentsAuthorizeRouterData) -> bool {
    match &response.response {
        Ok(types::PaymentsResponseData::TransactionResponse {
            redirection_data, ..
        }) => redirection_data.is_some(),
        other => panic!("unexpected response: {other:?}"),
    }
}

async fn make_approved_payment(minor_amount: i64) -> types::PaymentsAuthorizeRouterData {
    let response = CONNECTOR
        .make_payment(
            card_payment(APPROVED_CARD, minor_amount),
            get_default_payment_info(),
        )
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
    response
}

// The target's payment id is the attempt's reference, so a lost answer can be looked up.
#[actix_web::test]
async fn should_make_payment_under_the_attempts_reference() {
    let payment = make_approved_payment(1001).await;
    let reference = payment.connector_request_reference_id.clone();
    assert_eq!(
        utils::get_connector_transaction_id(payment.response),
        Some(reference)
    );
}

#[actix_web::test]
async fn should_sync_auto_captured_payment() {
    let payment = make_approved_payment(1002).await;
    let reference = payment.connector_request_reference_id.clone();
    let txn_id = utils::get_connector_transaction_id(payment.response).expect("payment id");
    let response = CONNECTOR
        .sync_payment_with_reference(
            reference,
            sync_data(types::ResponseId::ConnectorTransactionId(txn_id)),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

// An authorization whose answer never came: the sync finds it by the reference alone.
#[actix_web::test]
async fn should_sync_payment_by_its_reference_without_a_transaction_id() {
    let payment = make_approved_payment(1003).await;
    let response = CONNECTOR
        .sync_payment_with_reference(
            payment.connector_request_reference_id.clone(),
            sync_data(types::ResponseId::NoResponseId),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

#[actix_web::test]
async fn should_decline_payment() {
    let response = CONNECTOR
        .make_payment(
            card_payment(DECLINED_CARD, 1004),
            get_default_payment_info(),
        )
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::Failure);
    let error = response.response.unwrap_err();
    assert!(error.connector_transaction_id.is_some());
    assert_ne!(error.code, router::consts::NO_ERROR_CODE);
}

#[actix_web::test]
async fn should_redirect_to_3ds() {
    let response = CONNECTOR
        .make_payment(
            card_payment(THREE_DS_CARD, 1005),
            payment_info(enums::AuthenticationType::ThreeDs),
        )
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    assert!(redirection_of(&response), "3DS payment without a redirect");
}

#[actix_web::test]
async fn should_send_the_payer_straight_to_the_card_page() {
    let response = CONNECTOR
        .make_payment(card_redirect_data(1006), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    assert!(redirection_of(&response), "no redirect to the card page");
}

#[actix_web::test]
async fn should_send_the_payer_straight_to_klarna() {
    let response = CONNECTOR
        .make_payment(klarna_data(1015), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    assert!(redirection_of(&response), "no redirect to Klarna");
}

#[actix_web::test]
async fn should_keep_an_unpaid_card_redirect_pending_on_sync() {
    let payment = CONNECTOR
        .make_payment(card_redirect_data(1007), get_default_payment_info())
        .await
        .expect("Payment response");
    let reference = payment.connector_request_reference_id.clone();
    let txn_id = utils::get_connector_transaction_id(payment.response).expect("payment id");
    let response = CONNECTOR
        .sync_payment_with_reference(
            reference,
            sync_data(types::ResponseId::ConnectorTransactionId(txn_id)),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
}

#[actix_web::test]
async fn should_fail_sync_for_unknown_payment() {
    let response = CONNECTOR
        .sync_payment_with_reference(
            "pay_unknown_1".to_string(),
            sync_data(types::ResponseId::NoResponseId),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert!(response.response.is_err(), "an unknown payment was found");
}

#[actix_web::test]
async fn should_refund_auto_captured_payment() {
    let response = CONNECTOR
        .make_payment_and_refund(
            card_payment(APPROVED_CARD, 1008),
            refund_data(1008, 1008),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

#[actix_web::test]
async fn should_partially_refund_succeeded_payment() {
    let response = CONNECTOR
        .make_payment_and_refund(
            card_payment(APPROVED_CARD, 1009),
            refund_data(1009, 500),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

// Refund sync goes by our refund id, which the target was given as its own.
#[actix_web::test]
async fn should_sync_refund() {
    let refund_request = refund_data(1010, 1010);
    let refund = CONNECTOR
        .make_payment_and_refund(
            card_payment(APPROVED_CARD, 1010),
            refund_request.clone(),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    let connector_refund_id = refund.response.unwrap().connector_refund_id;
    let response = CONNECTOR
        .sync_refund(
            connector_refund_id.clone(),
            refund_request.map(|data| types::RefundsData {
                connector_refund_id: Some(connector_refund_id),
                ..data
            }),
            get_default_payment_info(),
        )
        .await
        .expect("RSync response");
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

#[actix_web::test]
async fn should_fail_refund_above_payment_amount() {
    let response = CONNECTOR
        .make_payment_and_refund(
            card_payment(APPROVED_CARD, 1011),
            refund_data(1011, 2000),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert!(
        response.response.is_err(),
        "the target accepted a refund larger than the payment"
    );
}

#[actix_web::test]
#[ignore = "the target's dummy connector has no manual capture"]
async fn should_capture_authorized_payment() {
    let response = CONNECTOR
        .authorize_and_capture_payment(
            payment_data(APPROVED_CARD, 1012, enums::CaptureMethod::Manual),
            None,
            get_default_payment_info(),
        )
        .await
        .expect("Capture response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

#[actix_web::test]
#[ignore = "the target's dummy connector has no manual capture"]
async fn should_partially_capture_authorized_payment() {
    let response = CONNECTOR
        .authorize_and_capture_payment(
            payment_data(APPROVED_CARD, 1013, enums::CaptureMethod::Manual),
            Some(types::PaymentsCaptureData {
                amount_to_capture: 500,
                minor_amount_to_capture: MinorUnit::new(500),
                ..utils::PaymentCaptureType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture response");
    assert_eq!(response.status, enums::AttemptStatus::PartialCharged);
}

#[actix_web::test]
#[ignore = "the target's dummy connector has no void"]
async fn should_void_authorized_payment() {
    let response = CONNECTOR
        .authorize_and_void_payment(
            payment_data(APPROVED_CARD, 1014, enums::CaptureMethod::Manual),
            Some(types::PaymentsCancelData {
                cancellation_reason: Some("requested_by_customer".to_string()),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Void response");
    assert_eq!(response.status, enums::AttemptStatus::Voided);
}
