//! Feature tests against the Pinnacle sandbox (payment-api).
//!
//! They call the real sandbox, so they need a token:
//! `CONNECTOR_AUTH_FILE_PATH` must point at a TOML file with
//! `[pinnacle]` / `api_key = "<sandbox token with the payment:s2s ability>"`.
//!
//! Sandbox cards: 5500000000000004 approves, 4242424242424242 declines, and
//! 4012888888881881 goes through 3DS. Completing 3DS needs a browser (the OTP
//! decides the outcome), so it is tested from the dashboard, not here.

use std::str::FromStr;

use common_utils::{pii::Email, types::MinorUnit};
use hyperswitch_domain_models::{
    address::{Address, AddressDetails, PhoneDetails},
    payment_method_data::{Card, PaymentMethodData},
};
use hyperswitch_masking::Secret;
use router::types::{self, api, storage::enums, PaymentAddress};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions, PaymentInfo};

#[derive(Clone, Copy)]
struct PinnacleTest;
impl ConnectorActions for PinnacleTest {}
impl utils::Connector for PinnacleTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Pinnacle;
        utils::construct_connector_data_old(
            Box::new(Pinnacle::new()),
            types::Connector::Pinnacle,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .pinnacle
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "pinnacle".to_string()
    }
}

static CONNECTOR: PinnacleTest = PinnacleTest {};

const APPROVED_CARD: &str = "5500000000000004";
const DECLINED_CARD: &str = "4242424242424242";
const THREE_DS_CARD: &str = "4012888888881881";

fn payment_info_with_first_name(first_name: &str) -> Option<PaymentInfo> {
    Some(PaymentInfo {
        address: Some(PaymentAddress::new(
            None,
            Some(Address {
                address: Some(AddressDetails {
                    first_name: Some(Secret::new(first_name.to_string())),
                    last_name: Some(Secret::new("Doe".to_string())),
                    line1: Some(Secret::new("10 Downing Street".to_string())),
                    city: Some("London".to_string()),
                    zip: Some(Secret::new("SW1A 2AA".to_string())),
                    country: Some(enums::CountryAlpha2::GB),
                    ..Default::default()
                }),
                phone: Some(PhoneDetails {
                    number: Some(Secret::new("7700900123".to_string())),
                    country_code: Some("+44".to_string()),
                }),
                email: None,
            }),
            None,
            None,
        )),
        ..Default::default()
    })
}

fn get_default_payment_info() -> Option<PaymentInfo> {
    payment_info_with_first_name("John")
}

/// payment-api refuses a second payment with the same card number and amount
/// within 10 seconds, and these tests run in parallel: each one pays its own amount.
fn payment_data(card_number: &str, minor_amount: i64) -> Option<types::PaymentsAuthorizeData> {
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
        email: Some(Email::from_str("customer@example.com").unwrap()),
        router_return_url: Some("https://hyperswitch.test/return".to_string()),
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

fn sync_data(connector_transaction_id: String) -> Option<types::PaymentsSyncData> {
    Some(types::PaymentsSyncData {
        connector_transaction_id: types::ResponseId::ConnectorTransactionId(
            connector_transaction_id,
        ),
        capture_method: Some(enums::CaptureMethod::Automatic),
        ..Default::default()
    })
}

async fn make_approved_payment(minor_amount: i64) -> types::PaymentsAuthorizeRouterData {
    let response = CONNECTOR
        .make_payment(
            payment_data(APPROVED_CARD, minor_amount),
            get_default_payment_info(),
        )
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
    response
}

#[actix_web::test]
async fn should_make_payment() {
    let payment = make_approved_payment(101).await;
    assert!(
        utils::get_connector_transaction_id(payment.response).is_some(),
        "no payment-api uuid"
    );
}

// Payment sync goes by the reference the payment was created with, as the router does.
#[actix_web::test]
async fn should_sync_auto_captured_payment() {
    let payment = make_approved_payment(102).await;
    let reference = payment.connector_request_reference_id.clone();
    let txn_id = utils::get_connector_transaction_id(payment.response).expect("payment-api uuid");
    let response = CONNECTOR
        .sync_payment_with_reference(reference, sync_data(txn_id), get_default_payment_info())
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

#[actix_web::test]
async fn should_decline_payment() {
    let response = CONNECTOR
        .make_payment(payment_data(DECLINED_CARD, 103), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::Failure);
    let error = response.response.unwrap_err();
    // A decline is a transaction outcome that payment-api answers with 200.
    assert_eq!(error.status_code, 200);
    assert!(error.connector_transaction_id.is_some());
}

#[actix_web::test]
async fn should_redirect_to_3ds() {
    let response = CONNECTOR
        .make_payment(payment_data(THREE_DS_CARD, 104), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    match response.response.expect("3DS response") {
        types::PaymentsResponseData::TransactionResponse {
            redirection_data, ..
        } => assert!(redirection_data.is_some(), "3DS payment without a redirect"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[actix_web::test]
async fn should_keep_unfinished_3ds_payment_open_on_sync() {
    let payment = CONNECTOR
        .make_payment(payment_data(THREE_DS_CARD, 105), get_default_payment_info())
        .await
        .expect("Payment response");
    let reference = payment.connector_request_reference_id.clone();
    let txn_id = utils::get_connector_transaction_id(payment.response).expect("payment-api uuid");
    let response = CONNECTOR
        .sync_payment_with_reference(reference, sync_data(txn_id), get_default_payment_info())
        .await
        .expect("PSync response");
    assert!(
        matches!(
            response.status,
            enums::AttemptStatus::Pending | enums::AttemptStatus::AuthenticationPending
        ),
        "an unfinished 3DS payment became {:?}",
        response.status
    );
}

#[actix_web::test]
async fn should_refund_auto_captured_payment() {
    let response = CONNECTOR
        .make_payment_and_refund(
            payment_data(APPROVED_CARD, 106),
            refund_data(106, 106),
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
            payment_data(APPROVED_CARD, 107),
            refund_data(107, 50),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

// Refund sync goes by the reference the refund was sent with: the same refund_id.
#[actix_web::test]
async fn should_sync_refund() {
    let refund_request = refund_data(108, 108);
    let refund = CONNECTOR
        .make_payment_and_refund(
            payment_data(APPROVED_CARD, 108),
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

// payment-api gives a refund its payment's uuid, which is what a lookup by uuid could
// get wrong: after a refund, the payment must still sync as charged.
#[actix_web::test]
async fn should_sync_payment_after_it_is_refunded() {
    let payment = make_approved_payment(112).await;
    let reference = payment.connector_request_reference_id.clone();
    let txn_id = utils::get_connector_transaction_id(payment.response).expect("payment-api uuid");
    let refund = CONNECTOR
        .refund_payment(
            txn_id.clone(),
            refund_data(112, 50),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert_eq!(
        refund.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
    let response = CONNECTOR
        .sync_payment_with_reference(reference, sync_data(txn_id), get_default_payment_info())
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

#[actix_web::test]
async fn should_fail_refund_above_payment_amount() {
    let response = CONNECTOR
        .make_payment_and_refund(
            payment_data(APPROVED_CARD, 109),
            refund_data(109, 200),
            get_default_payment_info(),
        )
        .await
        .expect("Refund response");
    assert!(
        response.response.is_err(),
        "payment-api accepted a refund larger than the payment"
    );
}

// payment-api accepts only letters and spaces in names for now; it is to be relaxed
// there. Until then its 422 has to reach the merchant with the offending field named.
#[actix_web::test]
async fn should_pass_on_validation_error_for_hyphenated_name() {
    let response = CONNECTOR
        .make_payment(
            payment_data(APPROVED_CARD, 110),
            payment_info_with_first_name("Jean-Luc"),
        )
        .await
        .expect("Payment response");
    let error = response.response.unwrap_err();
    assert_eq!(error.code, "422");
    assert!(error
        .reason
        .unwrap_or_default()
        .contains("billingFirstName"));
}

#[actix_web::test]
async fn should_reject_duplicate_payment_within_ten_seconds() {
    make_approved_payment(111).await;
    let response = CONNECTOR
        .make_payment(payment_data(APPROVED_CARD, 111), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.response.unwrap_err().code, "409");
}

// The test helpers make up a new reference for every call, so nothing carries this one.
#[actix_web::test]
async fn should_fail_sync_for_unknown_reference() {
    let response = CONNECTOR
        .sync_payment(
            sync_data(uuid::Uuid::new_v4().to_string()),
            get_default_payment_info(),
        )
        .await;
    assert!(
        response.map_or(true, |router_data| router_data.response.is_err()),
        "a status lookup for an unknown reference succeeded"
    );
}
