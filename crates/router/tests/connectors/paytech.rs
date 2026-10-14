//! Feature tests against the PayTech sandbox (`engine-sandbox.pay.tech`).
//!
//! They call the real sandbox, so they need a shop's API key:
//! `CONNECTOR_AUTH_FILE_PATH` must point at a TOML file with
//! `[paytech]` / `api_key = "<sandbox Shop API Key>"`, and the shop must have
//! iDEAL enabled. Which methods a shop has is PayTech's configuration.
//!
//! Every method this connector sends finishes on PayTech's checkout page, which
//! needs a browser, so these tests stop at the redirect. Completing a payment,
//! and the webhook it sends, is tested from the dashboard.

use std::str::FromStr;

use common_utils::{pii::Email, types::MinorUnit};
use hyperswitch_domain_models::{
    address::{Address, AddressDetails, PhoneDetails},
    payment_method_data::{BankRedirectData, Card, PaymentMethodData},
};
use hyperswitch_masking::Secret;
use router::types::{self, api, storage::enums, PaymentAddress};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions, PaymentInfo};

#[derive(Clone, Copy)]
struct PaytechTest;
impl ConnectorActions for PaytechTest {}
impl utils::Connector for PaytechTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Paytech;
        utils::construct_connector_data_old(
            Box::new(Paytech::new()),
            types::Connector::Paytech,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .paytech
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "paytech".to_string()
    }
}

static CONNECTOR: PaytechTest = PaytechTest {};

fn get_default_payment_info() -> Option<PaymentInfo> {
    Some(PaymentInfo {
        address: Some(PaymentAddress::new(
            None,
            Some(Address {
                address: Some(AddressDetails {
                    first_name: Some(Secret::new("John".to_string())),
                    last_name: Some(Secret::new("Doe".to_string())),
                    line1: Some(Secret::new("Damrak 1".to_string())),
                    city: Some("Amsterdam".to_string()),
                    zip: Some(Secret::new("1012 LG".to_string())),
                    country: Some(enums::CountryAlpha2::NL),
                    ..Default::default()
                }),
                phone: Some(PhoneDetails {
                    number: Some(Secret::new("201234567".to_string())),
                    country_code: Some("+31".to_string()),
                }),
                email: None,
            }),
            None,
            None,
        )),
        ..Default::default()
    })
}

fn payment_data(payment_method_data: PaymentMethodData) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data,
        amount: 1112,
        minor_amount: MinorUnit::new(1112),
        currency: enums::Currency::EUR,
        email: Some(Email::from_str("customer@example.com").unwrap()),
        router_return_url: Some("https://hyperswitch.test/return".to_string()),
        ..utils::PaymentAuthorizeType::default().0
    })
}

fn ideal() -> PaymentMethodData {
    PaymentMethodData::BankRedirect(BankRedirectData::Ideal { bank_name: None })
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

#[actix_web::test]
async fn should_send_the_customer_to_paytechs_checkout_page() {
    let response = CONNECTOR
        .make_payment(payment_data(ideal()), get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    match response.response.expect("payment response") {
        types::PaymentsResponseData::TransactionResponse {
            redirection_data, ..
        } => assert!(
            redirection_data.is_some(),
            "no redirect to the checkout page"
        ),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[actix_web::test]
async fn should_keep_a_payment_at_the_checkout_page_open_on_sync() {
    let payment = CONNECTOR
        .make_payment(payment_data(ideal()), get_default_payment_info())
        .await
        .expect("Payment response");
    let payment_id =
        utils::get_connector_transaction_id(payment.response).expect("PayTech payment id");
    let response = CONNECTOR
        .sync_payment(sync_data(payment_id), get_default_payment_info())
        .await
        .expect("PSync response");
    // The lookup carries no redirectUrl; without the attempt's earlier status it
    // reads as still pending rather than finished either way.
    assert!(matches!(
        response.status,
        enums::AttemptStatus::Pending | enums::AttemptStatus::AuthenticationPending
    ));
}

#[actix_web::test]
async fn should_refuse_a_card_without_calling_paytech() {
    let card = PaymentMethodData::Card(Card {
        card_number: cards::CardNumber::from_str("4000000000000002").unwrap(),
        ..utils::CCardType::default().0
    });
    let error = CONNECTOR
        .make_payment(payment_data(card), get_default_payment_info())
        .await
        .expect_err("cards go through the pinnacle connector");
    assert!(matches!(
        error.current_context(),
        router::core::errors::ConnectorError::NotImplemented(_)
    ));
}
