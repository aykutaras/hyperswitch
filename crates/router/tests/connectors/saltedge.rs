//! Feature tests against Salt Edge (`www.saltedge.com/api/v6`), which has no
//! separate sandbox host: a Salt Edge application in Test status reaches only
//! fake and sandbox banks.
//!
//! They call the real API, so they need such an application's keys, one per
//! currency because a Salt Edge profile takes one: `CONNECTOR_AUTH_FILE_PATH`
//! must point at a TOML file with `[saltedge]` for EUR and `[saltedge_gbp]` for
//! GBP, each with `api_key = "<App-id>"`, `key1 = "<Secret>"` and `api_secret =
//! "<private key PEM>"`, whose public key is uploaded to that application.
//!
//! The payer finishes every payment in Salt Edge's widget, which needs a
//! browser, so these tests stop at the redirect. Completing a payment, and the
//! callbacks it sends, is tested from the dashboard with a fake bank.

use std::str::FromStr;

use common_utils::{pii::Email, types::MinorUnit};
use hyperswitch_domain_models::payment_method_data::{BankRedirectData, PaymentMethodData};
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions, PaymentInfo};

#[derive(Clone, Copy)]
struct SaltedgeTest {
    currency: enums::Currency,
}
impl ConnectorActions for SaltedgeTest {}
impl utils::Connector for SaltedgeTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Saltedge;
        utils::construct_connector_data_old(
            Box::new(Saltedge::new()),
            types::Connector::Saltedge,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        let auth = connector_auth::ConnectorAuthentication::new();
        let keys = match self.currency {
            enums::Currency::GBP => auth.saltedge_gbp,
            _ => auth.saltedge,
        };
        utils::to_connector_auth_type(
            keys.expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "saltedge".to_string()
    }
}

static EUR_CONNECTOR: SaltedgeTest = SaltedgeTest {
    currency: enums::Currency::EUR,
};
static GBP_CONNECTOR: SaltedgeTest = SaltedgeTest {
    currency: enums::Currency::GBP,
};

/// A fresh email each run, so each run creates a Salt Edge customer: an email
/// Salt Edge already knows would get its existing customer instead.
fn new_payer_email() -> Email {
    Email::from_str(&format!(
        "saltedge-test-{}@example.com",
        uuid::Uuid::new_v4()
    ))
    .unwrap()
}

fn payment_info(
    currency: enums::Currency,
    connector_customer: Option<String>,
) -> Option<PaymentInfo> {
    let connector_meta_data = match currency {
        enums::Currency::GBP => serde_json::json!({
            "creditor_name": "Pinnacle Test",
            "creditor_sort_code": "040004",
            "creditor_account_number": "12345678",
            "test_banks": "show",
        }),
        _ => serde_json::json!({
            "creditor_name": "Pinnacle Test",
            "creditor_iban": "DE89370400440532013000",
            "test_banks": "show",
        }),
    };
    Some(PaymentInfo {
        connector_customer,
        connector_meta_data: Some(connector_meta_data),
        ..Default::default()
    })
}

fn open_banking(currency: enums::Currency) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::BankRedirect(BankRedirectData::OpenBanking {
            iban: None,
            account_number: None,
            sort_code: None,
            account_holder_name: None,
            additional_details: None,
            bank_name: None,
        }),
        amount: 1112,
        minor_amount: MinorUnit::new(1112),
        currency,
        router_return_url: Some("https://hyperswitch.test/return".to_string()),
        ..utils::PaymentAuthorizeType::default().0
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

async fn new_customer(connector: &SaltedgeTest) -> String {
    let response = connector
        .create_connector_customer(
            Some(types::ConnectorCustomerData {
                email: Some(new_payer_email()),
                ..utils::CustomerType::default().0
            }),
            payment_info(connector.currency, None),
        )
        .await
        .expect("Customer response");
    response.connector_customer.expect("Salt Edge customer id")
}

async fn assert_sent_to_the_widget(connector: &SaltedgeTest) -> String {
    let customer_id = new_customer(connector).await;
    let response = connector
        .make_payment(
            open_banking(connector.currency),
            payment_info(connector.currency, Some(customer_id)),
        )
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    match response.response.expect("payment response") {
        types::PaymentsResponseData::TransactionResponse {
            resource_id,
            redirection_data,
            ..
        } => {
            assert!(redirection_data.is_some(), "no redirect to the widget");
            resource_id
                .get_connector_transaction_id()
                .expect("Salt Edge payment id")
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[actix_web::test]
async fn should_send_a_eur_payer_to_salt_edges_widget() {
    assert_sent_to_the_widget(&EUR_CONNECTOR).await;
}

#[actix_web::test]
async fn should_send_a_gbp_payer_to_salt_edges_widget() {
    assert_sent_to_the_widget(&GBP_CONNECTOR).await;
}

#[actix_web::test]
async fn should_keep_a_payment_at_the_widget_waiting_on_sync() {
    let payment_id = assert_sent_to_the_widget(&EUR_CONNECTOR).await;
    let response = EUR_CONNECTOR
        .sync_payment(
            sync_data(payment_id),
            payment_info(enums::Currency::EUR, None),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
}

#[actix_web::test]
async fn should_refuse_gbp_on_a_eur_account_without_calling_salt_edge() {
    let error = EUR_CONNECTOR
        .make_payment(
            open_banking(enums::Currency::GBP),
            payment_info(enums::Currency::EUR, Some("1".to_string())),
        )
        .await
        .expect_err("a EUR account has no GBP creditor");
    assert!(matches!(
        error.current_context(),
        router::core::errors::ConnectorError::InvalidConnectorConfig { .. }
    ));
}

#[actix_web::test]
async fn should_refuse_a_currency_without_a_scheme_without_calling_salt_edge() {
    let error = EUR_CONNECTOR
        .make_payment(
            open_banking(enums::Currency::PLN),
            payment_info(enums::Currency::EUR, Some("1".to_string())),
        )
        .await
        .expect_err("PLN has no Salt Edge scheme here");
    assert!(matches!(
        error.current_context(),
        router::core::errors::ConnectorError::NotSupported { .. }
    ));
}
