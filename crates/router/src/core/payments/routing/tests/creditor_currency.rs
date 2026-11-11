use api_models::enums::Currency;
use hyperswitch_masking::Secret;
use serde_json::json;

use super::super::account_creditor_currency;

fn saltedge(metadata: serde_json::Value) -> Option<Currency> {
    account_creditor_currency("saltedge", &Some(Secret::new(metadata)))
}

#[test]
fn a_salt_edge_account_with_an_iban_takes_eur() {
    let currency = saltedge(json!({
        "creditor_name": "Brand Ltd",
        "creditor_iban": "DE89370400440532013000",
    }));
    assert_eq!(currency, Some(Currency::EUR));
}

#[test]
fn a_salt_edge_account_with_a_sort_code_takes_gbp() {
    let currency = saltedge(json!({
        "creditor_name": "Brand Ltd",
        "creditor_sort_code": "12-34-56",
        "creditor_account_number": "12345678",
    }));
    assert_eq!(currency, Some(Currency::GBP));
}

#[test]
fn a_salt_edge_account_naming_both_is_left_to_its_currencies() {
    let currency = saltedge(json!({
        "creditor_name": "Brand Ltd",
        "creditor_iban": "DE89370400440532013000",
        "creditor_sort_code": "12-34-56",
        "creditor_account_number": "12345678",
    }));
    assert_eq!(currency, None);
}

#[test]
fn a_salt_edge_account_without_metadata_is_left_to_its_currencies() {
    assert_eq!(account_creditor_currency("saltedge", &None), None);
}

#[test]
fn another_connector_is_left_to_its_currencies() {
    let metadata = json!({"creditor_iban": "DE89370400440532013000"});
    assert_eq!(
        account_creditor_currency("stripe", &Some(Secret::new(metadata))),
        None
    );
}
