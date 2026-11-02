use api_models::{
    admin::PaymentMethodsEnabled,
    enums::{Currency, PaymentMethodType},
};
use serde_json::json;

use super::super::account_accepts_currency;

/// Stored accounts hold this JSON, so the tests start from it.
fn enabled(payment_method_types: serde_json::Value) -> Vec<PaymentMethodsEnabled> {
    serde_json::from_value(json!([{
        "payment_method": "bank_redirect",
        "payment_method_types": payment_method_types,
    }]))
    .expect("payment methods enabled")
}

fn open_banking(accepted_currencies: serde_json::Value) -> Vec<PaymentMethodsEnabled> {
    enabled(json!([{
        "payment_method_type": "open_banking",
        "accepted_currencies": accepted_currencies,
    }]))
}

fn accepts(account: &[PaymentMethodsEnabled], currency: Currency) -> bool {
    account_accepts_currency(account, PaymentMethodType::OpenBanking, currency)
}

#[test]
fn an_account_takes_only_the_currencies_it_enables() {
    let account = open_banking(json!({"type": "enable_only", "list": ["GBP"]}));
    assert!(accepts(&account, Currency::GBP));
    assert!(!accepts(&account, Currency::EUR));
}

#[test]
fn an_account_refuses_the_currencies_it_disables() {
    let account = open_banking(json!({"type": "disable_only", "list": ["GBP"]}));
    assert!(!accepts(&account, Currency::GBP));
    assert!(accepts(&account, Currency::EUR));
}

#[test]
fn an_account_without_a_restriction_takes_any_currency() {
    assert!(accepts(&open_banking(json!(null)), Currency::EUR));
    assert!(accepts(
        &open_banking(json!({"type": "all_accepted"})),
        Currency::EUR
    ));
}

#[test]
fn an_empty_list_restricts_nothing() {
    for restriction in ["enable_only", "disable_only"] {
        let account = open_banking(json!({"type": restriction, "list": []}));
        assert!(accepts(&account, Currency::EUR), "{restriction}");
    }
}

#[test]
fn one_entry_of_several_for_a_type_is_enough() {
    let account = enabled(json!([
        {
            "payment_method_type": "open_banking",
            "accepted_currencies": {"type": "enable_only", "list": ["GBP"]},
        },
        {
            "payment_method_type": "open_banking",
            "accepted_currencies": {"type": "enable_only", "list": ["EUR"]},
        },
    ]));
    assert!(accepts(&account, Currency::EUR));
    assert!(!accepts(&account, Currency::USD));
}

#[test]
fn a_restriction_on_another_type_does_not_apply() {
    let account = enabled(json!([{
        "payment_method_type": "ideal",
        "accepted_currencies": {"type": "enable_only", "list": ["GBP"]},
    }]));
    assert!(accepts(&account, Currency::EUR));
}

#[test]
fn an_account_without_the_type_is_left_to_the_graph() {
    assert!(accepts(&[], Currency::EUR));
}
