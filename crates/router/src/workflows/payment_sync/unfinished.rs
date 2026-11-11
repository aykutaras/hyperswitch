//! Which payments the last scheduled payment sync moves to failed, and with
//! what. Kept apart from the workflow so it stays a few lines there.
//!
//! Two kinds fail: a payment still pending with no connector transaction id,
//! which never had a response from the connector, and a payment still awaiting
//! the customer at a connector whose unfinished payments can no longer complete
//! by then (`ConnectorSpecifications::expires_unfinished_payment_on_last_sync`).
//! Anything else stays as it is.

use hyperswitch_interfaces::api::ConnectorSpecifications;
use router_env::logger;

use crate::{
    consts,
    routes::SessionState,
    types::{
        api,
        storage::{self, enums},
    },
};

const UNFINISHED_PAYMENT_ERROR_CODE: &str = "PAYMENT_NOT_FINISHED";
const UNFINISHED_PAYMENT_ERROR_MESSAGE: &str =
    "This Payment has been moved to failed as the customer did not finish it before its last status check";

/// The error fields a payment fails with on its last sync.
#[derive(Debug, PartialEq)]
pub(super) struct LastSyncFailure {
    pub(super) error_code: Option<Option<String>>,
    pub(super) error_message: Option<Option<String>>,
    pub(super) error_reason: Option<Option<String>>,
}

/// What the payment fails with on this sync, if it does. Only the last retry
/// fails anything, and only a payment awaiting the customer asks its connector.
pub(super) fn last_sync_failure(
    state: &SessionState,
    connector: &str,
    payment_attempt: &storage::PaymentAttempt,
    is_last_retry: bool,
) -> Option<LastSyncFailure> {
    if !is_last_retry {
        return None;
    }
    let expires_unfinished = payment_attempt.status == enums::AttemptStatus::AuthenticationPending
        && connector_expires_unfinished_payment(state, connector);
    failure_for(
        payment_attempt.status,
        payment_attempt.connector_transaction_id.is_some(),
        expires_unfinished,
    )
}

fn failure_for(
    status: enums::AttemptStatus,
    has_connector_transaction_id: bool,
    expires_unfinished: bool,
) -> Option<LastSyncFailure> {
    match status {
        enums::AttemptStatus::Pending if !has_connector_transaction_id => Some(LastSyncFailure {
            error_code: None,
            error_message: None,
            error_reason: Some(Some(
                consts::REQUEST_TIMEOUT_ERROR_MESSAGE_FROM_PSYNC.to_string(),
            )),
        }),
        enums::AttemptStatus::AuthenticationPending if expires_unfinished => {
            Some(LastSyncFailure {
                error_code: Some(Some(UNFINISHED_PAYMENT_ERROR_CODE.to_string())),
                error_message: Some(Some(UNFINISHED_PAYMENT_ERROR_MESSAGE.to_string())),
                error_reason: Some(Some(UNFINISHED_PAYMENT_ERROR_MESSAGE.to_string())),
            })
        }
        _ => None,
    }
}

/// Whether the connector fails a payment still awaiting the customer on its last
/// sync. A name the router does not know cannot opt in.
fn connector_expires_unfinished_payment(state: &SessionState, connector: &str) -> bool {
    api::ConnectorData::get_connector_by_name(
        &state.conf.connectors,
        connector,
        api::GetToken::Connector,
        None,
    )
    .inspect_err(|err| {
        logger::warn!(
            error = ?err,
            "payment sync: unknown connector {connector}; an unfinished payment stays as it is"
        )
    })
    .is_ok_and(|connector_data| {
        connector_data
            .connector
            .expires_unfinished_payment_on_last_sync()
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_pending_payment_without_a_connector_response_fails_on_the_last_sync() {
        let failure = failure_for(enums::AttemptStatus::Pending, false, false).unwrap();
        assert_eq!(
            failure.error_reason,
            Some(Some(
                consts::REQUEST_TIMEOUT_ERROR_MESSAGE_FROM_PSYNC.to_string()
            ))
        );
        assert_eq!(failure.error_code, None);
    }

    #[test]
    fn a_pending_payment_the_connector_knows_stays_pending() {
        assert_eq!(failure_for(enums::AttemptStatus::Pending, true, true), None);
    }

    #[test]
    fn an_unfinished_payment_fails_where_the_connector_expires_it() {
        let failure = failure_for(enums::AttemptStatus::AuthenticationPending, true, true).unwrap();
        assert_eq!(
            failure.error_code,
            Some(Some(UNFINISHED_PAYMENT_ERROR_CODE.to_string()))
        );
        assert_eq!(
            failure.error_message,
            Some(Some(UNFINISHED_PAYMENT_ERROR_MESSAGE.to_string()))
        );
    }

    #[test]
    fn an_unfinished_payment_stays_where_the_connector_does_not() {
        assert_eq!(
            failure_for(enums::AttemptStatus::AuthenticationPending, true, false),
            None
        );
    }
}
