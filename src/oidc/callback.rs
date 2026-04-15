use super::types;
use time;

/// Normalized input extracted from the OIDC callback request.
pub struct CallbackInput {
    pub authorization_code: String,
    pub csrf_token: String,
}

/// Session state that must be persisted after the callback succeeds.
pub struct CallbackSession {
    pub session_id: String,
    pub subject: String,
    pub oidc_session_id: Option<String>,
}

/// Transport-agnostic data that the physical layer can use
/// to continue the authenticated application flow.
pub struct CallbackOutput {
    pub session_id: String,
    pub subject: String,
}

/// Result produced by the caller-owned OIDC callback finisher.
///
/// The pure logic only coordinates these two parts:
/// 1. persist the resulting session
/// 2. return the output back to the physical layer
pub struct PreparedCallback {
    pub session: CallbackSession,
    pub output: CallbackOutput,
}

/// Generic port that lets the pure logic stay decoupled from
/// concrete OIDC clients and session storage backends.
pub trait CallbackPort {
    type Error;

    /// Consumes the stored authorization state for the given CSRF token.
    /// Implementations can make this operation atomic to prevent callback replays.
    fn take_authorization_state(
        &self,
        csrf_token: &str,
    ) -> impl Future<Output = Result<types::AuthorizeState, Self::Error>>;

    /// Completes the OIDC callback using the consumed authorization state
    /// and returns the caller-owned session data together with a
    /// transport-agnostic output.
    fn finish_callback(
        &self,
        input: &CallbackInput,
        authorization_state: &types::AuthorizeState,
    ) -> impl Future<Output = Result<PreparedCallback, Self::Error>>;

    /// Returns the current time used by the pure logic layer
    /// to stamp the creation time of the authenticated session.
    fn current_time(&self) -> time::OffsetDateTime;

    /// Persists the authenticated session into any backend such as
    /// memory, a database, or another session service, together with
    /// the explicit creation time chosen by the logic layer.
    fn store_session(
        &self,
        session: &CallbackSession,
        created_at: time::OffsetDateTime,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Pure callback logic:
/// 1. consumes the stored authorization state using the CSRF token
/// 2. asks the caller to complete the OIDC callback flow
/// 3. stamps the resulting authenticated session creation time
/// 4. persists the session
/// 5. returns transport-agnostic output for the physical layer
pub async fn callback<P>(port: &P, input: &CallbackInput) -> Result<CallbackOutput, P::Error>
where
    P: CallbackPort,
{
    let authorization_state = port.take_authorization_state(&input.csrf_token).await?;
    let prepared = port.finish_callback(input, &authorization_state).await?;
    let created_at = port.current_time();

    port.store_session(&prepared.session, created_at).await?;

    Ok(prepared.output)
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        TakeState,
        Finish,
        Store,
    }

    struct FinishedCallbackCall {
        authorization_code: String,
        csrf_token: String,
        state_csrf_token: String,
        state_pkce_verifier: String,
        state_nonce: String,
    }

    struct StoredSession {
        session_id: String,
        subject: String,
        oidc_session_id: Option<String>,
        created_at: time::OffsetDateTime,
    }

    struct MockCallbackPort {
        take_state_results: test_support::Script<Result<types::AuthorizeState, TestError>>,
        finish_results: test_support::Script<Result<PreparedCallback, TestError>>,
        clock: test_support::StubClock,
        store_results: test_support::Script<Result<(), TestError>>,
        take_authorization_state_calls: test_support::Counter,
        finish_callback_calls: test_support::Counter,
        store_session_calls: test_support::Counter,
        taken_csrf_tokens: test_support::Recordings<String>,
        finished_callbacks: test_support::Recordings<FinishedCallbackCall>,
        stored_sessions: test_support::Recordings<StoredSession>,
    }

    impl MockCallbackPort {
        fn new<
            const TAKE_N: usize,
            const FINISH_N: usize,
            const TIME_N: usize,
            const STORE_N: usize,
        >(
            take_state_results: [Result<types::AuthorizeState, TestError>; TAKE_N],
            finish_results: [Result<PreparedCallback, TestError>; FINISH_N],
            current_times: [time::OffsetDateTime; TIME_N],
            store_results: [Result<(), TestError>; STORE_N],
        ) -> Self {
            Self {
                take_state_results: test_support::Script::new(take_state_results),
                finish_results: test_support::Script::new(finish_results),
                clock: test_support::StubClock::new(current_times),
                store_results: test_support::Script::new(store_results),
                take_authorization_state_calls: test_support::Counter::new(),
                finish_callback_calls: test_support::Counter::new(),
                store_session_calls: test_support::Counter::new(),
                taken_csrf_tokens: test_support::Recordings::new(),
                finished_callbacks: test_support::Recordings::new(),
                stored_sessions: test_support::Recordings::new(),
            }
        }
    }

    impl CallbackPort for MockCallbackPort {
        type Error = TestError;

        fn take_authorization_state(
            &self,
            csrf_token: &str,
        ) -> impl Future<Output = Result<types::AuthorizeState, Self::Error>> {
            self.take_authorization_state_calls.increment();
            self.taken_csrf_tokens.push(csrf_token.to_owned());

            let result = self
                .take_state_results
                .next("missing configured take_authorization_state return value");

            async move { result }
        }

        fn finish_callback(
            &self,
            input: &CallbackInput,
            authorization_state: &types::AuthorizeState,
        ) -> impl Future<Output = Result<PreparedCallback, Self::Error>> {
            self.finish_callback_calls.increment();
            self.finished_callbacks.push(FinishedCallbackCall {
                authorization_code: input.authorization_code.clone(),
                csrf_token: input.csrf_token.clone(),
                state_csrf_token: authorization_state.csrf_token.clone(),
                state_pkce_verifier: authorization_state.pkce_verifier.clone(),
                state_nonce: authorization_state.nonce.clone(),
            });

            let result = self
                .finish_results
                .next("missing configured finish_callback return value");

            async move { result }
        }

        fn current_time(&self) -> time::OffsetDateTime {
            self.clock.now()
        }

        fn store_session(
            &self,
            session: &CallbackSession,
            created_at: time::OffsetDateTime,
        ) -> impl Future<Output = Result<(), Self::Error>> {
            self.store_session_calls.increment();
            self.stored_sessions.push(StoredSession {
                session_id: session.session_id.clone(),
                subject: session.subject.clone(),
                oidc_session_id: session.oidc_session_id.clone(),
                created_at,
            });

            let result = self
                .store_results
                .next("missing configured store_session return value");

            async move { result }
        }
    }

    #[test]
    fn callback_returns_output_and_stores_session_with_created_at() {
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_authorize_state())],
            [ok_prepared_callback()],
            [created_at],
            [Ok(())],
        );
        let input = callback_input();

        let output = test_support::block_on(callback(&port, &input)).unwrap();

        assert_eq!(output.session_id, "session-123");
        assert_eq!(output.subject, "user-456");
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.finish_callback_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_session_calls.get(), 1);

        let taken_tokens = port.taken_csrf_tokens.borrow();
        assert_eq!(taken_tokens.as_slice(), ["csrf-123"]);

        let finished = port.finished_callbacks.borrow();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].authorization_code, "code-789");
        assert_eq!(finished[0].csrf_token, "csrf-123");
        assert_eq!(finished[0].state_csrf_token, "csrf-123");
        assert_eq!(finished[0].state_pkce_verifier, "pkce-456");
        assert_eq!(finished[0].state_nonce, "nonce-789");

        let stored = port.stored_sessions.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].session_id, "session-123");
        assert_eq!(stored[0].subject, "user-456");
        assert_eq!(
            stored[0].oidc_session_id.as_deref(),
            Some("oidc-session-321")
        );
        assert_eq!(stored[0].created_at, created_at);
    }

    #[test]
    fn callback_returns_take_state_error_without_finishing_callback() {
        let port = MockCallbackPort::new([Err(TestError::TakeState)], [], [], []);
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(TestError::TakeState) => {}
            Err(TestError::Finish) => panic!("expected take-state error, got finish error"),
            Err(TestError::Store) => panic!("expected take-state error, got store error"),
            Ok(_) => panic!("expected take-state error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.finish_callback_calls.get(), 0);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.finished_callbacks.is_empty());
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_finish_error_without_storing_session() {
        let port =
            MockCallbackPort::new([Ok(ok_authorize_state())], [Err(TestError::Finish)], [], []);
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(TestError::Finish) => {}
            Err(TestError::TakeState) => panic!("expected finish error, got take-state error"),
            Err(TestError::Store) => panic!("expected finish error, got store error"),
            Ok(_) => panic!("expected finish error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.finish_callback_calls.get(), 1);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_store_error_after_persist_attempt() {
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_authorize_state())],
            [ok_prepared_callback()],
            [created_at],
            [Err(TestError::Store)],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(TestError::Store) => {}
            Err(TestError::TakeState) => panic!("expected store error, got take-state error"),
            Err(TestError::Finish) => panic!("expected store error, got finish error"),
            Ok(_) => panic!("expected store error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.finish_callback_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_session_calls.get(), 1);

        let stored = port.stored_sessions.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].created_at, created_at);
    }

    fn callback_input() -> CallbackInput {
        CallbackInput {
            authorization_code: "code-789".to_owned(),
            csrf_token: "csrf-123".to_owned(),
        }
    }

    fn ok_authorize_state() -> types::AuthorizeState {
        types::AuthorizeState {
            csrf_token: "csrf-123".to_owned(),
            pkce_verifier: "pkce-456".to_owned(),
            nonce: "nonce-789".to_owned(),
        }
    }

    fn ok_prepared_callback() -> Result<PreparedCallback, TestError> {
        Ok(PreparedCallback {
            session: CallbackSession {
                session_id: "session-123".to_owned(),
                subject: "user-456".to_owned(),
                oidc_session_id: Some("oidc-session-321".to_owned()),
            },
            output: CallbackOutput {
                session_id: "session-123".to_owned(),
                subject: "user-456".to_owned(),
            },
        })
    }
}
