use time;

pub struct StoredAuthorizeState {
    pub csrf_token: String,
    pub pkce_verifier: String,
    pub nonce: String,
    pub created_at: time::OffsetDateTime,
}

/// Normalized input extracted from the OIDC callback request.
pub struct CallbackInput {
    pub authorization_code: String,
    pub csrf_token: String,
}

/// Tokens obtained from the upstream OIDC provider.
pub struct OidcTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token_nonce: String,
}

/// User profile resolved from the upstream OIDC provider.
pub struct UserProfile {
    pub subject: String,
    pub oidc_session_id: Option<String>,
}

/// Session data that must be persisted after the callback succeeds.
pub struct CallbackSession {
    pub tokens: OidcTokens,
    pub profile: UserProfile,
    pub authorization_created_at: time::OffsetDateTime,
}

/// Transport-agnostic data that the physical layer can use
/// to hand the newly issued refresh token back to the user.
pub struct CallbackOutput {
    pub refresh_token: String,
}

pub enum CallbackError<TakeStateE, ExchangeTokensE, FetchProfileE, RevokeTokensE, StoreSessionE> {
    NonceMismatch,
    TakeState(TakeStateE),
    ExchangeTokens(ExchangeTokensE),
    FetchProfile(FetchProfileE),
    RevokeTokens(RevokeTokensE),
    StoreSession(StoreSessionE),
}

pub trait CallbackPort {
    type TakeStateError;
    type ExchangeTokensError;
    type FetchProfileError;
    type RevokeTokensError;
    type StoreSessionError;

    /// Consumes the stored authorization state for the given CSRF token.
    /// Implementations can make this operation atomic to prevent callback replays.
    fn take_authorization_state(
        &self,
        csrf_token: &str,
    ) -> impl Future<Output = Result<StoredAuthorizeState, Self::TakeStateError>>;

    /// Exchanges the authorization code and PKCE verifier for the upstream
    /// OIDC token set.
    fn exchange_tokens(
        &self,
        input: &CallbackInput,
        authorization_state: &StoredAuthorizeState,
    ) -> impl Future<Output = Result<OidcTokens, Self::ExchangeTokensError>>;

    /// Fetches the authenticated user's profile using the OIDC token set.
    fn fetch_user_profile(
        &self,
        tokens: &OidcTokens,
    ) -> impl Future<Output = Result<UserProfile, Self::FetchProfileError>>;

    /// Revokes the OIDC token set after the required profile data
    /// has been collected.
    fn revoke_tokens(
        &self,
        tokens: &OidcTokens,
    ) -> impl Future<Output = Result<(), Self::RevokeTokensError>>;

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
    ) -> impl Future<Output = Result<(), Self::StoreSessionError>>;
}

/// Pure callback logic:
/// 1. consumes the stored authorization state using the CSRF token
/// 2. exchanges the authorization code for OIDC tokens
/// 3. verifies the returned nonce against the stored authorization state
/// 4. fetches the authenticated user's profile
/// 5. revokes the OIDC tokens
/// 6. stamps the resulting authenticated session creation time
/// 7. persists the session
/// 8. returns success or failure to the physical layer
pub async fn callback<P>(
    port: &P,
    input: &CallbackInput,
) -> Result<
    CallbackOutput,
    CallbackError<
        P::TakeStateError,
        P::ExchangeTokensError,
        P::FetchProfileError,
        P::RevokeTokensError,
        P::StoreSessionError,
    >,
>
where
    P: CallbackPort,
{
    let authorization_state = port
        .take_authorization_state(&input.csrf_token)
        .await
        .map_err(CallbackError::TakeState)?;
    let tokens = port
        .exchange_tokens(input, &authorization_state)
        .await
        .map_err(CallbackError::ExchangeTokens)?;

    if tokens.id_token_nonce != authorization_state.nonce {
        return Err(CallbackError::NonceMismatch);
    }

    let profile = port
        .fetch_user_profile(&tokens)
        .await
        .map_err(CallbackError::FetchProfile)?;
    port.revoke_tokens(&tokens)
        .await
        .map_err(CallbackError::RevokeTokens)?;
    let created_at = port.current_time();
    let session = CallbackSession {
        tokens,
        profile,
        authorization_created_at: authorization_state.created_at,
    };

    port.store_session(&session, created_at)
        .await
        .map_err(CallbackError::StoreSession)?;

    Ok(CallbackOutput {
        refresh_token: session.tokens.refresh_token,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum TakeStateTestError {
        TakeState,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ExchangeTokensTestError {
        ExchangeTokens,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum FetchProfileTestError {
        FetchProfile,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RevokeTokensTestError {
        RevokeTokens,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum StoreSessionTestError {
        StoreSession,
    }

    struct ExchangedTokensCall {
        authorization_code: String,
        input_csrf_token: String,
        state_csrf_token: String,
        state_pkce_verifier: String,
        state_nonce: String,
        state_created_at: time::OffsetDateTime,
    }

    struct FetchedProfileCall {
        access_token: String,
        refresh_token: String,
        id_token_nonce: String,
    }

    struct RevokedTokensCall {
        access_token: String,
        refresh_token: String,
        id_token_nonce: String,
    }

    struct StoredSession {
        access_token: String,
        refresh_token: String,
        subject: String,
        oidc_session_id: Option<String>,
        authorization_created_at: time::OffsetDateTime,
        created_at: time::OffsetDateTime,
    }

    struct MockCallbackPort {
        take_state_results: test_support::Script<Result<StoredAuthorizeState, TakeStateTestError>>,
        exchange_tokens_results: test_support::Script<Result<OidcTokens, ExchangeTokensTestError>>,
        fetch_profile_results: test_support::Script<Result<UserProfile, FetchProfileTestError>>,
        revoke_tokens_results: test_support::Script<Result<(), RevokeTokensTestError>>,
        clock: test_support::StubClock,
        store_results: test_support::Script<Result<(), StoreSessionTestError>>,

        take_authorization_state_calls: test_support::Counter,
        exchange_tokens_calls: test_support::Counter,
        fetch_user_profile_calls: test_support::Counter,
        revoke_tokens_calls: test_support::Counter,
        store_session_calls: test_support::Counter,

        taken_csrf_tokens: test_support::Recordings<String>,
        exchanged_tokens: test_support::Recordings<ExchangedTokensCall>,
        fetched_profiles: test_support::Recordings<FetchedProfileCall>,
        revoked_tokens: test_support::Recordings<RevokedTokensCall>,
        stored_sessions: test_support::Recordings<StoredSession>,
    }

    impl MockCallbackPort {
        fn new<
            const TAKE_N: usize,
            const EXCHANGE_N: usize,
            const FETCH_N: usize,
            const REVOKE_N: usize,
            const TIME_N: usize,
            const STORE_N: usize,
        >(
            take_state_results: [Result<StoredAuthorizeState, TakeStateTestError>; TAKE_N],
            exchange_tokens_results: [Result<OidcTokens, ExchangeTokensTestError>; EXCHANGE_N],
            fetch_profile_results: [Result<UserProfile, FetchProfileTestError>; FETCH_N],
            revoke_tokens_results: [Result<(), RevokeTokensTestError>; REVOKE_N],
            current_times: [time::OffsetDateTime; TIME_N],
            store_results: [Result<(), StoreSessionTestError>; STORE_N],
        ) -> Self {
            Self {
                take_state_results: test_support::Script::new(take_state_results),
                exchange_tokens_results: test_support::Script::new(exchange_tokens_results),
                fetch_profile_results: test_support::Script::new(fetch_profile_results),
                revoke_tokens_results: test_support::Script::new(revoke_tokens_results),
                clock: test_support::StubClock::new(current_times),
                store_results: test_support::Script::new(store_results),
                take_authorization_state_calls: test_support::Counter::new(),
                exchange_tokens_calls: test_support::Counter::new(),
                fetch_user_profile_calls: test_support::Counter::new(),
                revoke_tokens_calls: test_support::Counter::new(),
                store_session_calls: test_support::Counter::new(),
                taken_csrf_tokens: test_support::Recordings::new(),
                exchanged_tokens: test_support::Recordings::new(),
                fetched_profiles: test_support::Recordings::new(),
                revoked_tokens: test_support::Recordings::new(),
                stored_sessions: test_support::Recordings::new(),
            }
        }
    }

    impl CallbackPort for MockCallbackPort {
        type TakeStateError = TakeStateTestError;
        type ExchangeTokensError = ExchangeTokensTestError;
        type FetchProfileError = FetchProfileTestError;
        type RevokeTokensError = RevokeTokensTestError;
        type StoreSessionError = StoreSessionTestError;

        fn take_authorization_state(
            &self,
            csrf_token: &str,
        ) -> impl Future<Output = Result<StoredAuthorizeState, Self::TakeStateError>> {
            self.take_authorization_state_calls.increment();
            self.taken_csrf_tokens.push(csrf_token.to_owned());

            let result = self
                .take_state_results
                .next("missing configured take_authorization_state return value");

            async move { result }
        }

        fn exchange_tokens(
            &self,
            input: &CallbackInput,
            authorization_state: &StoredAuthorizeState,
        ) -> impl Future<Output = Result<OidcTokens, Self::ExchangeTokensError>> {
            self.exchange_tokens_calls.increment();
            self.exchanged_tokens.push(ExchangedTokensCall {
                authorization_code: input.authorization_code.clone(),
                input_csrf_token: input.csrf_token.clone(),
                state_csrf_token: authorization_state.csrf_token.clone(),
                state_pkce_verifier: authorization_state.pkce_verifier.clone(),
                state_nonce: authorization_state.nonce.clone(),
                state_created_at: authorization_state.created_at,
            });

            let result = self
                .exchange_tokens_results
                .next("missing configured exchange_tokens return value");

            async move { result }
        }

        fn fetch_user_profile(
            &self,
            tokens: &OidcTokens,
        ) -> impl Future<Output = Result<UserProfile, Self::FetchProfileError>> {
            self.fetch_user_profile_calls.increment();
            self.fetched_profiles.push(FetchedProfileCall {
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                id_token_nonce: tokens.id_token_nonce.clone(),
            });

            let result = self
                .fetch_profile_results
                .next("missing configured fetch_user_profile return value");

            async move { result }
        }

        fn revoke_tokens(
            &self,
            tokens: &OidcTokens,
        ) -> impl Future<Output = Result<(), Self::RevokeTokensError>> {
            self.revoke_tokens_calls.increment();
            self.revoked_tokens.push(RevokedTokensCall {
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                id_token_nonce: tokens.id_token_nonce.clone(),
            });

            let result = self
                .revoke_tokens_results
                .next("missing configured revoke_tokens return value");

            async move { result }
        }

        fn current_time(&self) -> time::OffsetDateTime {
            self.clock.now()
        }

        fn store_session(
            &self,
            session: &CallbackSession,
            created_at: time::OffsetDateTime,
        ) -> impl Future<Output = Result<(), Self::StoreSessionError>> {
            self.store_session_calls.increment();
            self.stored_sessions.push(StoredSession {
                access_token: session.tokens.access_token.clone(),
                refresh_token: session.tokens.refresh_token.clone(),
                subject: session.profile.subject.clone(),
                oidc_session_id: session.profile.oidc_session_id.clone(),
                authorization_created_at: session.authorization_created_at,
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
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [ok_oidc_tokens()],
            [ok_user_profile()],
            [Ok(())],
            [created_at],
            [Ok(())],
        );
        let input = callback_input();

        let output = match test_support::block_on(callback(&port, &input)) {
            Ok(output) => output,
            Err(_) => panic!("expected success"),
        };

        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 1);
        assert_eq!(port.revoke_tokens_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_session_calls.get(), 1);
        assert_eq!(output.refresh_token, "refresh-token-456");

        let taken_tokens = port.taken_csrf_tokens.borrow();
        assert_eq!(taken_tokens.as_slice(), ["csrf-123"]);

        let exchanged = port.exchanged_tokens.borrow();
        assert_eq!(exchanged.len(), 1);
        assert_eq!(exchanged[0].authorization_code, "code-789");
        assert_eq!(exchanged[0].input_csrf_token, "csrf-123");
        assert_eq!(exchanged[0].state_csrf_token, "csrf-123");
        assert_eq!(exchanged[0].state_pkce_verifier, "pkce-456");
        assert_eq!(exchanged[0].state_nonce, "nonce-789");
        assert_eq!(exchanged[0].state_created_at, authorization_created_at);

        let fetched = port.fetched_profiles.borrow();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].access_token, "access-token-123");
        assert_eq!(fetched[0].refresh_token, "refresh-token-456");
        assert_eq!(fetched[0].id_token_nonce, "nonce-789");

        let revoked = port.revoked_tokens.borrow();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].access_token, "access-token-123");
        assert_eq!(revoked[0].refresh_token, "refresh-token-456");
        assert_eq!(revoked[0].id_token_nonce, "nonce-789");

        let stored = port.stored_sessions.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].access_token, "access-token-123");
        assert_eq!(stored[0].refresh_token, "refresh-token-456");
        assert_eq!(stored[0].subject, "user-456");
        assert_eq!(
            stored[0].oidc_session_id.as_deref(),
            Some("oidc-session-321")
        );
        assert_eq!(stored[0].authorization_created_at, authorization_created_at);
        assert_eq!(stored[0].created_at, created_at);
    }

    #[test]
    fn callback_returns_take_state_error_without_follow_up_steps() {
        let port = MockCallbackPort::new([Err(TakeStateTestError::TakeState)], [], [], [], [], []);
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {
                panic!("expected take-state error, got nonce-mismatch error")
            }
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {}
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {
                panic!("expected take-state error, got exchange-tokens error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {
                panic!("expected take-state error, got fetch-profile error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {
                panic!("expected take-state error, got revoke-tokens error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {
                panic!("expected take-state error, got store-session error")
            }
            Ok(_) => panic!("expected take-state error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 0);
        assert_eq!(port.fetch_user_profile_calls.get(), 0);
        assert_eq!(port.revoke_tokens_calls.get(), 0);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.exchanged_tokens.is_empty());
        assert!(port.fetched_profiles.is_empty());
        assert!(port.revoked_tokens.is_empty());
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_exchange_tokens_error_without_follow_up_steps() {
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [Err(ExchangeTokensTestError::ExchangeTokens)],
            [],
            [],
            [],
            [],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {
                panic!("expected exchange-tokens error, got nonce-mismatch error")
            }
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {}
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {
                panic!("expected exchange-tokens error, got take-state error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {
                panic!("expected exchange-tokens error, got fetch-profile error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {
                panic!("expected exchange-tokens error, got revoke-tokens error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {
                panic!("expected exchange-tokens error, got store-session error")
            }
            Ok(_) => panic!("expected finish error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 0);
        assert_eq!(port.revoke_tokens_calls.get(), 0);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.fetched_profiles.is_empty());
        assert!(port.revoked_tokens.is_empty());
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_nonce_mismatch_without_follow_up_steps() {
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [ok_oidc_tokens_with_nonce("different-nonce")],
            [],
            [],
            [],
            [],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {}
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {
                panic!("expected nonce-mismatch error, got take-state error")
            }
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {
                panic!("expected nonce-mismatch error, got exchange-tokens error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {
                panic!("expected nonce-mismatch error, got fetch-profile error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {
                panic!("expected nonce-mismatch error, got revoke-tokens error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {
                panic!("expected nonce-mismatch error, got store-session error")
            }
            Ok(_) => panic!("expected nonce-mismatch error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 0);
        assert_eq!(port.revoke_tokens_calls.get(), 0);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.fetched_profiles.is_empty());
        assert!(port.revoked_tokens.is_empty());
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_fetch_profile_error_without_revoking_or_storing() {
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [ok_oidc_tokens()],
            [Err(FetchProfileTestError::FetchProfile)],
            [],
            [],
            [],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {
                panic!("expected fetch-profile error, got nonce-mismatch error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {}
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {
                panic!("expected fetch-profile error, got take-state error")
            }
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {
                panic!("expected fetch-profile error, got exchange-tokens error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {
                panic!("expected fetch-profile error, got revoke-tokens error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {
                panic!("expected fetch-profile error, got store-session error")
            }
            Ok(_) => panic!("expected fetch-profile error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 1);
        assert_eq!(port.revoke_tokens_calls.get(), 0);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.revoked_tokens.is_empty());
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_revoke_tokens_error_without_storing() {
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [ok_oidc_tokens()],
            [ok_user_profile()],
            [Err(RevokeTokensTestError::RevokeTokens)],
            [],
            [],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {
                panic!("expected revoke-tokens error, got nonce-mismatch error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {}
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {
                panic!("expected revoke-tokens error, got take-state error")
            }
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {
                panic!("expected revoke-tokens error, got exchange-tokens error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {
                panic!("expected revoke-tokens error, got fetch-profile error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {
                panic!("expected revoke-tokens error, got store-session error")
            }
            Ok(_) => panic!("expected revoke-tokens error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 1);
        assert_eq!(port.revoke_tokens_calls.get(), 1);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_session_calls.get(), 0);
        assert!(port.stored_sessions.is_empty());
    }

    #[test]
    fn callback_returns_store_session_error_after_revoking_tokens() {
        let authorization_created_at =
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap();
        let port = MockCallbackPort::new(
            [Ok(ok_stored_authorize_state(authorization_created_at))],
            [ok_oidc_tokens()],
            [ok_user_profile()],
            [Ok(())],
            [created_at],
            [Err(StoreSessionTestError::StoreSession)],
        );
        let input = callback_input();

        let result = test_support::block_on(callback(&port, &input));

        match result {
            Err(CallbackError::NonceMismatch) => {
                panic!("expected store-session error, got nonce-mismatch error")
            }
            Err(CallbackError::StoreSession(StoreSessionTestError::StoreSession)) => {}
            Err(CallbackError::TakeState(TakeStateTestError::TakeState)) => {
                panic!("expected store-session error, got take-state error")
            }
            Err(CallbackError::ExchangeTokens(ExchangeTokensTestError::ExchangeTokens)) => {
                panic!("expected store-session error, got exchange-tokens error")
            }
            Err(CallbackError::FetchProfile(FetchProfileTestError::FetchProfile)) => {
                panic!("expected store-session error, got fetch-profile error")
            }
            Err(CallbackError::RevokeTokens(RevokeTokensTestError::RevokeTokens)) => {
                panic!("expected store-session error, got revoke-tokens error")
            }
            Ok(_) => panic!("expected store error, got success"),
        }
        assert_eq!(port.take_authorization_state_calls.get(), 1);
        assert_eq!(port.exchange_tokens_calls.get(), 1);
        assert_eq!(port.fetch_user_profile_calls.get(), 1);
        assert_eq!(port.revoke_tokens_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_session_calls.get(), 1);

        let stored = port.stored_sessions.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].authorization_created_at, authorization_created_at);
        assert_eq!(stored[0].created_at, created_at);
    }

    fn callback_input() -> CallbackInput {
        CallbackInput {
            authorization_code: "code-789".to_owned(),
            csrf_token: "csrf-123".to_owned(),
        }
    }

    fn ok_stored_authorize_state(created_at: time::OffsetDateTime) -> StoredAuthorizeState {
        StoredAuthorizeState {
            csrf_token: "csrf-123".to_owned(),
            pkce_verifier: "pkce-456".to_owned(),
            nonce: "nonce-789".to_owned(),
            created_at,
        }
    }

    fn ok_oidc_tokens() -> Result<OidcTokens, ExchangeTokensTestError> {
        ok_oidc_tokens_with_nonce("nonce-789")
    }

    fn ok_oidc_tokens_with_nonce(
        id_token_nonce: &str,
    ) -> Result<OidcTokens, ExchangeTokensTestError> {
        Ok(OidcTokens {
            access_token: "access-token-123".to_owned(),
            refresh_token: "refresh-token-456".to_owned(),
            id_token_nonce: id_token_nonce.to_owned(),
        })
    }

    fn ok_user_profile() -> Result<UserProfile, FetchProfileTestError> {
        Ok(UserProfile {
            subject: "user-456".to_owned(),
            oidc_session_id: Some("oidc-session-321".to_owned()),
        })
    }
}
