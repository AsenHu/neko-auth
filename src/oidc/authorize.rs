use time;

pub struct AuthorizeState {
    pub csrf_token: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

/// Transport-agnostic data that the physical layer can use
/// to construct its own response.
pub struct AuthorizeOutput {
    pub authorization_url: String,
}

pub enum AuthorizeError<BuildE, StoreE> {
    Build(BuildE),
    Store(StoreE),
}

/// Generic port that lets the pure logic stay decoupled from
/// concrete OIDC clients and storage backends.
pub trait AuthorizePort {
    type BuildError;
    type StoreError;

    /// Builds the OIDC authorization URL and returns the
    /// CSRF / PKCE / nonce state together with a transport-agnostic output.
    fn build_authorization(
        &self,
    ) -> impl Future<Output = Result<(AuthorizeState, AuthorizeOutput), Self::BuildError>>;

    /// Returns the current time used by the pure logic layer
    /// to stamp the creation time of the authorization state.
    fn current_time(&self) -> time::OffsetDateTime;

    /// Persists the CSRF / PKCE / nonce state into any backend
    /// such as memory, a database, or another storage service,
    /// together with the explicit creation time chosen by the logic layer.
    fn store_authorization_state(
        &self,
        state: &AuthorizeState,
        created_at: time::OffsetDateTime,
    ) -> impl Future<Output = Result<(), Self::StoreError>>;
}

/// Pure authorize logic:
/// 1. asks the caller to build the OIDC authorization request
/// 2. stamps the state creation time
/// 3. persists the generated CSRF / PKCE / nonce state
/// 4. returns transport-agnostic output for the physical layer
pub async fn authorize<P>(
    port: &P,
) -> Result<AuthorizeOutput, AuthorizeError<P::BuildError, P::StoreError>>
where
    P: AuthorizePort,
{
    let (state, output) = port
        .build_authorization()
        .await
        .map_err(AuthorizeError::Build)?;
    let created_at = port.current_time();

    port.store_authorization_state(&state, created_at)
        .await
        .map_err(AuthorizeError::Store)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum BuildTestError {
        Build,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum StoreTestError {
        Store,
    }

    struct StoredAuthorization {
        csrf_token: String,
        pkce_verifier: String,
        nonce: String,
        created_at: time::OffsetDateTime,
    }

    struct MockAuthorizePort {
        build_results:
            test_support::Script<Result<(AuthorizeState, AuthorizeOutput), BuildTestError>>,
        clock: test_support::StubClock, // This comes with a built-in call count counter 这个自带调用次数计数器
        store_results: test_support::Script<Result<(), StoreTestError>>,

        build_authorization_calls: test_support::Counter,
        store_authorization_state_calls: test_support::Counter,

        stored_authorizations: test_support::Recordings<StoredAuthorization>,
    }

    impl MockAuthorizePort {
        fn new<const BUILD_N: usize, const TIME_N: usize, const STORE_N: usize>(
            build_results: [Result<(AuthorizeState, AuthorizeOutput), BuildTestError>; BUILD_N],
            current_times: [time::OffsetDateTime; TIME_N],
            store_results: [Result<(), StoreTestError>; STORE_N],
        ) -> Self {
            Self {
                build_results: test_support::Script::new(build_results),
                clock: test_support::StubClock::new(current_times),
                store_results: test_support::Script::new(store_results),

                build_authorization_calls: test_support::Counter::new(),
                store_authorization_state_calls: test_support::Counter::new(),

                stored_authorizations: test_support::Recordings::new(),
            }
        }
    }

    impl AuthorizePort for MockAuthorizePort {
        type BuildError = BuildTestError;
        type StoreError = StoreTestError;

        fn build_authorization(
            &self,
        ) -> impl Future<Output = Result<(AuthorizeState, AuthorizeOutput), Self::BuildError>>
        {
            self.build_authorization_calls.increment();

            let result = self
                .build_results
                .next("missing configured build_authorization return value");

            async move { result }
        }

        fn current_time(&self) -> time::OffsetDateTime {
            self.clock.now()
        }

        fn store_authorization_state(
            &self,
            state: &AuthorizeState,
            created_at: time::OffsetDateTime,
        ) -> impl Future<Output = Result<(), Self::StoreError>> {
            self.store_authorization_state_calls.increment();

            self.stored_authorizations.push(StoredAuthorization {
                csrf_token: state.csrf_token.clone(),
                pkce_verifier: state.pkce_verifier.clone(),
                nonce: state.nonce.clone(),
                created_at,
            });

            let result = self
                .store_results
                .next("missing configured store_authorization_state return value");

            async move { result }
        }
    }

    #[test]
    fn authorize_returns_output_and_stores_state_with_created_at() {
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockAuthorizePort::new([ok_prepared_authorize()], [created_at], [Ok(())]);

        let output = match test_support::block_on(authorize(&port)) {
            Ok(output) => output,
            Err(_) => panic!("expected success"),
        };

        assert_eq!(
            output.authorization_url,
            "https://issuer.example.com/authorize?state=csrf-123"
        );
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_authorization_state_calls.get(), 1);

        let stored = port.stored_authorizations.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].csrf_token, "csrf-123");
        assert_eq!(stored[0].pkce_verifier, "pkce-456");
        assert_eq!(stored[0].nonce, "nonce-789");
        assert_eq!(stored[0].created_at, created_at);
    }

    #[test]
    fn authorize_returns_build_error_without_storing_state() {
        let port = MockAuthorizePort::new([Err(BuildTestError::Build)], [], []);

        let result = test_support::block_on(authorize(&port));

        match result {
            Err(AuthorizeError::Build(BuildTestError::Build)) => {}
            Err(AuthorizeError::Store(StoreTestError::Store)) => {
                panic!("expected build error, got store error")
            }
            Ok(_) => panic!("expected build error, got success"),
        }
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.store_authorization_state_calls.get(), 0);
        assert!(port.stored_authorizations.is_empty());
    }

    #[test]
    fn authorize_returns_store_error_after_persist_attempt() {
        let created_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockAuthorizePort::new(
            [ok_prepared_authorize()],
            [created_at],
            [Err(StoreTestError::Store)],
        );

        let result = test_support::block_on(authorize(&port));

        match result {
            Err(AuthorizeError::Store(StoreTestError::Store)) => {}
            Err(AuthorizeError::Build(BuildTestError::Build)) => {
                panic!("expected store error, got build error")
            }
            Ok(_) => panic!("expected store error, got success"),
        }
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.store_authorization_state_calls.get(), 1);

        let stored = port.stored_authorizations.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].created_at, created_at);
    }

    fn ok_prepared_authorize() -> Result<(AuthorizeState, AuthorizeOutput), BuildTestError> {
        Ok((
            AuthorizeState {
                csrf_token: "csrf-123".to_owned(),
                pkce_verifier: "pkce-456".to_owned(),
                nonce: "nonce-789".to_owned(),
            },
            AuthorizeOutput {
                authorization_url: "https://issuer.example.com/authorize?state=csrf-123".to_owned(),
            },
        ))
    }
}
