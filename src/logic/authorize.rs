use time::OffsetDateTime;

/// Pure logical state that must be persisted before handing control
/// to the upstream OIDC provider.
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

/// Result produced by the caller-owned OIDC builder.
///
/// The pure logic only coordinates these two parts:
/// 1. persist the state
/// 2. return the output back to the physical layer
pub struct PreparedAuthorize {
    pub state: AuthorizeState,
    pub output: AuthorizeOutput,
}

/// Generic port that lets the pure logic stay decoupled from
/// concrete OIDC clients and storage backends.
pub trait AuthorizePort {
    type Error;

    /// Builds the OIDC authorization URL and returns the
    /// CSRF / PKCE / nonce state together with a transport-agnostic output.
    fn build_authorization(&self) -> impl Future<Output = Result<PreparedAuthorize, Self::Error>>;

    /// Returns the current time used by the pure logic layer
    /// to stamp the creation time of the authorization state.
    fn current_time(&self) -> OffsetDateTime;

    /// Persists the CSRF / PKCE / nonce state into any backend
    /// such as memory, a database, or another storage service,
    /// together with the explicit creation time chosen by the logic layer.
    fn store_authorization_state(
        &self,
        state: &AuthorizeState,
        created_at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Pure authorize logic:
/// 1. asks the caller to build the OIDC authorization request
/// 2. stamps the state creation time
/// 3. persists the generated CSRF / PKCE / nonce state
/// 4. returns transport-agnostic output for the physical layer
pub async fn authorize<P>(port: &P) -> Result<AuthorizeOutput, P::Error>
where
    P: AuthorizePort,
{
    let prepared = port.build_authorization().await?;
    let created_at = port.current_time();

    port.store_authorization_state(&prepared.state, created_at)
        .await?;

    Ok(prepared.output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future;
    use core::task::{Context, Poll, Waker};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::{pin, thread};
    use time::OffsetDateTime;

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        Build,
        Store,
    }

    struct StoredAuthorization {
        csrf_token: String,
        pkce_verifier: String,
        nonce: String,
        created_at: OffsetDateTime,
    }

    struct MockAuthorizePort {
        build_results: RefCell<VecDeque<Result<PreparedAuthorize, TestError>>>,
        current_times: RefCell<VecDeque<OffsetDateTime>>,
        store_results: RefCell<VecDeque<Result<(), TestError>>>,

        build_authorization_calls: Cell<usize>,
        current_time_calls: Cell<usize>,
        store_authorization_state_calls: Cell<usize>,

        stored_authorizations: RefCell<Vec<StoredAuthorization>>,
    }

    impl MockAuthorizePort {
        fn new<const BUILD_N: usize, const TIME_N: usize, const STORE_N: usize>(
            build_results: [Result<PreparedAuthorize, TestError>; BUILD_N],
            current_times: [OffsetDateTime; TIME_N],
            store_results: [Result<(), TestError>; STORE_N],
        ) -> Self {
            Self {
                build_results: RefCell::new(build_results.into_iter().collect()),
                current_times: RefCell::new(current_times.into_iter().collect()),
                store_results: RefCell::new(store_results.into_iter().collect()),

                build_authorization_calls: Cell::new(0),
                current_time_calls: Cell::new(0),
                store_authorization_state_calls: Cell::new(0),

                stored_authorizations: RefCell::new(Vec::new()),
            }
        }
    }

    impl AuthorizePort for MockAuthorizePort {
        type Error = TestError;

        fn build_authorization(
            &self,
        ) -> impl Future<Output = Result<PreparedAuthorize, Self::Error>> {
            self.build_authorization_calls
                .set(self.build_authorization_calls.get() + 1);

            let result = self
                .build_results
                .borrow_mut()
                .pop_front()
                .expect("missing configured build_authorization return value");

            async move { result }
        }

        fn current_time(&self) -> OffsetDateTime {
            self.current_time_calls
                .set(self.current_time_calls.get() + 1);

            self.current_times
                .borrow_mut()
                .pop_front()
                .expect("missing configured current_time return value")
        }

        fn store_authorization_state(
            &self,
            state: &AuthorizeState,
            created_at: OffsetDateTime,
        ) -> impl Future<Output = Result<(), Self::Error>> {
            self.store_authorization_state_calls
                .set(self.store_authorization_state_calls.get() + 1);

            self.stored_authorizations
                .borrow_mut()
                .push(StoredAuthorization {
                    csrf_token: state.csrf_token.clone(),
                    pkce_verifier: state.pkce_verifier.clone(),
                    nonce: state.nonce.clone(),
                    created_at,
                });

            let result = self
                .store_results
                .borrow_mut()
                .pop_front()
                .expect("missing configured store_authorization_state return value");

            async move { result }
        }
    }

    #[test]
    fn authorize_returns_output_and_stores_state_with_created_at() {
        let created_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockAuthorizePort::new([ok_prepared_authorize()], [created_at], [Ok(())]);

        let output = block_on(authorize(&port)).unwrap();

        assert_eq!(
            output.authorization_url,
            "https://issuer.example.com/authorize?state=csrf-123"
        );
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.current_time_calls.get(), 1);
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
        let port = MockAuthorizePort::new([Err(TestError::Build)], [], []);

        let result = block_on(authorize(&port));

        match result {
            Err(TestError::Build) => {}
            Err(TestError::Store) => panic!("expected build error, got store error"),
            Ok(_) => panic!("expected build error, got success"),
        }
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.current_time_calls.get(), 0);
        assert_eq!(port.store_authorization_state_calls.get(), 0);
        assert!(port.stored_authorizations.borrow().is_empty());
    }

    #[test]
    fn authorize_returns_store_error_after_persist_attempt() {
        let created_at = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let port = MockAuthorizePort::new(
            [ok_prepared_authorize()],
            [created_at],
            [Err(TestError::Store)],
        );

        let result = block_on(authorize(&port));

        match result {
            Err(TestError::Store) => {}
            Err(TestError::Build) => panic!("expected store error, got build error"),
            Ok(_) => panic!("expected store error, got success"),
        }
        assert_eq!(port.build_authorization_calls.get(), 1);
        assert_eq!(port.current_time_calls.get(), 1);
        assert_eq!(port.store_authorization_state_calls.get(), 1);

        let stored = port.stored_authorizations.borrow();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].created_at, created_at);
    }

    fn ok_prepared_authorize() -> Result<PreparedAuthorize, TestError> {
        Ok(PreparedAuthorize {
            state: AuthorizeState {
                csrf_token: "csrf-123".to_owned(),
                pkce_verifier: "pkce-456".to_owned(),
                nonce: "nonce-789".to_owned(),
            },
            output: AuthorizeOutput {
                authorization_url: "https://issuer.example.com/authorize?state=csrf-123".to_owned(),
            },
        })
    }

    fn block_on<F>(future: F) -> F::Output
    where
        F: future::Future,
    {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin::pin!(future);

        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => thread::yield_now(),
            }
        }
    }
}
