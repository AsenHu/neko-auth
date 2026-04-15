use time;

/// Normalized input extracted from the OIDC backchannel logout request.
pub struct BackchannelLogoutInput {
    pub logout_token: String,
}

/// Verified OIDC logout identity used to locate authenticated sessions.
pub struct BackchannelLogoutIdentity {
    pub issuer: String,
    pub subject: Option<String>,
    pub oidc_session_id: Option<String>,
}

/// Transport-agnostic data that the physical layer can use
/// to observe the revocation result.
pub struct BackchannelLogoutOutput {
    pub revoked_session_count: usize,
}

/// Generic port that lets the pure logic stay decoupled from
/// concrete OIDC verifiers and session storage backends.
pub trait BackchannelLogoutPort {
    type Error;

    /// Verifies the OIDC backchannel logout token and extracts
    /// the issuer / subject / session identity used for revocation.
    fn verify_backchannel_logout(
        &self,
        input: &BackchannelLogoutInput,
    ) -> impl Future<Output = Result<BackchannelLogoutIdentity, Self::Error>>;

    /// Returns the current time used by the pure logic layer
    /// to stamp the revocation time of the affected sessions.
    fn current_time(&self) -> time::OffsetDateTime;

    /// Revokes all authenticated sessions matched by the verified
    /// backchannel logout identity, together with the explicit revocation
    /// time chosen by the logic layer.
    fn revoke_sessions(
        &self,
        identity: &BackchannelLogoutIdentity,
        revoked_at: time::OffsetDateTime,
    ) -> impl Future<Output = Result<BackchannelLogoutOutput, Self::Error>>;
}

/// Pure backchannel logout logic:
/// 1. verifies the logout token
/// 2. stamps the revocation time
/// 3. revokes matched authenticated sessions
/// 4. returns transport-agnostic output for the physical layer
pub async fn backchannel_logout<P>(
    port: &P,
    input: &BackchannelLogoutInput,
) -> Result<BackchannelLogoutOutput, P::Error>
where
    P: BackchannelLogoutPort,
{
    let identity = port.verify_backchannel_logout(input).await?;
    let revoked_at = port.current_time();

    port.revoke_sessions(&identity, revoked_at).await
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum TestError {
        Verify,
        Revoke,
    }

    struct RevokedSessions {
        issuer: String,
        subject: Option<String>,
        oidc_session_id: Option<String>,
        revoked_at: time::OffsetDateTime,
    }

    struct MockBackchannelLogoutPort {
        verify_results: test_support::Script<Result<BackchannelLogoutIdentity, TestError>>,
        clock: test_support::StubClock,
        revoke_results: test_support::Script<Result<BackchannelLogoutOutput, TestError>>,
        verify_backchannel_logout_calls: test_support::Counter,
        revoke_sessions_calls: test_support::Counter,
        verified_logout_tokens: test_support::Recordings<String>,
        revoked_sessions: test_support::Recordings<RevokedSessions>,
    }

    impl MockBackchannelLogoutPort {
        fn new<const VERIFY_N: usize, const TIME_N: usize, const REVOKE_N: usize>(
            verify_results: [Result<BackchannelLogoutIdentity, TestError>; VERIFY_N],
            current_times: [time::OffsetDateTime; TIME_N],
            revoke_results: [Result<BackchannelLogoutOutput, TestError>; REVOKE_N],
        ) -> Self {
            Self {
                verify_results: test_support::Script::new(verify_results),
                clock: test_support::StubClock::new(current_times),
                revoke_results: test_support::Script::new(revoke_results),
                verify_backchannel_logout_calls: test_support::Counter::new(),
                revoke_sessions_calls: test_support::Counter::new(),
                verified_logout_tokens: test_support::Recordings::new(),
                revoked_sessions: test_support::Recordings::new(),
            }
        }
    }

    impl BackchannelLogoutPort for MockBackchannelLogoutPort {
        type Error = TestError;

        fn verify_backchannel_logout(
            &self,
            input: &BackchannelLogoutInput,
        ) -> impl Future<Output = Result<BackchannelLogoutIdentity, Self::Error>> {
            self.verify_backchannel_logout_calls.increment();
            self.verified_logout_tokens.push(input.logout_token.clone());

            let result = self
                .verify_results
                .next("missing configured verify_backchannel_logout return value");

            async move { result }
        }

        fn current_time(&self) -> time::OffsetDateTime {
            self.clock.now()
        }

        fn revoke_sessions(
            &self,
            identity: &BackchannelLogoutIdentity,
            revoked_at: time::OffsetDateTime,
        ) -> impl Future<Output = Result<BackchannelLogoutOutput, Self::Error>> {
            self.revoke_sessions_calls.increment();
            self.revoked_sessions.push(RevokedSessions {
                issuer: identity.issuer.clone(),
                subject: identity.subject.clone(),
                oidc_session_id: identity.oidc_session_id.clone(),
                revoked_at,
            });

            let result = self
                .revoke_results
                .next("missing configured revoke_sessions return value");

            async move { result }
        }
    }

    #[test]
    fn backchannel_logout_returns_output_after_revoking_sessions() {
        let revoked_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_200).unwrap();
        let port = MockBackchannelLogoutPort::new(
            [ok_backchannel_logout_identity()],
            [revoked_at],
            [Ok(BackchannelLogoutOutput {
                revoked_session_count: 2,
            })],
        );
        let input = backchannel_logout_input();

        let output = test_support::block_on(backchannel_logout(&port, &input)).unwrap();

        assert_eq!(output.revoked_session_count, 2);
        assert_eq!(port.verify_backchannel_logout_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.revoke_sessions_calls.get(), 1);

        let verified = port.verified_logout_tokens.borrow();
        assert_eq!(verified.as_slice(), ["logout-token-123"]);

        let revoked = port.revoked_sessions.borrow();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].issuer, "https://issuer.example.com");
        assert_eq!(revoked[0].subject.as_deref(), Some("user-456"));
        assert_eq!(
            revoked[0].oidc_session_id.as_deref(),
            Some("oidc-session-321")
        );
        assert_eq!(revoked[0].revoked_at, revoked_at);
    }

    #[test]
    fn backchannel_logout_returns_verify_error_without_revoking_sessions() {
        let port = MockBackchannelLogoutPort::new([Err(TestError::Verify)], [], []);
        let input = backchannel_logout_input();

        let result = test_support::block_on(backchannel_logout(&port, &input));

        match result {
            Err(TestError::Verify) => {}
            Err(TestError::Revoke) => panic!("expected verify error, got revoke error"),
            Ok(_) => panic!("expected verify error, got success"),
        }
        assert_eq!(port.verify_backchannel_logout_calls.get(), 1);
        assert_eq!(port.clock.calls(), 0);
        assert_eq!(port.revoke_sessions_calls.get(), 0);
        assert!(port.revoked_sessions.is_empty());
    }

    #[test]
    fn backchannel_logout_returns_revoke_error_after_revocation_attempt() {
        let revoked_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_200).unwrap();
        let port = MockBackchannelLogoutPort::new(
            [ok_backchannel_logout_identity()],
            [revoked_at],
            [Err(TestError::Revoke)],
        );
        let input = backchannel_logout_input();

        let result = test_support::block_on(backchannel_logout(&port, &input));

        match result {
            Err(TestError::Revoke) => {}
            Err(TestError::Verify) => panic!("expected revoke error, got verify error"),
            Ok(_) => panic!("expected revoke error, got success"),
        }
        assert_eq!(port.verify_backchannel_logout_calls.get(), 1);
        assert_eq!(port.clock.calls(), 1);
        assert_eq!(port.revoke_sessions_calls.get(), 1);

        let revoked = port.revoked_sessions.borrow();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].revoked_at, revoked_at);
    }

    fn backchannel_logout_input() -> BackchannelLogoutInput {
        BackchannelLogoutInput {
            logout_token: "logout-token-123".to_owned(),
        }
    }

    fn ok_backchannel_logout_identity() -> Result<BackchannelLogoutIdentity, TestError> {
        Ok(BackchannelLogoutIdentity {
            issuer: "https://issuer.example.com".to_owned(),
            subject: Some("user-456".to_owned()),
            oidc_session_id: Some("oidc-session-321".to_owned()),
        })
    }
}
