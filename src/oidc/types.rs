/// Pure OIDC authorization state that must be persisted before handing
/// control to the upstream identity provider and later consumed by the callback.
pub struct AuthorizeState {
    pub csrf_token: String,
    pub pkce_verifier: String,
    pub nonce: String,
}
