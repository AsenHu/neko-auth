use std::net::{IpAddr, Ipv4Addr};

use crate::types::{
    CfBotManagement, CfJsDetection, CfProperties, CfRequestPriority, CfTlsClientAuth,
    RequestContext,
};

pub fn from_worker_request(req: &worker::Request) -> RequestContext {
    let ip = req
        .headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .or_else(|| req.headers().get("X-Forwarded-For").ok().flatten())
        .and_then(|raw| raw.split(',').next().map(str::trim).map(str::to_string))
        .and_then(|raw| raw.parse::<IpAddr>().ok())
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    RequestContext {
        ip,
        cf: req.cf().map(extract_cf).unwrap_or_default(),
    }
}

pub fn user_agent(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

pub fn trace_id(headers: &worker::Headers) -> String {
    headers.get("CF-Ray").ok().flatten().unwrap_or_default()
}

fn extract_cf(cf: &worker::Cf) -> CfProperties {
    let request_priority = cf.request_priority().map(|p| CfRequestPriority {
        weight: p.weight,
        exclusive: p.exclusive,
        group: p.group,
        group_weight: p.group_weight,
    });
    let (latitude, longitude) = cf
        .coordinates()
        .map(|(lat, lon)| (Some(lat.to_string()), Some(lon.to_string())))
        .unwrap_or((None, None));

    CfProperties {
        bot_management: cf.bot_management().map(|bot| CfBotManagement {
            score: bot.score(),
            verified_bot: bot.verified_bot(),
            corporate_proxy: bot.corporate_proxy(),
            static_resource: bot.static_resource(),
            ja3_hash: bot.ja3_hash(),
            ja4: bot.ja4(),
            js_detection: bot
                .js_detection()
                .map(|d| CfJsDetection { passed: d.passed() }),
            detection_ids: bot.detection_ids(),
        }),
        verified_bot_category: cf.verified_bot_category(),
        colo: Some(cf.colo()),
        asn: cf.asn(),
        as_organization: cf.as_organization(),
        country: cf.country(),
        http_protocol: Some(cf.http_protocol()),
        request_priority,
        tls_cipher: Some(cf.tls_cipher()),
        tls_client_auth: cf.tls_client_auth().map(|tls| CfTlsClientAuth {
            cert_issuer_dn_legacy: tls.cert_issuer_dn_legacy(),
            cert_issuer_dn: tls.cert_issuer_dn(),
            cert_issuer_dn_rfc2253: tls.cert_issuer_dn_rfc2253(),
            cert_subject_dn_legacy: tls.cert_subject_dn_legacy(),
            cert_verified: tls.cert_verified(),
            cert_not_after: tls.cert_not_after(),
            cert_subject_dn: tls.cert_subject_dn(),
            cert_fingerprint_sha1: tls.cert_fingerprint_sha1(),
            cert_fingerprint_sha256: tls.cert_fingerprint_sha256(),
            cert_not_before: tls.cert_not_before(),
            cert_serial: tls.cert_serial(),
            cert_presented: tls.cert_presented(),
            cert_subject_dn_rfc2253: tls.cert_subject_dn_rfc2253(),
        }),
        tls_version: Some(cf.tls_version()),
        city: cf.city(),
        continent: cf.continent(),
        latitude,
        longitude,
        postal_code: cf.postal_code(),
        metro_code: cf.metro_code(),
        region: cf.region(),
        region_code: cf.region_code(),
        timezone: Some(cf.timezone_name()),
        is_eu_country: Some(cf.is_eu_country()),
    }
}
