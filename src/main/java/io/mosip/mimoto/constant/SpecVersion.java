package io.mosip.mimoto.constant;

/**
 * Identifies which OpenID4VP specification version a verifier's authorization
 * request targets.
 *
 * <ul>
 *   <li>{@link #DRAFT_23} — request contains a {@code presentation_definition}</li>
 *   <li>{@link #V1_0}     — request contains a {@code dcql_query}</li>
 * </ul>
 *
 * The value is detected once during {@code handleVPAuthorizationRequest} and stored
 * in the session so every subsequent call in the same presentation transaction uses
 * the same routing path.
 */
public enum SpecVersion {

    /** OpenID4VP Draft 23 — Presentation Exchange / presentation_definition. */
    DRAFT_23,

    /** OpenID4VP Version 1.0 — DCQL / dcql_query. */
    V1_0
}
