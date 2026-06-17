# Mimoto Spike: OpenID4VP 0.8.0 (Draft23 + OVP 1.0/DCQL)

## Context

Mimoto currently uses `io.inji:inji-openid4vp-jar:0.7.0-SNAPSHOT-myLocal` and is implemented against the older OpenID4VP entry points and Presentation Definition-centric flow.

Your target plan is:

1. First, move Mimoto to the new 0.8.0-style library behavior (using your local jar) and make Draft23 flow work through the migrated API surface.
2. Then add OpenID4VP 1.0 + DCQL support.

This document captures all required changes identified from:

- VP Request with DCQL Query spike notes
- OpenID4VP Version Support for V1.0 notes
- Migration Guide `inji-openid4vp 0.7.0 -> 0.8.0`
- Current Mimoto codebase analysis

## Current State (Codebase Findings)

## Dependency and API coupling

- `pom.xml` currently pins `inji-openid4vp-jar` to `0.7.0-SNAPSHOT-myLocal`.
- `OpenID4VPService` creates OVP with `new OpenID4VP(traceabilityId, WalletMetadata)`.
- `OpenID4VPService` and `WalletPresentationServiceImpl` call `authenticateVerifier(authRequest, preRegisteredVerifiers, shouldValidateClient)`.
- VP generation still uses old method shape:
  - `constructUnsignedVPToken(verifiableCredentials, holderId, signatureSuite)`
  - `sendVPResponseToVerifier(Map<FormatType, VPTokenSigningResult>)`

## Matching and submit contract is Presentation Definition based

- `CredentialMatchingServiceImpl` reads `AuthorizationRequest.getPresentationDefinition()` and does custom descriptor/constraints matching.
- `SubmitPresentationRequestDTO` carries only `selectedCredentials: List<String>`.
- This request shape is insufficient for DCQL, where query-aware mapping and claim-level selection are required.

## Scope impact is broad (service + DTO + API docs + tests)

- Affected service path:
  - `OpenID4VPService`
  - `WalletPresentationServiceImpl`
  - `CredentialMatchingServiceImpl`
  - `WalletPresentationsController`
- Affected DTOs:
  - `SubmitPresentationRequestDTO`
  - `MatchingCredentialsResponseDTO` / `CredentialDTO` response model expectations
  - session payload in `VerifiablePresentationSessionData`
- Affected tests are significant:
  - `OpenID4VPServiceTest`
  - `WalletPresentationServiceTest`
  - `CredentialMatchingServiceTest`
  - `WalletPresentationsControllerTest`
- Swagger examples/constants in `SwaggerLiteralConstants` are currently presentation-definition-oriented.

## Required Changes

## Phase 0: Dependency and baseline migration guardrails

1. **Upgrade dependency to OVP 0.8.0-compatible local jar**
   - Keep temporary local jar strategy (until official 0.8.0 release).
   - Prefer one dedicated property in `pom.xml` for easier swap to official release.
2. **Support both specs without a feature toggle**
   - Mimoto must support Draft23 and OVP 1.0/DCQL at the same time.
   - Route automatically based on authorization request structure/version detection.
3. **Define migration baseline branch**
   - Separate commits/PR sections for:
     - API migration (0.7 -> 0.8 shape changes)
     - Draft23 compatibility
     - OVP 1.0/DCQL enablement

## Phase 1: Migrate to 0.8.0 API shape (Draft23 support intact)

### 1) OpenID4VP initialization changes

- Replace `WalletMetadata` constructor usage with `WalletConfig`.
- Move trusted verifiers/capabilities into `WalletConfig`.
- Update `OpenID4VPService.create(...)` accordingly.

### 2) Authenticate flow changes

- Update calls to `authenticateVerifier(url)` — 1 arg only.
- Pass `trustedVerifiers` and `validatePreRegisteredVerifier` (was `shouldValidateClient`) into `WalletConfig` at `create()` time.
- Ensure `shouldValidateClient` behaviour remains unchanged in Mimoto contract: compute before `create()`, store in session, replay on later flows.

### 3) VP construction and submission changes

- Replace old `constructUnsignedVPToken(...)` call with:
  - `constructUnsignedVPToken(selectedCredentials: Map<String, List<Credential>>)`
- Update signing pipeline to consume `List<UnsignedVPToken>` and produce `List<VPTokenSigningResult>`.
- Update `sendVPResponseToVerifier(...)` to list-based input expected by 0.8.0.

### 4) Holder/signature handling adjustments

- Remove old holderId/signatureSuite plumbing where no longer needed by entry point.
- Keep detached JWS proof handling only where format-specific signing still requires it.
- Validate format support assumptions (currently mostly `LDP_VC` path in service logic).

## Phase 2: Add OVP 1.0 + DCQL support

### 1) Version detection strategy

Implement and persist request version determination:

- If `dcql_query` exists -> treat as OVP 1.0/DCQL path.
- If only `presentation_definition`/scope path -> Draft23 path.
- For `request_uri` and pre-registered clients, use trusted verifier metadata/client prefix logic.
- Persist detected spec version in session DTO `VerifiablePresentationSessionData` and reuse it across subsequent calls in the same presentation transaction.

### 2) Metadata and naming updates (spec alignment)

> **Library verification note:** The following items from this section are handled
> entirely inside `inji-openid4vp`. No mimoto code changes are needed for them.
> Confirmed by reading library source at `E:\Mosip\inji-openid4vp`.

- ~~Support `vp_formats_supported` changes for 1.0 structures.~~
  → Handled by library: `ClientMetadata.kt` (V1) and `ClientMetadataDraft23.kt` (Draft23) parse this field internally.

- ~~Update client ID terminology: `client_id_schemes_supported` → `client_id_prefixes_supported`~~
  → Handled by library: `WalletConfig.clientIdPrefixesSupported` feeds into library validation. `WalletConfigDefaults.kt` includes `PRE_REGISTERED`, `REDIRECT_URI`, `DECENTRALIZED_IDENTIFIER` by default.

- ~~`decentralized_identifier:` handling~~
  → Handled by library: `DecentralizedIdentifierPrefixAuthorizationRequestHandler.kt` exists in library.

- ~~Enforce request object `typ = oauth-authz-req+jwt`~~
  → Handled by library: `ClientIdPrefixBasedAuthorizationRequestHandler.kt` line 309 validates this.

### 3) DCQL matching integration

Current Mimoto matching logic is manual + Presentation Definition-only. For DCQL:

- **Use library helper `DCQLHelper.getMatchingCredentials(inputCredentials, dcqlQuery)`** for DCQL requests.
  - Class: `io.mosip.openID4VP.evaluator.dcql.DCQLHelper` — confirmed exists in library.
  - Input: `List<Credential>` (all wallet VCs) + `DCQLQuery` (from `AuthorizationDcqlRequest.getDcqlQuery()`).
  - Output: `MatchingCredentialsResult`:
    - `success: Boolean` — overall satisfaction
    - `queryMatches: Map<queryId, QueryMatchResult>` — per query:
      - `matchingCredentials: List<MatchingCredential>?` — each has `credentialId`, `matchingClaims`
      - `failedClaims: List<ClaimFailure>?`
      - `allowMultipleCredentials: Boolean`
    - `credentialSets: List<CredentialSetQuery>`
  - The library handles internally: format matching, meta matching, cryptographic holder binding, claim path matching, claimSets, credentialSets satisfaction.
  - **Mimoto does NOT need to write manual DCQL matching code.**
- Keep existing manual matching for legacy Presentation Definition requests (Draft23 path unchanged).
- Mimoto's job for DCQL: call `DCQLHelper.getMatchingCredentials()`, then map `MatchingCredentialsResult` to mimoto's `DcqlQueryGroup` response DTOs for the UI.

### 4) API contract changes for credential selection

`SubmitPresentationRequestDTO` currently only accepts `List<String> selectedCredentials`, which is not enough for DCQL.

Required evolution:

- Add query-aware selected credentials payload (queryId -> selected credential entries).
- Include selected claim groups/paths where needed.
- Preserve backward compatibility with current list-based payload during transition window.

### 5) VP response mapping for DCQL

- Ensure VP token response construction maps by credential query id for DCQL.
- Enforce mandatory query/credential set rules:
  - no partial response for mandatory constraints
  - enforce `multiple=false` rules
  - exclude optional query entries with no match

### 6) Error behavior alignment

- Map invalid combinations to OpenID4VP-compliant `invalid_request` / `access_denied` / `invalid_transaction_data` scenarios.
- Add explicit error mapping for:
  - ~~both `dcql_query` and `scope` present~~ → Handled by library: `DCQLUtil.kt` throws `InvalidData` when both are present. Mimoto catches `OpenID4VPExceptions` from `authenticateVerifier()`.
  - ~~missing `dcql_query`/scope for `vp_token`~~ → Handled by library during request validation.
  - client id prefix validation failures → Handled by library. Mimoto catches `OpenID4VPExceptions.InvalidVerifier`.
- Mimoto's actual responsibility: catch `OpenID4VPExceptions` thrown by `authenticateVerifier()` and map to HTTP error responses (already done in `WalletPresentationsController`).

## Method-level implementation map (DCQL + OVP 1.0)

### 1) `OpenID4VPService`

- Update `create(String presentationId, List<Verifier> trustedVerifiers)` to construct `WalletConfig` with v1-compatible defaults and trusted verifiers.
- Add/confirm helper to resolve request spec version from `AuthorizationRequest` type:
  - `AuthorizationDcqlRequest` -> `V1_0`
  - `AuthorizationPresentationExchangeRequest` -> `DRAFT23`
- Keep `resolvePresentationDefinition(...)` only for Draft23 path.
- Add DCQL extractor helper for v1 flow if needed by matching service:
  - expected output: `DcqlQuery` or JSON map to pass into library/helper.

### 2) `WalletPresentationServiceImpl`

- In `handleVPAuthorizationRequest(...)`:
  - authenticate verifier once
  - detect spec version from authorization request type
  - persist spec version into `VerifiablePresentationSessionData`.
- In `submitPresentation(...)`:
  - branch by spec version from session
  - Draft23: existing Presentation Definition selection path
  - V1_0: query-aware/DCQL selection path
- Keep `constructUnsignedVPToken(...)` aligned to 0.8 API:
  - input `Map<String, List<Credential>>`
  - output `List<UnsignedVPToken>`.
- Keep `signVPToken(...)` aligned to 0.8 signing contract:
  - sign `UnsignedVPToken.getDataToSign()`
  - return raw signature bytes in `VPTokenSigningResult`.
- Ensure final submission uses:
  - `sendVPResponseToVerifier(List<VPTokenSigningResult>)`.

### 3) `CredentialMatchingServiceImpl`

- Add top-level branch:
  - `DRAFT23` -> existing descriptor/constraint matching
  - `V1_0` -> DCQL matching path.
- Implement V1_0/DCQL matching via library helper:
  - call `getMatchingCredentials(...)`
  - map results to wallet response DTO with query grouping, required flags, multiple flags, and claim options.
- Add validation before submit:
  - enforce mandatory credential queries/sets
  - enforce `multiple=false`
  - reject missing mandatory claims/queries.

### 4) DTOs and request/response contract

- `VerifiablePresentationSessionData`:
  - add `specVersion` field (enum preferred: `DRAFT23`, `V1_0`).
- `SubmitPresentationRequestDTO`:
  - keep backward compatibility for `selectedCredentials: List<String>` (Draft23)
  - add v1/DCQL structure for query-aware selection (queryId + selected credentials + selected claim group/claim path where applicable).
- Matching response DTO:
  - add query-centric response fields for DCQL (`credentialQueryId`, `required`, `multiple`, `matchingClaims`, `credentialSets` options).

## Phase 3: Controller, DTO, and API documentation changes

1. **Controller updates**
   - `WalletPresentationsController` endpoints must support both flow families:
     - Draft23 Presentation Definition
     - OVP 1.0 DCQL
2. **DTO updates**
   - Add spec version field to `VerifiablePresentationSessionData` (session context for flow routing and validation).
   - Add DCQL-aware matching response DTOs (or augment existing ones).
   - Add DCQL-aware submit payload schema.
3. **Swagger examples**
   - Update `SwaggerLiteralConstants` examples for:
     - request examples containing `dcql_query`
     - matching response showing credential_sets/options and query mapping
     - submit payload with query-aware selected credential mapping

## Phase 4: Tests and quality gates

## Unit tests

- Refactor all tests mocking old OVP signatures.
- Add dedicated test classes for version branching:
  - Draft23 path tests
  - OVP 1.0/DCQL path tests

## Integration tests

- Add test vectors for:
  - required vs optional credential_sets
  - same credential satisfying multiple queries
  - `multiple=true/false` enforcement
  - claim_sets priority handling
  - missing mandatory claims/queries -> reject flow

## Regression tests

- Keep existing Draft23 behavior green.
- Verify no regressions in verifier rejection/error path (`sendErrorInfoToVerifier` flow).

## Risks and Mitigations

- **Risk: API breakage due to local unpublished jar**
  - Mitigation: isolate library usage in `OpenID4VPService` adapter-style methods.
- **Risk: DTO/API contract churn affecting UI**
  - Mitigation: backward-compatible request parsing during transition.
- **Risk: Incorrect behavior for mixed verifier ecosystems**
  - Mitigation: strict version detection + dual-path tests.
- **Risk: Large test refactor effort**
  - Mitigation: stage migration and lock regression suite at each PR.

## Out of Scope (for this spike)

- DC API profile features (multi-signed protocol, expected_origins handling) unless explicitly requested.
- Wallet UI redesign decisions beyond backend payload support.
- Non-OVP protocol enhancements unrelated to VP flow migration.

## Approval Checklist

- [ ] Approve local 0.8.0 jar usage until official release.
- [ ] Approve staged rollout in 5 PRs.
- [ ] Approve backward-compatible request contract during migration.
- [ ] Approve dual support target: Draft23 + OVP 1.0/DCQL.
- [ ] Approve added integration tests for DCQL constraints before production rollout.

