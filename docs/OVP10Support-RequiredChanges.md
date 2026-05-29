# OVP 1.0 Support in Mimoto — Complete Required Changes

**Document version:** 1.0  
**Last updated:** May 2026  
**Project:** [mimoto](https://github.com/mosip/mimoto) (MOSIP Inji wallet backend)  
**Goal:** Support **OpenID4VP OVP spec v1.0 (DCQL)** while keeping **OpenID4VP draft-23 (Presentation Exchange)** working.

**Primary dependency:** [inji-openid4vp PR #174](https://github.com/inji/inji-openid4vp/pull/174) — ports OVP v1 from Swift to Kotlin; dual spec (`DRAFT_23`, `V1`).

**Current Mimoto dependency:** `io.inji:inji-openid4vp-jar:0.7.0` (PE / draft-23 only)

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Terminology and scope](#2-terminology-and-scope)
3. [What PR #174 changes in the library](#3-what-pr-174-changes-in-the-library)
4. [Current Mimoto state](#4-current-mimoto-state)
5. [Required Mimoto backend changes](#5-required-mimoto-backend-changes)
6. [API and DTO contract changes](#6-api-and-dto-contract-changes)
7. [UI / wallet client changes](#7-ui--wallet-client-changes)
8. [Configuration changes](#8-configuration-changes)
9. [Testing and Postman](#9-testing-and-postman)
10. [Implementation order](#10-implementation-order)
11. [File-by-file checklist](#11-file-by-file-checklist)
12. [Out of scope](#12-out-of-scope)
13. [References](#13-references)

---

## 1. Executive summary

Mimoto exposes wallet presentation APIs under `/wallets/{walletId}/presentations`. Verifiers send an **authorization request** (QR or deep link); the wallet authenticates the verifier, finds matching credentials, and submits a **VP token**.

| Spec | Verifier sends | Mimoto today |
|------|----------------|--------------|
| **draft-23** | `presentation_definition` / `_uri` (Presentation Exchange) | Supported via JAR 0.7.0 |
| **OVP v1** | `dcql_query` (DCQL) | **Not supported** |

To support OVP 1.0:

1. **Upgrade** `inji-openid4vp-jar` to a release containing PR #174.
2. **Detect spec version** per presentation session and branch PE vs DCQL.
3. **Extend APIs/DTOs** for grouped matching and structured submit (`credentialQueryId`).
4. **Migrate** VP construction/signing to new list-based, `byte[]` JAR APIs.
5. **Update** wallet clients (Inji Web) per [Section 7](#7-ui--wallet-client-changes).

**Note:** OpenID4VCI `draft-13` / `v1` (**credential issuance**) is already implemented separately (`Draft13VCDownloadHandler`, `V1VCDownloadHandler`). This document is about **presentation (OpenID4VP)** only.

---

## 2. Terminology and scope

| Term | Meaning |
|------|---------|
| **draft-23** | OpenID4VP with Presentation Exchange (`presentation_definition`, input descriptors) |
| **OVP v1 / v1** | OpenID4VP 1.0 final; uses **DCQL** (`dcql_query`) |
| **PE** | Presentation Exchange |
| **DCQL** | Digital Credentials Query Language — `credentials`, `credential_sets`, `claims`, `claim_sets` |
| **Legacy OVP** | `INJI_OVP://` flow via `GET /authorize` — custom Mimoto PE; **does not use** `inji-openid4vp-jar` |

---

## 3. What PR #174 changes in the library

Use this as the contract Mimoto must align with after upgrading the JAR.

### 3.1 Spec and routing

- `SpecVersion` enum: `DRAFT_23`, `V1`
- `ClientIdPrefix`: `pre-registered`, `redirect_uri`, `did` (replaces scheme-only handlers)
- Authorization request types:
  - `AuthorizationPresentationExchangeRequest` (draft-23 + PE)
  - `AuthorizationDcqlRequest` (v1 + DCQL)

### 3.2 DCQL

- Models: `DCQLQuery`, `CredentialQuery`, `ClaimsQuery`, `CredentialSetQuery`
- `DcqlEvaluator` — format, meta, claims matching
- `OpenID4VP.getMatchingCredentials()` — public matching API
- `CredentialToCredentialQueryIdMapping` on submit

### 3.3 VP token flow (breaking vs 0.7.0)

| Old (0.7.0) | New (PR #174) |
|-------------|---------------|
| `Map<FormatType, UnsignedVPToken>` | `List<UnsignedVPToken>` |
| `dataToSign` / `signedData` as `String` | `byte[]` |
| `sendVPResponseToVerifier(Map<...>)` | `sendVPResponseToVerifier(List<...>)` |
| PE-only `constructUnsignedVPToken` | Unified for PE and DCQL |
| `WalletMetadata` — LDP only | Version-aware `VPFormatSupported`; `client_id_prefixes_supported` |

### 3.4 Other

- `WalletConfig` — GET fallback, prefix fallback
- Spec-aware JWE / `direct_post.jwt`
- VP construct failure → `SERVER_ERROR` to verifier
- Validate selected credentials against DCQL query

---

## 4. Current Mimoto state

### 4.1 Presentation API flow

| Step | Method | Path | Handler |
|------|--------|------|---------|
| 1 | `POST` | `/wallets/{walletId}/presentations` | `WalletPresentationsController` → `WalletPresentationServiceImpl.handleVPAuthorizationRequest` |
| 2 | `GET` | `/wallets/{walletId}/presentations/{presentationId}/credentials` | `CredentialMatchingServiceImpl` |
| 3 | `PATCH` | `/wallets/{walletId}/presentations/{presentationId}` | Submit or reject |

### 4.2 Key classes today

| Class | Role | OVP v1 gap |
|-------|------|------------|
| `OpenID4VPService` | Creates `OpenID4VP`, `resolvePresentationDefinition()` only | No DCQL; metadata LDP-only |
| `WalletPresentationServiceImpl` | Auth, sign LDP, `sendVPResponseToVerifier(Map)` | Map API; no DCQL submit |
| `CredentialMatchingServiceImpl` | PE input descriptors → flat list | No DCQL evaluator |
| `VerifiablePresentationSessionData` | Session storage | No `specVersion` |
| `MatchingCredentialsResponseDTO` | Flat `availableCredentials` + `missingClaims` | Not grouped by query |
| `SubmitPresentationRequestDTO` | `List<String>` credential IDs | No `credentialQueryId` |

### 4.3 Current JAR usage snippet

`OpenID4VPService.create()`:

```java
WalletMetadata walletMetadata = new WalletMetadata();
walletMetadata.setVpFormatsSupported(
    Map.of(VPFormatType.LDP_VC, new VPFormatSupported(List.of("EEd25519Signature2020"))));
return new OpenID4VP(presentationId, walletMetadata);
```

`OpenID4VPService.resolvePresentationDefinition()` calls `authorizationRequest.getPresentationDefinition()` — **fails for DCQL requests**.

`WalletPresentationServiceImpl` uses:

- `openID4VP.constructUnsignedVPToken(verifiableCredentials, holderId, suite)` → `Map<FormatType, UnsignedVPToken>`
- `((UnsignedLdpVPToken) token).getDataToSign()` as `String`
- `openID4VP.sendVPResponseToVerifier(Map)`

### 4.4 Format support matrix (today)

| Format | PE matching | VP submit |
|--------|-------------|-----------|
| `ldp_vc` | Yes | Yes |
| `vc+sd-jwt` | Partial | **No** (throws) |
| `dc+sd-jwt` | Partial | **No** (throws) |
| mdoc | No | No |

---

## 5. Required Mimoto backend changes

### 5.1 Dependency upgrade

**File:** `pom.xml`

```xml
<dependency>
    <groupId>io.inji</groupId>
    <artifactId>inji-openid4vp-jar</artifactId>
    <version><!-- TBD: first release with PR #174 merged --></version>
</dependency>
```

Fix all compile errors from breaking JAR API changes across presentation packages.

---

### 5.2 `OpenID4VPService.java`

| # | Change | Details |
|---|--------|---------|
| 1 | **WalletMetadata** | Advertise `ldp_vc`, `vc+sd-jwt`, `dc+sd-jwt` (and mdoc if product requires) with correct algs/suites per `SpecVersion` |
| 2 | **WalletConfig** | Pass to `OpenID4VP` constructor if required by new JAR |
| 3 | **Spec detection helper** | After `authenticateVerifier()`, return `SpecVersion` and typed `AuthorizationRequest` |
| 4 | **Keep PE helper** | `resolvePresentationDefinition()` for draft-23 only |
| 5 | **Add DCQL helper** | Resolve `DCQLQuery` or delegate `getMatchingCredentials()` to JAR |
| 6 | **Error mapping** | Add `SERVER_ERROR` and any new codes in `openId4VPErrorException()` |

---

### 5.3 `VerifiablePresentationSessionData.java`

**Add:**

```java
private String specVersion;  // "draft-23" | "v1"
```

**Set in:** `WalletPresentationServiceImpl.handleVPAuthorizationRequest()` immediately after `authenticateVerifier()`.

**Optional:** cache minimal DCQL summary for UI (query ids, purposes) to avoid re-parsing.

---

### 5.4 `WalletPresentationServiceImpl.java`

| # | Change | Details |
|---|--------|---------|
| 1 | Store `specVersion` in session (via controller/session manager) | Branch all later steps |
| 2 | **Matching** | Delegate to PE or DCQL path in `CredentialMatchingService` |
| 3 | **`constructUnsignedVPToken`** | Use new list-based JAR API; pass `CredentialToCredentialQueryIdMapping` for v1 |
| 4 | **Signing** | Read `dataToSign` as `byte[]`; update detached JWT construction |
| 5 | **`sendVPResponseToVerifier`** | Pass `List<VPTokenSigningResult>` |
| 6 | **Submit validation** | For v1, validate selection against DCQL (JAR); return clear 400 errors |
| 7 | **SD-JWT / mdoc submit** | Implement via JAR builders (today only LDP in `signVPToken`) |
| 8 | **Reject flow** | Keep `sendErrorToVerifier`; ensure spec-aware JAR state |

**Remove or refactor:**

- `Map<FormatType, UnsignedVPToken>` / `Map<FormatType, LdpVPTokenSigningResult>` local types
- Hard-coded "Only ldp_vc format is supported" where product needs SD-JWT for v1 verifiers

---

### 5.5 `CredentialMatchingServiceImpl.java`

| Spec | Implementation |
|------|----------------|
| **draft-23** | Keep: `resolvePresentationDefinition()` → iterate `InputDescriptor` → flat `availableCredentials` (backward compatible) |
| **v1** | Call JAR `getMatchingCredentials()` or `DcqlEvaluator` with wallet credentials; build **grouped** `MatchingCredentialsResponseDTO` |

**DCQL response must include:**

- Per `credentialQueryId`: matching credentials, `missingClaims`, `purpose`, `format`
- Per `credentialSet`: `options` (OR branches), `required`, `purpose`

---

### 5.6 `WalletPresentationsController.java`

- No new endpoints required if DTOs are extended in place.
- Ensure session stores `specVersion` when creating `VerifiablePresentationSessionData`.
- Handle new validation errors (invalid DCQL selection, unsupported format).

---

### 5.7 `SessionManager` / session flow

- Persist `specVersion` with presentation session (Redis/HTTP session).
- No change to unlock/PIN flow.

---

### 5.8 New DTOs (recommended)

| DTO | Purpose |
|-----|---------|
| `CredentialQueryMatchDTO` | One DCQL query + its matching credentials |
| `CredentialSetDTO` | DCQL set with `options`, `required`, `purpose` |
| `SelectedCredentialDTO` | `credentialId` + `credentialQueryId` (+ optional `disclosures` for SD-JWT) |

Alternatively extend existing DTOs with optional fields (see [Section 6](#6-api-and-dto-contract-changes)).

---

### 5.9 `SwaggerLiteralConstants.java`

Update OpenAPI examples for:

- POST presentations (unchanged URL shape; document both PE and DCQL auth URLs)
- GET credentials — v1 grouped response example
- PATCH submit — v1 structured `selectedCredentials` example

---

## 6. API and DTO contract changes

### 6.1 Step 1 — `POST /wallets/{walletId}/presentations`

**Request (unchanged):**

```json
{
  "authorizationRequestUrl": "<url-encoded OpenID4VP authorization request>"
}
```

**Response — add optional field:**

```json
{
  "presentationId": "uuid",
  "specVersion": "draft-23",
  "verifier": {
    "id": "mock-client",
    "name": "Verifier name",
    "logo": "https://...",
    "isTrusted": true,
    "isPreregisteredWithWallet": true,
    "redirectUri": "https://..."
  }
}
```

For v1: `"specVersion": "v1"`.

---

### 6.2 Step 2 — `GET .../presentations/{presentationId}/credentials`

#### draft-23 (backward compatible)

```json
{
  "specVersion": "draft-23",
  "availableCredentials": [
    {
      "credentialId": "cred-123",
      "credentialTypeDisplayName": "MOSIP ID",
      "credentialTypeLogo": "https://...",
      "format": "ldp_vc",
      "claims": ["name", "birthdate"],
      "sdClaims": []
    }
  ],
  "missingClaims": ["birthdate"]
}
```

#### OVP v1 (new shape)

```json
{
  "specVersion": "v1",
  "credentialQueries": [
    {
      "id": "identity_verification",
      "purpose": "Prove your identity",
      "format": "vc+sd-jwt",
      "matchingCredentials": [
        {
          "credentialId": "cred-123",
          "credentialTypeDisplayName": "MOSIP ID",
          "credentialTypeLogo": "https://...",
          "format": "vc+sd-jwt",
          "claims": ["given_name"],
          "sdClaims": ["family_name", "birthdate"]
        }
      ],
      "missingClaims": []
    }
  ],
  "credentialSets": [
    {
      "purpose": "Proof of address",
      "required": true,
      "options": [
        {
          "label": "Utility bill OR bank statement",
          "queryIds": ["utility_query", "bank_query"]
        }
      ]
    }
  ],
  "missingClaims": []
}
```

**UI rule:** If `credentialQueries` is present, use grouped picker; else use flat `availableCredentials`.

---

### 6.3 Step 3 — `PATCH .../presentations/{presentationId}`

#### Submit — draft-23 (backward compatible)

```json
{
  "selectedCredentials": ["cred-123", "cred-456"]
}
```

#### Submit — OVP v1

```json
{
  "selectedCredentials": [
    {
      "credentialId": "cred-123",
      "credentialQueryId": "identity_verification"
    },
    {
      "credentialId": "cred-456",
      "credentialQueryId": "utility_query"
    }
  ]
}
```

**Optional future (SD-JWT):**

```json
{
  "selectedCredentials": [
    {
      "credentialId": "cred-123",
      "credentialQueryId": "identity_verification",
      "disclosures": ["$.family_name", "$.birthdate"]
    }
  ]
}
```

#### Reject (unchanged)

```json
{
  "errorCode": "access_denied",
  "errorMessage": "User denied authorization to share credentials"
}
```

---

### 6.4 Java DTO changes summary

| File | Changes |
|------|---------|
| `MatchingCredentialsResponseDTO` | Add `specVersion`, `credentialQueries`, `credentialSets`; keep `availableCredentials` + `missingClaims` for draft-23 |
| `SubmitPresentationRequestDTO` | Support `List<String>` OR `List<SelectedCredentialDTO>` (or union type with validation) |
| `VPResponseDTO` | Add optional `specVersion` |
| `CredentialDTO` | No change required; reuse in nested lists |
| `VerifiablePresentationSessionData` | Add `specVersion` |

---

## 7. UI / wallet client changes

Mimoto does not include the wallet UI; **Inji Web** (or mobile) must update when Mimoto deploys v1 APIs.

| Area | draft-23 | OVP v1 |
|------|----------|--------|
| QR / deep link | `presentation_definition*` in URL | `dcql_query` in URL — same POST API |
| Consent screen | Verifier info | Same; show DCQL `purpose` if returned |
| Credential picker | Flat list | Sections per `credentialQueryId`; credential sets (AND/OR) |
| Claim disclosure | `claims` / `sdClaims` | Same + DCQL `claim_sets` (pick one of) |
| Submit | `string[]` IDs | `{ credentialId, credentialQueryId }[]` |
| Deny / redirect | Unchanged | Unchanged |

**Feature detection:**

```javascript
if (response.specVersion === 'v1' || response.credentialQueries) {
  renderDcqlPicker(response);
} else {
  renderPePicker(response);  // current behavior
}
```

---

## 8. Configuration changes

### 8.1 `mimoto-trusted-verifiers.json`

- Align `client_id` with **prefix** format expected by PR #174 (`pre-registered:...`, `redirect_uri:...`, `did:...`) where verifiers use v1.
- draft-23 verifiers may keep existing ids if JAR supports both.

### 8.2 `application-default.properties` / `application-local.properties`

Optional new properties (examples):

```properties
# Supported VP formats advertised to verifiers (if not hardcoded)
mosip.openid4vp.wallet.formats.supported=ldp_vc,vc+sd-jwt,dc+sd-jwt
```

### 8.3 `mimoto-issuers-config.json`

**No change** for OVP 1.0 presentation (issuance config only).

---

## 9. Testing and Postman

### 9.1 Unit / integration tests

| Test class | Add / update |
|------------|----------------|
| `OpenID4VPService` (new or existing) | Spec detection, metadata |
| `CredentialMatchingServiceImpl` | PE regression; DCQL fixtures |
| `WalletPresentationServiceImpl` | List VP API, byte[] signing, DCQL submit |
| `WalletPresentationsController` | v1 response shapes |

### 9.2 Manual / Postman

**File:** `docs/postman-collections/MIMOTO.postman_collection.json`

- Add folder: **Wallet Presentations — OVP v1 (DCQL)**
- Sample auth URL with `dcql_query`
- GET credentials — assert grouped response
- PATCH submit — structured `selectedCredentials`

### 9.3 QA scenarios

| # | Scenario | Expected |
|---|----------|----------|
| 1 | PE verifier (Inji Verify) | Flat credentials; submit with ID strings |
| 2 | DCQL single query | One section; one selection |
| 3 | DCQL multiple queries | Multiple sections |
| 4 | DCQL credential set (OR) | User picks one branch |
| 5 | Required + optional set | Optional skippable if `required: false` |
| 6 | No match | Per-query empty state |
| 7 | SD-JWT with sdClaims | Disclosure UI; submit when backend ready |
| 8 | User deny | Error to verifier |
| 9 | Untrusted verifier | Trust warning unchanged |

---

## 10. Implementation order

| Phase | Task | Owner hint |
|-------|------|------------|
| **0** | Wait for / publish `inji-openid4vp-jar` with PR #174 | Platform |
| **1** | Bump `pom.xml`; fix compile (imports, list APIs, byte[]) | Backend |
| **2** | `specVersion` in session + `VPResponseDTO` | Backend |
| **3** | PE path regression on new JAR (matching + LDP submit) | Backend |
| **4** | DCQL matching + extended `MatchingCredentialsResponseDTO` | Backend |
| **5** | DCQL submit + `SubmitPresentationRequestDTO` | Backend |
| **6** | WalletMetadata + trusted verifiers config | Backend / DevOps |
| **7** | SD-JWT (and mdoc if needed) submit | Backend |
| **8** | Swagger + Postman + tests | Backend / QA |
| **9** | Inji Web UI grouped picker + structured submit | Frontend |

---

## 11. File-by-file checklist

| File | Action |
|------|--------|
| `pom.xml` | Bump `inji-openid4vp-jar` version |
| `OpenID4VPService.java` | Metadata, WalletConfig, spec helpers, DCQL delegate, errors |
| `VerifiablePresentationSessionData.java` | Add `specVersion` |
| `WalletPresentationServiceImpl.java` | List VP APIs, byte[] signing, DCQL branch, SD-JWT submit |
| `CredentialMatchingServiceImpl.java` | PE + DCQL branches |
| `WalletPresentationsController.java` | Session specVersion; error handling |
| `MatchingCredentialsResponseDTO.java` | v1 fields |
| `SubmitPresentationRequestDTO.java` | Structured selection |
| `VPResponseDTO.java` | Optional `specVersion` |
| `CredentialQueryMatchDTO.java` | **New** (recommended) |
| `CredentialSetDTO.java` | **New** (recommended) |
| `SelectedCredentialDTO.java` | **New** (recommended) |
| `SwaggerLiteralConstants.java` | Updated examples |
| `mimoto-trusted-verifiers.json` | Prefix-compatible `client_id` |
| `application-default.properties` | Optional wallet format props |
| `src/test/java/.../WalletPresentation*` | PE + DCQL tests |
| `src/test/java/.../CredentialMatching*` | DCQL fixtures |
| `docs/postman-collections/MIMOTO.postman_collection.json` | DCQL examples |
| `docs/OVP10Support-RequiredChanges.md` | This document |

**No change:**

| File | Reason |
|------|--------|
| `Draft13VCDownloadHandler.java` | VCI issuance |
| `V1VCDownloadHandler.java` | VCI issuance |
| `PresentationController.java` | Legacy INJI_OVP QR |
| `PresentationServiceImpl.java` | Legacy INJI_OVP QR |
| `mimoto-issuers-config.json` | VCI issuers only |

---

## 12. Out of scope

- Legacy `INJI_OVP://` PDF QR presentation (`/authorize`)
- OpenID4VCI draft-13 / v1 issuance (already done — see `docs/VCIssuanceV1SpecificationSupport.md`)
- Verifier-side DCQL construction (Inji Verify / other verifier products)
- Publishing the Kotlin JAR (dependency on inji-openid4vp release process)

---

## 13. References

| Resource | URL |
|----------|-----|
| OpenID4VP 1.0 spec | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| inji-openid4vp PR #174 | https://github.com/inji/inji-openid4vp/pull/174 |
| Mimoto VCI v1 guide (parallel pattern) | `docs/VCIssuanceV1SpecificationSupport.md` |
| Mimoto presentation controller | `WalletPresentationsController.java` |
| Mimoto Postman | `docs/postman-collections/MIMOTO.postman_collection.json` |
| DCQL overview | https://vidos.id/docs/explanations/standards/oidf/dcql/ |

---

## Appendix A — Architecture

```
                    Verifier Authorization Request
                    (PE: presentation_definition)
                    (v1: dcql_query)
                              │
                              ▼
              ┌───────────────────────────────┐
              │  WalletPresentationsController │
              └───────────────┬───────────────┘
                              ▼
              ┌───────────────────────────────┐
              │ WalletPresentationServiceImpl  │
              │  • OpenID4VP.authenticateVerifier│
              │  • detect SpecVersion → session  │
              └───────────────┬───────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
     specVersion=draft-23                specVersion=v1
            │                                   │
            ▼                                   ▼
 CredentialMatchingServiceImpl      CredentialMatchingServiceImpl
 (PE: InputDescriptor)               (DCQL: JAR evaluator)
            │                                   │
            └─────────────────┬─────────────────┘
                              ▼
              constructUnsignedVPToken (JAR, List)
                              ▼
                    Sign (LDP / SD-JWT / …)
                              ▼
              sendVPResponseToVerifier (JAR, List)
```

---

## Appendix B — Mapping to inji-openid4vp PR #174

| PR #174 area | Mimoto touchpoint |
|--------------|-------------------|
| `SpecVersion`, `ClientIdPrefix` | `OpenID4VPService`, session, trusted verifiers |
| `AuthorizationDcqlRequest` | `CredentialMatchingServiceImpl`, session |
| `DcqlEvaluator`, `getMatchingCredentials` | `CredentialMatchingServiceImpl` |
| List `UnsignedVPToken` / `byte[]` | `WalletPresentationServiceImpl` |
| `CredentialToCredentialQueryIdMapping` | `SubmitPresentationRequestDTO` → submit |
| `WalletMetadata`, `WalletConfig` | `OpenID4VPService.create()` |
| `AuthorizationResponse` sealed PE/Dcql | Transparent in JAR; Mimoto uses `sendVPResponseToVerifier` |

---

*End of document — single source of truth for OVP 1.0 work in Mimoto.*
