# OpenID4VP 0.8.0 — Full Migration Plan (Draft-23 + OVP 1.0 / DCQL)

> This is the single source of truth for the `inji-openid4vp-jar` 0.7.0 → 0.8.0
> upgrade in mimoto. It covers **every affected file**, **before/after flowcharts**
> for each stage of the VP flow, and **new method implementations** for both
> Draft-23 and OVP 1.0 / DCQL simultaneously.

---

## 1. High-Level Strategy

```
Both spec versions (Draft-23 and OVP 1.0) will be supported at the same time.
The library auto-detects the spec version from the authorization request structure.
Mimoto routes internally based on the returned AuthorizationRequest subtype.

  Verifier sends request
         │
         ▼
  authenticateVerifier()
         │
         ├─ AuthorizationPresentationExchangeRequest  →  Draft-23 path
         │         (has presentation_definition)
         │
         └─ AuthorizationDcqlRequest                  →  OVP 1.0 / DCQL path
                   (has dcql_query)
```

---

## 2. Library API Changes: 0.7.0 → 0.8.0

> **Library update (from inji-openid4vp team):** `WalletConfig` now also accepts `validatePreRegisteredVerifier`.
> This flag was previously the second argument to `authenticateVerifier()` (`shouldValidateClient`).
> Mimoto must compute it **before** `create()` and pass it into `WalletConfig`; `authenticateVerifier(url)` becomes a **1-arg** call.

| # | What changed | Old (0.7.0) | New (0.8.0) |
|---|--------------|-------------|-------------|
| 1 | OVP constructor | `OpenID4VP(id, WalletMetadata)` | `OpenID4VP(id, WalletConfig)` |
| 2 | Trusted verifiers | Passed per-call in `authenticateVerifier()` | Declared once inside `WalletConfig` |
| 3 | Pre-registered verifier validation | `authenticateVerifier(url, trustedVerifiers, shouldValidateClient)` — 3 args | `validatePreRegisteredVerifier` inside `WalletConfig` at `create()` time |
| 4 | `authenticateVerifier` URL overload | `(url, trustedVerifiers, validate)` — 3 args | `(url)` — **1 arg** (validation flag read from `WalletConfig`) |
| 5 | `constructUnsignedVPToken` input | `Map<String, Map<FormatType, List<Object>>>` + holderId + suite | `Map<descriptorId/queryId, List<Credential>>` — map key is the query id |
| 6 | `constructUnsignedVPToken` output | Opaque encoded map | `List<UnsignedVPToken>` — each has `dataToSign`, `signatureAlgorithm`, `format` |
| 7 | `sendVPResponseToVerifier` input | `Map<FormatType, VPTokenSigningResult>` | `List<VPTokenSigningResult>` |
| 8 | `Credential` class | Different structure | `io.mosip.openID4VP.wallet.Credential(format, data, credentialId)` |
| 9 | Request subtypes | Single `AuthorizationRequest` | `AuthorizationPresentationExchangeRequest` or `AuthorizationDcqlRequest` |
| 10 | DCQL query type | Not available | `AuthorizationDcqlRequest.getDcqlQuery()` returns `DCQLQuery` |

---

## 3. New Library Classes (Quick Reference)

```
WalletConfig
├── vpFormatsSupported: Map<VPFormatType, VPFormatSupported>
├── clientIdPrefixesSupported: List<ClientIdPrefix>   ← replaces "schemes"
├── requestObjectSigningAlgValuesSupported: List?
├── authorizationEncryptionAlgValuesSupported: List?
├── authorizationEncryptionEncValuesSupported: List?
├── responseTypesSupported: List<ResponseType>
├── isPresentationDefinitionUriSupported: Boolean
├── supportedRequestUriMethods: List<RequestUriMethod>
├── trustedVerifiers: List<Verifier>                  ← moved here (was authenticateVerifier arg)
└── validatePreRegisteredVerifier: Boolean            ← moved here (was shouldValidateClient arg)

UnsignedVPToken
├── format: FormatType
├── holderKeyReference: String
├── signatureAlgorithm: String                        ← e.g. "EdDSA"
└── dataToSign: ByteArray                             ← raw bytes to sign

VPTokenSigningResult
└── signedData: ByteArray                             ← raw signature bytes

Credential  (io.mosip.openID4VP.wallet.Credential)
├── format: FormatType
├── data: Any                                         ← VC payload object
└── credentialId: String

AuthorizationDcqlRequest extends AuthorizationRequest
└── dcqlQuery: DCQLQuery
      ├── credentials: List<CredentialQuery>
      │     ├── id: String                            ← map key for constructUnsignedVPToken
      │     ├── format: String
      │     ├── multiple: Boolean
      │     ├── claims: List<ClaimsQuery>?
      │     └── claimSets: List<List<String>>?
      └── credentialSets: List<CredentialSetQuery>?
            ├── options: List<List<String>>            ← OR between options
            └── required: Boolean
```

---

## 4. Complete Flow Diagrams

### 4.1 Authorization Request Phase

```
┌─────────────────────────────────── BEFORE (0.7.0) ───────────────────────────────────┐

POST /wallets/{id}/presentations
  Body: { authorizationRequestUrl: "openid4vp://..." }
         │
         ▼
WalletPresentationServiceImpl.handleVPAuthorizationRequest()
  │
  ├─① verifierService.getTrustedVerifiers()  → List<Verifier>
  │
  ├─② OpenID4VPService.create(presentationId)
  │       └─ new OpenID4VP(id, new WalletMetadata())   ← no verifiers here
  │
  └─③ openID4VP.authenticateVerifier(
            urlString,
            preRegisteredVerifiers,   ← passed as arg
            shouldValidate
        )
└──────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────── AFTER (0.8.0) ────────────────────────────────────┐

POST /wallets/{id}/presentations
  Body: { authorizationRequestUrl: "openid4vp://..." }
         │
         ▼
WalletPresentationServiceImpl.handleVPAuthorizationRequest()
  │
  ├─① getPreRegisteredVerifiers()  → List<Verifier>
  │
  ├─② shouldValidateClient = isVerifierClientPreregistered(verifiers, url)
  │
  ├─③ OpenID4VPService.create(presentationId, trustedVerifiers, shouldValidateClient)
  │       └─ new WalletConfig(..., trustedVerifiers, validatePreRegisteredVerifier)
  │       └─ new OpenID4VP(id, walletConfig)
  │
  ├─④ openID4VP.authenticateVerifier(urlString)         ← 1 arg only
  │       └─ returns AuthorizationRequest subtype
  │
  ├─⑤ if (authReq instanceof AuthorizationDcqlRequest)
  │         → sessionData.specVersion = V1_0
  │   else
  │         → sessionData.specVersion = DRAFT_23
  │
  └─⑥ store session: presentationId, authRequest, specVersion, isPreRegistered
        (isPreRegistered = shouldValidateClient — replayed on later create() calls)
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.2 Credential Matching Phase

```
┌─────────────────── DRAFT-23 path (unchanged logic, new service stub) ─────────────────┐

GET /wallets/{id}/presentations/{pid}/credentials
         │
         ▼
CredentialMatchingServiceImpl.getMatchingCredentials()
  │
  ├─ session.specVersion == DRAFT_23  (or null → default to DRAFT_23)
  │
  ├─ openID4VPService.resolvePresentationDefinition(presentationId, authRequest, preReg)
  │       └─ create(id, verifiers, preReg) → authenticateVerifier(url)  ← FIXED
  │       └─ cast to AuthorizationPresentationExchangeRequest
  │       └─ return presentationDefinition
  │
  ├─ walletCredentialService.getDecryptedCredentials(walletId, key)
  │
  ├─ for each InputDescriptor:
  │       match credentials by format + constraints/fields
  │       record descriptorId → matched credentials
  │
  ├─ build MatchingCredentialsResponseDTO:
  │       availableCredentials: List<CredentialDTO>  (flat, deduped)
  │       missingClaims: Set<String>
  │
  └─ store matchingCredentials (with descriptorId) in session cache
└───────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────── OVP 1.0 / DCQL path (NEW) ─────────────────────────────────────────┐

GET /wallets/{id}/presentations/{pid}/credentials
         │
         ▼
CredentialMatchingServiceImpl.getMatchingCredentials()
  │
  ├─ session.specVersion == V1_0
  │
  ├─ openID4VPService.resolveDcqlQuery(presentationId, authRequest, preReg)
  │       └─ create(id, verifiers, preReg) → authenticateVerifier(url)
  │       └─ cast to AuthorizationDcqlRequest
  │       └─ return dcqlQuery
  │
  ├─ walletCredentialService.getDecryptedCredentials(walletId, key)
  │
  ├─ for each CredentialQuery in dcqlQuery.credentials:
  │       queryId = credentialQuery.id
  │       format  = credentialQuery.format
  │       match wallet VCs by format
  │       if credentialQuery.claims != null → filter by claim paths/values
  │       if credentialQuery.multiple == false → allow only 1 match
  │
  ├─ evaluate credentialSets (if present):
  │       credentialSets = dcqlQuery.credentialSets
  │       for each CredentialSetQuery:
  │           if required=true and no option fully satisfied → mark missing
  │
  ├─ build DcqlMatchingCredentialsResponseDTO:
  │       queryGroups: List<DcqlQueryGroup>
  │           each: { queryId, multiple, availableCredentials, missingClaims }
  │       credentialSets: List<CredentialSetInfo>  (optional, for UI)
  │
  └─ store dcqlMatchingCredentials (with queryId per credential) in session cache
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.3 Presentation Submission Phase

```
┌─────────────────── DRAFT-23 submission (adapted for 0.8.0) ───────────────────────────┐

PATCH /wallets/{id}/presentations/{pid}
  Body: { selectedCredentials: ["vc-id-1", "vc-id-2"] }
         │
         ▼
WalletPresentationServiceImpl.submitPresentation()
  │
  ├─① fetchSelectedCredentials(sessionData, selectedIds)
  │       └─ filters session.matchingCredentials by selectedIds
  │       └─ each DecryptedCredentialDTO has .descriptorId set from matching step
  │
  ├─② create(presentationId, preRegisteredVerifiers, isPreReg)
  │   openID4VP.authenticateVerifier(authRequest)   ← FIXED: 1 arg
  │
  ├─③ buildDescriptorCredentialMap(selectedCredentials, sessionData)
  │       input:  List<DecryptedCredentialDTO>
  │       output: Map<descriptorId, List<Credential>>         ← KEY IS descriptorId
  │           e.g. { "id_card_descriptor": [Credential(LDP_VC, vcData, "vc-id-1")] }
  │
  ├─④ openID4VP.constructUnsignedVPToken(descriptorCredentialMap)
  │       returns List<UnsignedVPToken>
  │           each: { format=LDP_VC, signatureAlgorithm="EdDSA", dataToSign=<bytes> }
  │
  ├─⑤ signVPToken(unsignedVPTokens, keyPair, signingAlgorithm)
  │       for each UnsignedVPToken:
  │           signer = SigningKeyUtil.createSigner(algo, jwk)
  │           signature = signer.sign(JWSHeader(algo), dataToSign).decode()
  │           → VPTokenSigningResult(signedData = rawBytes)
  │       returns List<VPTokenSigningResult>
  │
  └─⑥ openID4VP.sendVPResponseToVerifier(List<VPTokenSigningResult>)
           returns VerifierResponse
└───────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────── OVP 1.0 / DCQL submission (NEW) ───────────────────────────────────┐

PATCH /wallets/{id}/presentations/{pid}
  Body: {
    dcqlSelections: [
      { queryId: "pid_query",  selectedCredentialIds: ["vc-id-1"] },
      { queryId: "mdl_query",  selectedCredentialIds: ["vc-id-2"] }
    ]
  }
         │
         ▼
WalletPresentationServiceImpl.submitPresentation()
  │
  ├─① validateDcqlSelections(request, sessionData)
  │       enforce mandatory credential_sets
  │       enforce multiple=false rules
  │
  ├─② buildQueryCredentialMap(request.dcqlSelections, sessionData)
  │       for each DcqlSelection:
  │           resolve credentials by selectedCredentialIds from session cache
  │           key = selection.queryId
  │       output: Map<queryId, List<Credential>>              ← KEY IS queryId
  │           e.g. { "pid_query": [Credential(...)], "mdl_query": [Credential(...)] }
  │
  ├─③ create(presentationId, preRegisteredVerifiers, isPreReg)
  │   openID4VP.authenticateVerifier(authRequest)
  │
  ├─④ openID4VP.constructUnsignedVPToken(queryCredentialMap)
  │       same call as Draft-23 — library handles both spec versions internally
  │       returns List<UnsignedVPToken>
  │
  ├─⑤ signVPToken(unsignedVPTokens, keyPair, signingAlgorithm)
  │       identical to Draft-23 signing loop
  │
  └─⑥ openID4VP.sendVPResponseToVerifier(List<VPTokenSigningResult>)
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.4 Error / Rejection Path

```
PATCH /wallets/{id}/presentations/{pid}
  Body: { errorCode: "access_denied", errorMessage: "User denied" }
         │
         ▼
WalletPresentationServiceImpl.rejectVerifier()
  │
  └─ openID4VPService.sendErrorToVerifier(sessionData, errorPayload)
          │
          ├─ create(presentationId, preRegisteredVerifiers, isPreReg)
          ├─ openID4VP.authenticateVerifier(authRequest)  ← FIXED: 1 arg
          └─ openID4VP.sendErrorInfoToVerifier(OpenID4VPException)
```

---

## 5. Affected Files — Complete List

| File | Nature of Change |
|------|-----------------|
| `pom.xml` | Version bump |
| `OpenID4VPService.java` | WalletConfig fix + authenticateVerifier fix + new `resolveDcqlQuery()` |
| `WalletPresentationServiceImpl.java` | authenticateVerifier fix + map key fix + DCQL submission path |
| `CredentialMatchingServiceImpl.java` | Add DCQL matching branch |
| `VerifiablePresentationSessionData.java` | Add `specVersion` field |
| `DecryptedCredentialDTO.java` | Add `descriptorId` field |
| `SubmitPresentationRequestDTO.java` | Add `dcqlSelections` field |
| `MatchingCredentialsResponseDTO.java` | Add DCQL query groups structure |
| `CredentialDTO.java` | Add `descriptorId` / `queryId` field |
| `DcqlQueryGroup.java` | New DTO |
| `DcqlCredentialSelection.java` | New DTO |
| `SpecVersion.java` | New enum |
| `OpenID4VPServiceTest.java` | Mock signature updates |
| `WalletPresentationServiceTest.java` | Mock + DCQL path tests |
| `CredentialMatchingServiceTest.java` | Add DCQL matching tests |

---

## 6. Code Changes — File by File

---

### 6.1 `pom.xml`

```xml
<!-- BEFORE -->
<version>0.7.0-SNAPSHOT-myLocal</version>

<!-- AFTER -->
<version>0.8.0-myLocal</version>
```

**Install prerequisite (run once before builds):**
```bash
# Option A — build from source
cd E:\Mosip\inji-openid4vp\kotlin
mvn install -DskipTests

# Option B — install pre-built JAR
mvn install:install-file \
  -Dfile=inji-openid4vp-jar-0.8.0.jar \
  -DgroupId=io.inji -DartifactId=inji-openid4vp-jar \
  -Dversion=0.8.0-myLocal -Dpackaging=jar
```

---

### 6.2 New Enum: `SpecVersion.java`

```java
// src/main/java/io/mosip/mimoto/constant/SpecVersion.java
package io.mosip.mimoto.constant;

public enum SpecVersion {
    DRAFT_23,
    V1_0
}
```

---

### 6.3 New DTO: `DcqlQueryGroup.java`

This is the per-query result returned to the UI for OVP 1.0 flows.

```java
// src/main/java/io/mosip/mimoto/dto/DcqlQueryGroup.java
package io.mosip.mimoto.dto;

import lombok.*;
import java.util.List;
import java.util.Set;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class DcqlQueryGroup {
    private String queryId;
    private boolean multiple;
    private List<CredentialDTO> availableCredentials;
    private Set<String> missingClaims;
}
```

---

### 6.4 New DTO: `DcqlCredentialSelection.java`

Carries a single user selection for one DCQL query.

```java
// src/main/java/io/mosip/mimoto/dto/DcqlCredentialSelection.java
package io.mosip.mimoto.dto;

import lombok.*;
import java.util.List;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class DcqlCredentialSelection {
    private String queryId;
    private List<String> selectedCredentialIds;
}
```

---

### 6.5 `VerifiablePresentationSessionData.java` — add `specVersion`

```java
// BEFORE
@Data @AllArgsConstructor @NoArgsConstructor
public class VerifiablePresentationSessionData implements Serializable {
    private String presentationId;
    private String authorizationRequest;
    private Instant createdAt;
    private boolean isVerifierClientPreregistered;
    private List<DecryptedCredentialDTO> matchingCredentials;
}

// AFTER — add one field
@Data @AllArgsConstructor @NoArgsConstructor
public class VerifiablePresentationSessionData implements Serializable {
    private String presentationId;
    private String authorizationRequest;
    private Instant createdAt;
    private boolean isVerifierClientPreregistered;
    private List<DecryptedCredentialDTO> matchingCredentials;
    private SpecVersion specVersion;   // ← NEW: DRAFT_23 or V1_0
}
```

---

### 6.6 `DecryptedCredentialDTO.java` — add `descriptorId`

```java
// AFTER — add one field
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class DecryptedCredentialDTO implements Serializable {
    private String id;
    private String walletId;
    private VCCredentialResponse credential;
    private CredentialMetadata credentialMetadata;
    private Instant createdAt;
    private Instant updatedAt;
    private String descriptorId;   // ← NEW: InputDescriptor.id or DCQL queryId this VC satisfies
}
```

---

### 6.7 `MatchingCredentialsResponseDTO.java` — add DCQL fields

```java
// BEFORE
public class MatchingCredentialsResponseDTO {
    private List<CredentialDTO> availableCredentials;
    private Set<String> missingClaims;
}

// AFTER
public class MatchingCredentialsResponseDTO {
    // Draft-23 fields (kept as-is for backward compatibility)
    private List<CredentialDTO> availableCredentials;
    private Set<String> missingClaims;

    // OVP 1.0 / DCQL fields (null for Draft-23 responses)
    private List<DcqlQueryGroup> queryGroups;       // ← NEW: per-query groups
    private boolean isDcql;                          // ← NEW: tells UI which shape to use
}
```

---

### 6.8 `SubmitPresentationRequestDTO.java` — add DCQL selection

```java
// BEFORE
public class SubmitPresentationRequestDTO {
    private List<String> selectedCredentials;  // Draft-23
    private String errorCode;
    private String errorMessage;
}

// AFTER
public class SubmitPresentationRequestDTO {
    // Draft-23: simple list of VC ids
    private List<String> selectedCredentials;

    // OVP 1.0 / DCQL: query-aware selection
    private List<DcqlCredentialSelection> dcqlSelections;  // ← NEW

    private String errorCode;
    private String errorMessage;

    public boolean isSubmissionRequest() {
        boolean hasDraft23 = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasDcql = dcqlSelections != null && !dcqlSelections.isEmpty();
        boolean hasError = (errorCode != null && !errorCode.isBlank())
                        || (errorMessage != null && !errorMessage.isBlank());
        return (hasDraft23 || hasDcql) && !hasError;
    }

    public boolean isDcqlSubmission() {
        return dcqlSelections != null && !dcqlSelections.isEmpty();
    }

    public boolean isRejectionRequest() {
        boolean hasError = errorCode != null && !errorCode.isBlank()
                       && errorMessage != null && !errorMessage.isBlank();
        boolean hasCredentials = (selectedCredentials != null && !selectedCredentials.isEmpty())
                              || (dcqlSelections != null && !dcqlSelections.isEmpty());
        return hasError && !hasCredentials;
    }
}
```

---

### 6.9 `OpenID4VPService.java` — full rewrite of affected methods

#### 6.9.1 `create()` — fix WalletConfig construction

**BEFORE (bug: empty lists override library defaults):**
```java
public OpenID4VP create(String presentationId, List<Verifier> trustedVerifiers) {
    WalletConfig walletConfig = new WalletConfig(
        Map.of(VPFormatType.LDP_VC, new LdpVcFormatSupported(...)),
        Collections.emptyList(),  // ← clientIdPrefixes: empty kills pre-registered scheme
        Collections.emptyList(),  // ← requestObjectSigningAlg: empty
        Collections.emptyList(),  // ← encAlg: empty
        Collections.emptyList(),  // ← encEnc: empty
        Collections.emptyList(),  // ← responseTypes: empty kills vp_token
        false,                    // ← presentationDefinitionUriSupported: wrong
        Collections.emptyList(),  // ← supportedRequestUriMethods: kills GET
        trustedVerifiers
    );
    return new OpenID4VP(presentationId, walletConfig);
}
```

**AFTER (use library defaults from `WalletConfigDefaults.kt` — confirmed by reading library source):**

> **Library finding:** `WalletConfigDefaults.kt` defines the correct defaults:
> - `vpFormatsSupported`: LDP_VC, MSO_MDOC, DC_SD_JWT
> - `clientIdPrefixesSupported`: PRE_REGISTERED, REDIRECT_URI, DECENTRALIZED_IDENTIFIER
> - `responseTypesSupported`: VP_TOKEN
> - `requestObjectSigningAlgValuesSupported`: EdDSA
> - `authorizationEncryptionAlgValuesSupported`: ECDH_ES
> - `authorizationEncryptionEncValuesSupported`: A256GCM
>
> Mimoto customizes `trustedVerifiers` and `validatePreRegisteredVerifier`. All other fields
> should use those library defaults. Since `WalletConfig` is a Kotlin `data class`
> with `@JvmOverloads`, use the full constructor from Java — pass the correct
> defaults explicitly so they are not accidentally overridden with empty lists.

```java
public OpenID4VP create(String presentationId,
                        List<Verifier> trustedVerifiers,
                        boolean validatePreRegisteredVerifier) {
    // vpFormatsSupported: keep LDP_VC only for now (mimoto only supports ldp_vc signing).
    // Expand to MSO_MDOC / DC_SD_JWT when those signing paths are implemented.
    Map<VPFormatType, VPFormatSupported> vpFormats = Map.of(
            VPFormatType.LDP_VC,
            new LdpVcFormatSupported(List.of(ProofType.Ed25519Signature2020), null)
    );
    WalletConfig walletConfig = new WalletConfig(
            vpFormats,
            // Library default: PRE_REGISTERED, REDIRECT_URI, DECENTRALIZED_IDENTIFIER
            List.of(ClientIdPrefix.PRE_REGISTERED,
                    ClientIdPrefix.REDIRECT_URI,
                    ClientIdPrefix.DECENTRALIZED_IDENTIFIER),
            // Library default: EdDSA — pass null to use library default
            null,
            // Library default: ECDH_ES — pass null to use library default
            null,
            // Library default: A256GCM — pass null to use library default
            null,
            // Library default: VP_TOKEN
            List.of(ResponseType.VP_TOKEN),
            // Library default: true
            true,
            // Library default: GET, POST
            List.of(RequestUriMethod.GET, RequestUriMethod.POST),
            trustedVerifiers,
            validatePreRegisteredVerifier   // was shouldValidateClient in authenticateVerifier()
    );
    return new OpenID4VP(presentationId, walletConfig);
}
```

> **Kotlin note:** In Kotlin, `validatePreRegisteredVerifier` is optional via named args
> (`WalletConfig(trustedVerifiers = …, validatePreRegisteredVerifier = …)`). From Java,
> pass the full constructor including this flag.

**New imports for `OpenID4VPService`:**
```java
import io.mosip.openID4VP.authorizationRequest.ClientIdPrefix;
import io.mosip.openID4VP.constants.ResponseType;
import io.mosip.openID4VP.constants.RequestUriMethod;
```

---

#### 6.9.2 `resolvePresentationDefinition()` — fix authenticateVerifier call

**BEFORE:**
```java
public PresentationDefinition resolvePresentationDefinition(...) {
    List<Verifier> preRegisteredVerifiers = verifierService...
    OpenID4VP openID4VP = create(presentationId, preRegisteredVerifiers, isVerifierClientPreregistered);
    AuthorizationRequest req = openID4VP.authenticateVerifier(authRequest);
    if (req instanceof AuthorizationPresentationExchangeRequest pe) {
        return pe.getPresentationDefinition();
    }
    return null;
}
```

**AFTER:**
```java
public PresentationDefinition resolvePresentationDefinition(
        String presentationId,
        String authRequest,
        boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {

    if (presentationId == null || authRequest == null) return null;

    OpenID4VP openID4VP = create(
            presentationId,
            getPreRegisteredVerifiers(),
            isVerifierClientPreregistered);
    AuthorizationRequest req = openID4VP.authenticateVerifier(authRequest);
    if (req instanceof AuthorizationPresentationExchangeRequest pe) {
        return pe.getPresentationDefinition();
    }
    return null;
}
```

---

#### 6.9.3 New method: `resolveDcqlQuery()`

```java
/**
 * For OVP 1.0 requests: creates a fresh OpenID4VP instance, authenticates, and
 * returns the DCQLQuery from the authorization request.
 */
public DCQLQuery resolveDcqlQuery(
        String presentationId,
        String authRequest,
        boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {

    if (presentationId == null || authRequest == null) return null;

    OpenID4VP openID4VP = create(
            presentationId,
            getPreRegisteredVerifiers(),
            isVerifierClientPreregistered);
    AuthorizationRequest req = openID4VP.authenticateVerifier(authRequest);
    if (req instanceof AuthorizationDcqlRequest dcqlRequest) {
        return dcqlRequest.getDcqlQuery();
    }
    return null;
}
```

**New import:**
```java
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery;
```

---

#### 6.9.4 `sendErrorToVerifier()` — fix authenticateVerifier call

**BEFORE:**
```java
OpenID4VP openID4VP = create(sessionData.getPresentationId(), preRegisteredVerifiers);
openID4VP.authenticateVerifier(
    sessionData.getAuthorizationRequest(),
    preRegisteredVerifiers,                   // ← WRONG
    sessionData.isVerifierClientPreregistered()
);
```

**AFTER:**
```java
OpenID4VP openID4VP = create(
        sessionData.getPresentationId(),
        preRegisteredVerifiers,
        sessionData.isVerifierClientPreregistered());
openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());   // ← 1 arg
```

Also add a private helper used by all three methods above to avoid duplication:
```java
private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
    return verifierService.getTrustedVerifiers().getVerifiers().stream()
            .map(v -> new Verifier(v.getClientId(), v.getResponseUris(),
                                   v.getJwksUri(), v.getAllowUnsignedRequest()))
            .toList();
}
```

---

### 6.10 `WalletPresentationServiceImpl.java` — all affected methods

#### 6.10.1 `handleVPAuthorizationRequest()` — fix + add spec version detection

**BEFORE:**
```java
public VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) {
    String presentationId = UUID.randomUUID().toString();
    List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
    OpenID4VP openID4VP = openID4VPService.create(presentationId, preRegisteredVerifiers);
    boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(
            preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
    AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(
            urlEncodedVPAuthorizationRequest,
            preRegisteredVerifiers,    // ← WRONG
            shouldValidateClient);
    ...
    return new VPResponseDTO(presentationId, verifiablePresentationVerifierDTO);
}
```

**AFTER:**
```java
public VPResponseDTO handleVPAuthorizationRequest(
        String urlEncodedVPAuthorizationRequest, String walletId)
        throws ApiNotAccessibleException, IOException, URISyntaxException {

    String presentationId = UUID.randomUUID().toString();
    List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
    boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(
            preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
    OpenID4VP openID4VP = openID4VPService.create(
            presentationId, preRegisteredVerifiers, shouldValidateClient);

    // ① FIXED: validation flag now in WalletConfig; authenticateVerifier is 1-arg
    AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(
            urlEncodedVPAuthorizationRequest);

    // ② NEW: detect spec version and expose it for session storage
    SpecVersion specVersion = (authorizationRequest instanceof AuthorizationDcqlRequest)
            ? SpecVersion.V1_0 : SpecVersion.DRAFT_23;

    VerifiablePresentationVerifierDTO verifierDTO =
            createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

    // ③ Return presentationId + verifierDTO; specVersion stored in controller
    return new VPResponseDTO(presentationId, verifierDTO, specVersion);
}
```

**`VPResponseDTO`** needs `specVersion` added:
```java
// Add to VPResponseDTO:
private SpecVersion specVersion;
```

**In `WalletPresentationsController.handleVPAuthorizationRequest()`**, store spec version to session:
```java
VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
        verifiablePresentationResponseDTO.getPresentationId(),
        vpAuthorizationRequest.getAuthorizationRequestUrl(),
        Instant.now(),
        verifiablePresentationResponseDTO.getVerifiablePresentationVerifierDTO().isPreregisteredWithWallet(),
        null,
        verifiablePresentationResponseDTO.getSpecVersion()  // ← NEW
);
```

---

#### 6.10.2 `submitPresentation()` — add DCQL branch

**AFTER (both paths):**
```java
public SubmitPresentationResponseDTO submitPresentation(
        VerifiablePresentationSessionData sessionData,
        String walletId, String presentationId,
        SubmitPresentationRequestDTO request, String base64Key)
        throws ApiNotAccessibleException, IOException, JOSEException,
               KeyGenerationException, DecryptionException {

    LocalDateTime requestedAt = LocalDateTime.now();
    validateInputs(request);

    List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
    OpenID4VP openID4VP = openID4VPService.create(
            presentationId,
            preRegisteredVerifiers,
            sessionData.isVerifierClientPreregistered());

    // ① FIXED: trusted verifiers + validatePreRegisteredVerifier in WalletConfig
    openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

    SigningAlgorithm signingAlgorithm = SigningAlgorithm.valueOf(DEFAULT_SIGNING_ALGORITHM_NAME);
    KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, signingAlgorithm);

    // ② Branch by spec version
    Map<String, List<Credential>> selectedCredentialMap;
    if (request.isDcqlSubmission()) {
        // OVP 1.0 / DCQL path
        validateDcqlSelections(request, sessionData);
        selectedCredentialMap = buildQueryCredentialMap(request.getDcqlSelections(), sessionData);
    } else {
        // Draft-23 path
        List<DecryptedCredentialDTO> selectedCredentials =
                fetchSelectedCredentials(sessionData, request.getSelectedCredentials());
        selectedCredentialMap = buildDescriptorCredentialMap(selectedCredentials, sessionData);
    }

    // ③ Construct — same library call for both spec versions
    List<UnsignedVPToken> unsignedVPTokens =
            openID4VP.constructUnsignedVPToken(selectedCredentialMap);

    // ④ Sign — same for both paths
    List<VPTokenSigningResult> signingResults =
            signVPToken(unsignedVPTokens, keyPair, signingAlgorithm);

    // ⑤ Send
    try {
        VerifierResponse response = openID4VP.sendVPResponseToVerifier(signingResults);
        boolean success = response.getStatusCode() >= 200 && response.getStatusCode() < 300;
        storePresentationRecord(walletId, presentationId, request, sessionData, success, requestedAt);
        return SubmitPresentationResponseDTO.builder()
                .redirectUri(response.getRedirectUri())
                .status(success ? STATUS_SUCCESS : STATUS_ERROR)
                .message(success ? MESSAGE_PRESENTATION_SUCCESS : MESSAGE_PRESENTATION_SHARE_FAILED)
                .build();
    } catch (Exception e) {
        log.error("Failed to share verifiable presentation with verifier", e);
        storePresentationRecord(walletId, presentationId, request, sessionData, false, requestedAt);
        return SubmitPresentationResponseDTO.builder()
                .status(STATUS_ERROR)
                .message(MESSAGE_PRESENTATION_SHARE_FAILED)
                .build();
    }
}
```

---

#### 6.10.3 New method: `buildDescriptorCredentialMap()` (Draft-23 map key fix)

**BEFORE (`convertCredentialsToJarFormat`)** — WRONG: groups by VC id:
```java
private Map<String, List<Credential>> convertCredentialsToJarFormat(
        List<DecryptedCredentialDTO> credentials) {
    return credentials.stream()
        .collect(Collectors.groupingBy(
            DecryptedCredentialDTO::getId,    // ← BUG: credential id ≠ descriptor id
            ...));
}
```

**AFTER** — groups by `descriptorId`:
```java
/**
 * Draft-23: builds Map<descriptorId, List<Credential>> required by constructUnsignedVPToken.
 * The descriptorId was stored on each DecryptedCredentialDTO during the matching step.
 */
private Map<String, List<Credential>> buildDescriptorCredentialMap(
        List<DecryptedCredentialDTO> selectedCredentials,
        VerifiablePresentationSessionData sessionData) {

    Map<String, List<Credential>> result = new LinkedHashMap<>();
    for (DecryptedCredentialDTO dto : selectedCredentials) {
        // descriptorId is set during matching; fall back to credential id if absent
        String key = (dto.getDescriptorId() != null && !dto.getDescriptorId().isBlank())
                ? dto.getDescriptorId() : dto.getId();
        VCCredentialResponse vc = dto.getCredential();
        FormatType format = mapStringToFormatType(vc.getFormat());
        Credential credential = new Credential(format, vc.getCredential(), dto.getId());
        result.computeIfAbsent(key, k -> new ArrayList<>()).add(credential);
    }
    return result;
}
```

---

#### 6.10.4 New method: `buildQueryCredentialMap()` (OVP 1.0 / DCQL)

```java
/**
 * OVP 1.0: builds Map<queryId, List<Credential>> from the user's DCQL selections.
 * The queryId comes from DCQLQuery.credentials[i].id.
 */
private Map<String, List<Credential>> buildQueryCredentialMap(
        List<DcqlCredentialSelection> dcqlSelections,
        VerifiablePresentationSessionData sessionData) {

    // Build a lookup: credentialId → DecryptedCredentialDTO from session cache
    Map<String, DecryptedCredentialDTO> credentialCache = Optional
            .ofNullable(sessionData.getMatchingCredentials())
            .orElse(Collections.emptyList())
            .stream()
            .collect(Collectors.toMap(DecryptedCredentialDTO::getId, c -> c));

    Map<String, List<Credential>> result = new LinkedHashMap<>();
    for (DcqlCredentialSelection selection : dcqlSelections) {
        List<Credential> credentials = selection.getSelectedCredentialIds().stream()
                .map(vcId -> {
                    DecryptedCredentialDTO dto = credentialCache.get(vcId);
                    if (dto == null) {
                        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                                "Selected credential not found in session: " + vcId);
                    }
                    FormatType format = mapStringToFormatType(dto.getCredential().getFormat());
                    return new Credential(format, dto.getCredential().getCredential(), dto.getId());
                })
                .collect(Collectors.toList());
        result.put(selection.getQueryId(), credentials);
    }
    return result;
}
```

---

#### 6.10.5 New method: `validateDcqlSelections()` (OVP 1.0 constraint enforcement)

```java
/**
 * Enforces OVP 1.0 / DCQL rules before submission:
 * - mandatory credential_sets must have at least one satisfied option
 * - multiple=false queries must not have more than one selected credential
 */
private void validateDcqlSelections(
        SubmitPresentationRequestDTO request,
        VerifiablePresentationSessionData sessionData) throws ApiNotAccessibleException, IOException {

    DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
            sessionData.getPresentationId(),
            sessionData.getAuthorizationRequest(),
            sessionData.isVerifierClientPreregistered());

    if (dcqlQuery == null) return;

    Map<String, Integer> selectionCountByQueryId = request.getDcqlSelections().stream()
            .collect(Collectors.toMap(
                    DcqlCredentialSelection::getQueryId,
                    s -> s.getSelectedCredentialIds().size()
            ));

    // Rule 1: multiple=false → max 1 credential per query
    for (CredentialQuery credentialQuery : dcqlQuery.getCredentials()) {
        if (!credentialQuery.getMultiple()) {
            int count = selectionCountByQueryId.getOrDefault(credentialQuery.getId(), 0);
            if (count > 1) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Query '" + credentialQuery.getId()
                        + "' has multiple=false but " + count + " credentials were selected");
            }
        }
    }

    // Rule 2: required credential_sets must be satisfied
    if (dcqlQuery.getCredentialSets() != null) {
        for (CredentialSetQuery setQuery : dcqlQuery.getCredentialSets()) {
            if (!setQuery.getRequired()) continue;
            boolean anySatisfied = setQuery.getOptions().stream().anyMatch(option ->
                    option.stream().allMatch(queryId ->
                            selectionCountByQueryId.getOrDefault(queryId, 0) > 0
                    )
            );
            if (!anySatisfied) {
                throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                        "Mandatory credential_set is not satisfied. "
                        + "Options: " + setQuery.getOptions());
            }
        }
    }
}
```

**New imports for `WalletPresentationServiceImpl`:**
```java
import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.DcqlCredentialSelection;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.CredentialQuery;
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.CredentialSetQuery;
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery;
```

---

#### 6.10.6 `signVPToken()` — cleaned-up signing

Remove the separate `JWK` / `JWSSigner` creation before the loop. Resolve per-token.

**BEFORE:**
```java
// In submitPresentation():
JWK jwk = SigningKeyUtil.generateJwk(signingAlgorithm, keyPair);
JWSSigner jwsSigner = SigningKeyUtil.createSigner(signingAlgorithm, jwk);
List<VPTokenSigningResult> vpTokenSigningResults = signVPToken(unsignedVPTokens, jwsSigner);

// signVPToken only handles LDP_VC
private List<VPTokenSigningResult> signVPToken(List<UnsignedVPToken> tokens, JWSSigner signer)
```

**AFTER:**
```java
// In submitPresentation():
List<VPTokenSigningResult> signingResults = signVPToken(unsignedVPTokens, keyPair, signingAlgorithm);

// signVPToken — resolves JWSSigner per token using the algorithm from the library
private List<VPTokenSigningResult> signVPToken(
        List<UnsignedVPToken> unsignedVPTokens,
        KeyPair keyPair,
        SigningAlgorithm defaultAlgorithm) throws JOSEException {

    log.debug("Signing {} VP token(s)", unsignedVPTokens.size());
    List<VPTokenSigningResult> results = new ArrayList<>();

    for (UnsignedVPToken token : unsignedVPTokens) {
        if (token.getFormat() != FormatType.LDP_VC) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Unsupported format: " + token.getFormat()
                    + ". Only ldp_vc is supported in this version.");
        }
        results.add(signLdpVcToken(token, keyPair, defaultAlgorithm));
    }
    return results;
}

private VPTokenSigningResult signLdpVcToken(
        UnsignedVPToken token, KeyPair keyPair, SigningAlgorithm defaultAlgorithm)
        throws JOSEException {

    // Use the algorithm the library requested, fall back to our default
    String algorithmName = Optional.ofNullable(token.getSignatureAlgorithm())
            .filter(s -> !s.isBlank())
            .orElse(defaultAlgorithm.getAlgorithmName());

    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithmName);
    JWK jwk = SigningKeyUtil.generateJwk(defaultAlgorithm, keyPair);
    JWSSigner signer = SigningKeyUtil.createSigner(defaultAlgorithm, jwk);

    // sign() returns the raw signature as a Base64URL; decode() gives the raw bytes
    Base64URL signature = signer.sign(new JWSHeader(jwsAlgorithm), token.getDataToSign());
    return new VPTokenSigningResult(signature.decode());
}
```

**Import to remove:**
```java
// No longer needed at submitPresentation() level:
// import com.nimbusds.jose.jwk.JWK;  ← still needed inside signLdpVcToken, keep it
```

---

### 6.11 `CredentialMatchingServiceImpl.java` — add DCQL branch

#### 6.11.1 Top-level `getMatchingCredentials()` — route by spec version

**BEFORE:**
```java
public MatchingCredentialsDTO getMatchingCredentials(
        VerifiablePresentationSessionData sessionData, String walletId, String base64Key) {
    PresentationDefinition pd = openID4VPService.resolvePresentationDefinition(...);
    // ... Draft-23 matching only
}
```

**AFTER:**
```java
@Override
public MatchingCredentialsDTO getMatchingCredentials(
        VerifiablePresentationSessionData sessionData,
        String walletId, String base64Key)
        throws ApiNotAccessibleException, IOException {

    log.info("Getting matching credentials for walletId: {}, specVersion: {}",
            walletId, sessionData.getSpecVersion());

    List<DecryptedCredentialDTO> decryptedCredentials =
            walletCredentialService.getDecryptedCredentials(walletId, base64Key);

    SpecVersion specVersion = sessionData.getSpecVersion();
    if (specVersion == SpecVersion.V1_0) {
        return matchDcql(sessionData, decryptedCredentials);
    } else {
        return matchPresentationDefinition(sessionData, walletId, decryptedCredentials);
    }
}
```

---

#### 6.11.2 Extracted method: `matchPresentationDefinition()` (Draft-23)

Existing logic moves here unchanged, but now records `descriptorId` per credential:

```java
private MatchingCredentialsDTO matchPresentationDefinition(
        VerifiablePresentationSessionData sessionData,
        String walletId,
        List<DecryptedCredentialDTO> decryptedCredentials)
        throws ApiNotAccessibleException, IOException {

    PresentationDefinition pd = openID4VPService.resolvePresentationDefinition(
            sessionData.getPresentationId(),
            sessionData.getAuthorizationRequest(),
            sessionData.isVerifierClientPreregistered());

    validateInputParameters(pd, walletId, /* base64Key not needed here */ "placeholder");

    if (decryptedCredentials.isEmpty()) {
        return emptyDraft23Result(pd);
    }

    List<InputDescriptor> descriptors = pd.getInputDescriptors();
    Map<Integer, List<CredentialDTO>> matchesByDescriptor = new HashMap<>();
    Set<String> missingClaims = new HashSet<>();
    // credentialId → descriptorId mapping for session storage
    Map<String, String> credentialToDescriptor = new HashMap<>();

    IntStream.range(0, descriptors.size()).forEach(i -> {
        InputDescriptor descriptor = descriptors.get(i);
        List<CredentialDTO> matches = decryptedCredentials.stream()
                .filter(dto -> matchesInputDescriptor(dto.getCredential(), descriptor))
                .peek(dto -> credentialToDescriptor.put(dto.getId(), descriptor.getId())) // ← record mapping
                .map(this::buildAvailableCredential)
                .collect(Collectors.toList());
        if (!matches.isEmpty()) {
            matchesByDescriptor.put(i, matches);
        } else {
            missingClaims.addAll(extractClaimsFromInputDescriptor(descriptor));
        }
    });

    // De-duplicate available credentials
    Set<String> seen = new HashSet<>();
    List<CredentialDTO> available = matchesByDescriptor.values().stream()
            .flatMap(List::stream)
            .filter(c -> seen.add(c.getCredentialId()))
            .collect(Collectors.toList());

    MatchingCredentialsResponseDTO response = MatchingCredentialsResponseDTO.builder()
            .availableCredentials(available)
            .missingClaims(missingClaims)
            .isDcql(false)
            .build();

    // Set descriptorId on each matched credential for use in buildDescriptorCredentialMap()
    List<DecryptedCredentialDTO> matched = decryptedCredentials.stream()
            .filter(dto -> credentialToDescriptor.containsKey(dto.getId()))
            .peek(dto -> dto.setDescriptorId(credentialToDescriptor.get(dto.getId())))
            .collect(Collectors.toList());

    return MatchingCredentialsDTO.builder()
            .matchingCredentialsResponse(response)
            .matchingCredentials(matched)
            .build();
}
```

---

#### 6.11.3 New method: `matchDcql()` (OVP 1.0)

> **Library finding:** The library provides `DCQLHelper.getMatchingCredentials(inputCredentials, dcqlQuery)`
> (`io.mosip.openID4VP.evaluator.dcql.DCQLHelper`) which handles all DCQL matching internally:
> format check, meta check, cryptographic holder binding, claim path evaluation, claimSets,
> credentialSets satisfaction — confirmed in `DcqlEvaluator.kt` and `DCQLHelper.kt`.
>
> **Mimoto does NOT write manual matching code.** Just call the library helper and map its result.

```java
/**
 * OVP 1.0 / DCQL matching.
 * Delegates all credential matching logic to DCQLHelper from the inji-openid4vp library.
 * Mimoto's job here is only to:
 *   1. Convert wallet VCs to library Credential objects
 *   2. Call DCQLHelper.getMatchingCredentials()
 *   3. Map MatchingCredentialsResult → mimoto response DTOs for the UI
 */
private MatchingCredentialsDTO matchDcql(
        VerifiablePresentationSessionData sessionData,
        List<DecryptedCredentialDTO> decryptedCredentials)
        throws ApiNotAccessibleException, IOException {

    DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
            sessionData.getPresentationId(),
            sessionData.getAuthorizationRequest(),
            sessionData.isVerifierClientPreregistered());

    if (dcqlQuery == null) {
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "Authorization request does not contain a DCQL query");
    }

    // ① Convert all wallet VCs to library Credential objects
    List<Credential> libraryCredentials = decryptedCredentials.stream()
            .map(dto -> new Credential(
                    mapStringToFormatType(dto.getCredential().getFormat()),
                    dto.getCredential().getCredential(),
                    dto.getId()))
            .collect(Collectors.toList());

    // ② Delegate ALL matching to the library — no manual logic needed
    DCQLHelper dcqlHelper = new DCQLHelper();
    MatchingCredentialsResult matchingResult =
            dcqlHelper.getMatchingCredentials(libraryCredentials, dcqlQuery);

    // ③ Build a lookup: credentialId → DecryptedCredentialDTO for session storage
    Map<String, DecryptedCredentialDTO> dtoById = decryptedCredentials.stream()
            .collect(Collectors.toMap(DecryptedCredentialDTO::getId, d -> d));

    // ④ Map library result → mimoto DcqlQueryGroup DTOs (one per query)
    List<DcqlQueryGroup> queryGroups = new ArrayList<>();
    List<DecryptedCredentialDTO> allMatchedCredentials = new ArrayList<>();
    Set<String> seenCredentialIds = new HashSet<>();

    for (Map.Entry<String, QueryMatchResult> entry : matchingResult.getQueryMatches().entrySet()) {
        String queryId = entry.getKey();
        QueryMatchResult queryMatchResult = entry.getValue();

        List<CredentialDTO> availableCredentials = new ArrayList<>();
        Set<String> missingClaims = new HashSet<>();

        if (queryMatchResult.getMatchingCredentials() != null) {
            for (MatchingCredential mc : queryMatchResult.getMatchingCredentials()) {
                DecryptedCredentialDTO dto = dtoById.get(mc.getCredentialId());
                if (dto != null) {
                    // Tag with queryId so submission can build the correct map key
                    dto.setDescriptorId(queryId);
                    if (seenCredentialIds.add(mc.getCredentialId())) {
                        allMatchedCredentials.add(dto);
                    }
                    availableCredentials.add(buildAvailableCredential(dto));
                }
            }
        } else if (queryMatchResult.getFailedClaims() != null) {
            // No match: collect failed claim paths as missingClaims for UI feedback
            queryMatchResult.getFailedClaims().forEach(f ->
                    missingClaims.add(f.getClaim().getPath().stream()
                            .map(Object::toString)
                            .collect(Collectors.joining("."))));
        }

        queryGroups.add(DcqlQueryGroup.builder()
                .queryId(queryId)
                .multiple(queryMatchResult.getAllowMultipleCredentials())
                .availableCredentials(availableCredentials)
                .missingClaims(missingClaims)
                .build());
    }

    // ⑤ Map credentialSets for UI (mandatory/optional logic lives here, not on queryGroup)

    MatchingCredentialsResponseDTO response = MatchingCredentialsResponseDTO.builder()
            .queryGroups(queryGroups)
            .isDcql(true)
            .build();

    return MatchingCredentialsDTO.builder()
            .matchingCredentialsResponse(response)
            .matchingCredentials(allMatchedCredentials)
            .build();
}
```

**New imports for `CredentialMatchingServiceImpl`:**
```java
import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.DcqlQueryGroup;
import io.mosip.openID4VP.authorizationRequest.dcqlQuery.DCQLQuery;
import io.mosip.openID4VP.evaluator.dcql.DCQLHelper;
import io.mosip.openID4VP.evaluator.dcql.MatchingCredential;
import io.mosip.openID4VP.evaluator.dcql.MatchingCredentialsResult;
import io.mosip.openID4VP.evaluator.dcql.QueryMatchResult;
import io.mosip.openID4VP.wallet.Credential;
```

> **Methods removed from plan** (were in earlier draft, now not needed):
> - ~~`matchesDcqlQuery()`~~ — library handles format + claim matching
> - ~~`matchesDcqlClaimPath()`~~ — library handles JSON path resolution
> - ~~`claimValueMatches()`~~ — library handles value comparison
> - ~~`extractMissingClaimsFromDcqlQuery()`~~ — library returns `failedClaims` directly

---

## 7. Data Flow Diagrams — Session State

### 7.1 What gets stored in session and when

```
POST /wallets/{id}/presentations  (handleVPAuthorizationRequest)
  Stores:
    VerifiablePresentationSessionData {
      presentationId        = UUID
      authorizationRequest  = original URL string
      isVerifierPreregistered = boolean
      specVersion           = DRAFT_23 | V1_0   ← NEW
      matchingCredentials   = null (not yet)
    }

GET /wallets/{id}/presentations/{pid}/credentials  (getMatchingCredentials)
  Reads:
    session.specVersion  →  routes to Draft-23 or DCQL matching
  Stores (updates session):
    matchingCredentials = List<DecryptedCredentialDTO>
                         each DTO has .descriptorId = inputDescriptorId or dcqlQueryId

PATCH /wallets/{id}/presentations/{pid}  (submitPresentation or rejectVerifier)
  Reads:
    session.specVersion       → routes submission path
    session.matchingCredentials → resolve selectedCredentialIds to full VC data
    dto.descriptorId or dto.queryId → build the map key for constructUnsignedVPToken
```

---

### 7.2 Map key for `constructUnsignedVPToken()`

```
Draft-23:
  InputDescriptor.id (from PresentationDefinition) ← stored as DecryptedCredentialDTO.descriptorId
  e.g. Map { "national_id_descriptor": [Credential(ldp_vc, vcData, "vc-uuid-1")] }

OVP 1.0 / DCQL:
  CredentialQuery.id (from DCQLQuery.credentials[i].id)  ← stored as descriptorId
  e.g. Map { "pid_query": [Credential(ldp_vc, vcData, "vc-uuid-1")],
              "mdl_query": [Credential(ldp_vc, vcData, "vc-uuid-2")] }
```

---

## 8. Test Changes

### 8.1 `OpenID4VPServiceTest.java`

| What to change | Detail |
|----------------|--------|
| `authenticateVerifier` mocks | Remove middle `anyList()` arg → `(anyString(), anyBoolean())` |
| `create()` test throws clause | Add `throws Exception` since `getPreRegisteredVerifiers()` may throw |
| Add test: `resolveDcqlQuery()` | Mock `AuthorizationDcqlRequest`, assert `getDcqlQuery()` is returned |

### 8.2 `WalletPresentationServiceTest.java`

| What to change | Detail |
|----------------|--------|
| `authenticateVerifier` mocks | Remove middle arg |
| `constructUnsignedVPToken` mock return | `List.of(new UnsignedVPToken(FormatType.LDP_VC, "key-ref", "EdDSA", new byte[]{}))` |
| `sendVPResponseToVerifier` mock arg | `anyList()` not `anyMap()` |
| Add Draft-23 submission test | `selectedCredentials` path, assert `buildDescriptorCredentialMap` called |
| Add DCQL submission test | `dcqlSelections` path, assert `buildQueryCredentialMap` called |
| Add DCQL validation test | `multiple=false` with 2 selections → expect `InvalidRequestException` |

### 8.3 `CredentialMatchingServiceTest.java`

| What to change | Detail |
|----------------|--------|
| Existing tests | Add `sessionData.specVersion = DRAFT_23` to all existing test setups |
| Add DCQL match test | Build `AuthorizationDcqlRequest` mock, assert `queryGroups` in response |
| Add optional set test | `required=false` credentialSet, assert `credentialSets[].required = false` in response |
| Add constraint test | `multiple=false` query with 2 matches → assert only first returned or all shown |

---

## 9. PR Breakdown

| PR | Scope | Files |
|----|-------|-------|
| PR-1 | Bump JAR + new enums/DTOs | `pom.xml`, `SpecVersion.java`, `DcqlQueryGroup.java`, `DcqlCredentialSelection.java` |
| PR-2 | DTO field additions + session specVersion | `VerifiablePresentationSessionData`, `DecryptedCredentialDTO`, `MatchingCredentialsResponseDTO`, `SubmitPresentationRequestDTO`, `VPResponseDTO` |
| PR-3 | OpenID4VPService fixes + resolveDcqlQuery | `OpenID4VPService.java` + `OpenID4VPServiceTest.java` |
| PR-4 | WalletPresentationServiceImpl — both submission paths | `WalletPresentationServiceImpl.java` + `WalletPresentationServiceTest.java` |
| PR-5 | CredentialMatchingServiceImpl — DCQL branch + controller specVersion storage | `CredentialMatchingServiceImpl.java`, `WalletPresentationsController.java` + `CredentialMatchingServiceTest.java` |

---

## 10. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Local JAR not installed | Build fails | Run `mvn install -DskipTests` in inji-openid4vp first |
| `WalletConfig` empty-list issue | Verifier rejects wallet metadata | Use explicit values (PR-3) |
| Wrong map key in `constructUnsignedVPToken` | Library builds VP for wrong descriptor | `descriptorId` field on DTO + `buildDescriptorCredentialMap` (PR-4) |
| DCQL `multiple=false` not enforced | User submits invalid VP | `validateDcqlSelections()` (PR-4) |
| `specVersion` null in old sessions | NPE after deploy | Default to `DRAFT_23` when null — `specVersion == SpecVersion.V1_0` check is null-safe |
| `authenticateVerifier` 3-arg call | `NoSuchMethodException` at runtime (hard to catch) | All call sites use 1-arg overload; flag in `WalletConfig` |
| `validatePreRegisteredVerifier` not passed to `create()` | Wrong verifier validation behaviour | Compute `shouldValidateClient` before `create()`; store in session for replay |

---

## 11. Approval Checklist

- [ ] Approve local 0.8.0 JAR strategy (install before build)
- [ ] Approve simultaneous Draft-23 + OVP 1.0 support in one release
- [ ] Approve `specVersion` field in session DTO
- [ ] Approve `descriptorId` field on `DecryptedCredentialDTO`
- [ ] Approve `dcqlSelections` as new field in submit request body
- [ ] Approve `queryGroups` in matching response for DCQL flows
- [ ] Approve 5-PR split strategy
