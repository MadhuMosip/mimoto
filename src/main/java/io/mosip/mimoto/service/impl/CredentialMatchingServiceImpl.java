package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.CredentialDTO;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.DcqlQueryGroup;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.service.CredentialFormatHandlerFactory;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.openID4VP.dcql.query.ClaimValue;
import io.mosip.openID4VP.dcql.query.ClaimsQuery;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static io.mosip.mimoto.exception.ErrorConstants.UNSUPPORTED_FORMAT;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
@Service
public class CredentialMatchingServiceImpl implements CredentialMatchingService {

    private static final String JSON_PATH_PREFIX = "$.";
    private static final String LDP_VC_FORMAT = "ldp_vc";
    private static final String PROOF_TYPE_KEY = "proof_type";
    private static final String SD_JWT_ALG_VALUES_KEY = "sd-jwt_alg_values";
    private static final String CREDENTIAL_SUBJECT_PREFIX = "credentialSubject.";
    private static final String ALG = "alg";
    private static final String CREDENTIAL_SUBJECT = "credentialSubject";
    private static final String SD = "_sd";
    private static final String META_VCT_VALUES = "vct_values";
    private static final String META_TYPE_VALUES = "type_values";
    private static final String TYPE = "type";
    private static final String VCT = "vct";

    private final ObjectMapper objectMapper;

    private final IssuersService issuersService;

    private final OpenID4VPService openID4VPService;

    private final WalletCredentialService walletCredentialService;

    private final CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    public CredentialMatchingServiceImpl(ObjectMapper objectMapper, IssuersService issuersService, OpenID4VPService openID4VPService, WalletCredentialService walletCredentialService, CredentialFormatHandlerFactory credentialFormatHandlerFactory) {
        this.objectMapper = objectMapper;
        this.issuersService = issuersService;
        this.openID4VPService = openID4VPService;
        this.walletCredentialService = walletCredentialService;
        this.credentialFormatHandlerFactory = credentialFormatHandlerFactory;
    }


    @Override
    public MatchingCredentialsDTO getMatchingCredentials(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String base64Key) throws ApiNotAccessibleException, IOException {

        log.info("getMatchingCredentials: walletId={}, specVersion={}",
                walletId, sessionData != null ? sessionData.getSpecVersion() : "null");

        List<DecryptedCredentialDTO> decryptedCredentials =
                walletCredentialService.getDecryptedCredentials(walletId, base64Key);

        // Route to the correct matching path based on the spec version stored in session.
        // When specVersion is null (old sessions or first deploy), default to Draft-23.
        if (sessionData != null && SpecVersion.V1_0.equals(sessionData.getSpecVersion())) {
            return matchWithDcqlQuery(sessionData, walletId, decryptedCredentials);
        }
        return matchWithPresentationDefinition(sessionData, walletId, base64Key, decryptedCredentials);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Draft-23 — Presentation Definition matching
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Matches wallet credentials against each {@link InputDescriptor} in the verifier's
     * {@link PresentationDefinition}.
     *
     * <p>Sets {@link DecryptedCredentialDTO#setDescriptorId} on every matched credential
     * so the submission step can use the correct key when calling
     * {@code openID4VP.constructUnsignedVPToken(Map<descriptorId, List<Credential>>)}.
     */
    private MatchingCredentialsDTO matchWithPresentationDefinition(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String base64Key,
            List<DecryptedCredentialDTO> decryptedCredentials)
            throws ApiNotAccessibleException, IOException {

        PresentationDefinition presentationDefinition = openID4VPService.resolvePresentationDefinition(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered());

        validateInputParameters(presentationDefinition, walletId, base64Key);

        if (decryptedCredentials.isEmpty()) {
            return MatchingCredentialsDTO.builder()
                    .matchingCredentialsResponse(createEmptyResponseWithMissingClaims(presentationDefinition))
                    .matchingCredentials(new ArrayList<>())
                    .build();
        }

        List<InputDescriptor> descriptors = presentationDefinition.getInputDescriptors();
        Map<Integer, List<CredentialDTO>> matchesByDescriptor = new HashMap<>();
        Set<String> missingClaims = new HashSet<>();
        // Records which InputDescriptor.id each credential satisfies.
        Map<String, String> credentialToDescriptor = new HashMap<>();

        IntStream.range(0, descriptors.size()).forEach(i -> {
            InputDescriptor descriptor = descriptors.get(i);
            List<CredentialDTO> matches = decryptedCredentials.stream()
                    .filter(dto -> matchesInputDescriptor(dto.getCredential(), descriptor))
                    .peek(dto -> credentialToDescriptor.put(dto.getId(), descriptor.getId()))
                    .map(this::buildAvailableCredential)
                    .collect(Collectors.toList());
            if (!matches.isEmpty()) {
                matchesByDescriptor.put(i, matches);
            } else {
                missingClaims.addAll(extractClaimsFromInputDescriptor(descriptor));
            }
        });

        // De-duplicate: a credential can satisfy multiple descriptors but should appear once.
        Set<String> seen = new HashSet<>();
        List<CredentialDTO> availableCredentials = matchesByDescriptor.values().stream()
                .flatMap(List::stream)
                .filter(c -> seen.add(c.getCredentialId()))
                .collect(Collectors.toList());

        Set<String> matchedIds = availableCredentials.stream()
                .map(CredentialDTO::getCredentialId)
                .collect(Collectors.toSet());

        // Stamp each matched DecryptedCredentialDTO with the descriptor id it satisfied.
        List<DecryptedCredentialDTO> matchedCredentials = decryptedCredentials.stream()
                .filter(dto -> matchedIds.contains(dto.getId()))
                .peek(dto -> dto.setDescriptorId(credentialToDescriptor.get(dto.getId())))
                .collect(Collectors.toList());

        MatchingCredentialsResponseDTO response = MatchingCredentialsResponseDTO.builder()
                .availableCredentials(availableCredentials)
                .missingClaims(missingClaims)
                .isDcql(false)
                .build();

        return MatchingCredentialsDTO.builder()
                .matchingCredentialsResponse(response)
                .matchingCredentials(matchedCredentials)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OVP 1.0 — DCQL matching
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Matches wallet credentials against each {@link CredentialQuery} in the verifier's
     * {@link DCQLQuery}.
     *
     * <p>Returns one {@link DcqlQueryGroup} per credential query, carrying the matched
     * credentials, any missing claim paths, and the {@code required} / {@code multiple}
     * flags from the query definition.  The UI uses these groups to render per-query
     * selection sections instead of the Draft-23 flat list.
     *
     * <p>Also stamps {@link DecryptedCredentialDTO#setDescriptorId} with the query id
     * so the submission step uses the correct map key.
     */
    private MatchingCredentialsDTO matchWithDcqlQuery(
            VerifiablePresentationSessionData sessionData,
            String walletId,
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

        List<DcqlQueryGroup> queryGroups = new ArrayList<>();
        // All credentials that matched at least one query (for session cache).
        List<DecryptedCredentialDTO> allMatched = new ArrayList<>();

        for (CredentialQuery credentialQuery : dcqlQuery.getCredentials()) {
            List<DecryptedCredentialDTO> matches = decryptedCredentials.stream()
                    .filter(dto -> matchesDcqlQuery(dto.getCredential(), credentialQuery))
                    .map(dto -> DecryptedCredentialDTO.builder()
                            .id(dto.getId())
                            .walletId(dto.getWalletId())
                            .credential(dto.getCredential())
                            .credentialMetadata(dto.getCredentialMetadata())
                            .createdAt(dto.getCreatedAt())
                            .updatedAt(dto.getUpdatedAt())
                            .descriptorId(credentialQuery.getId())
                            .build())
                    .collect(Collectors.toList());

            allMatched.addAll(matches);

            Set<String> missingClaims = matches.isEmpty()
                    ? extractMissingClaimsFromQuery(credentialQuery) : Set.of();

            List<CredentialDTO> credentialDTOs = matches.stream()
                    .map(this::buildAvailableCredential)
                    .collect(Collectors.toList());

            // Default required=true; will be overridden for optional credential_set entries below.
            queryGroups.add(DcqlQueryGroup.builder()
                    .queryId(credentialQuery.getId())
                    .required(true)
                    .multiple(credentialQuery.getMultiple())
                    .availableCredentials(credentialDTOs)
                    .missingClaims(missingClaims)
                    .build());
        }

        // Apply required=false for query IDs that only appear in optional credential_sets.
        if (dcqlQuery.getCredentialSets() != null) {
            Set<String> optionalQueryIds = dcqlQuery.getCredentialSets().stream()
                    .filter(cs -> !cs.getRequired())
                    .flatMap(cs -> cs.getOptions().stream().flatMap(List::stream))
                    .collect(Collectors.toSet());
            queryGroups.forEach(group -> {
                if (optionalQueryIds.contains(group.getQueryId())) {
                    group.setRequired(false);
                }
            });
        }

        List<DecryptedCredentialDTO> uniqueMatched = allMatched.stream()
                .collect(Collectors.toMap(
                        DecryptedCredentialDTO::getId,
                        dto -> dto,
                        (first, second) -> first,
                        LinkedHashMap::new))
                .values().stream()
                .collect(Collectors.toList());

        log.info("matchWithDcqlQuery: walletId={}, queries={}, totalMatched={}",
                walletId, queryGroups.size(), uniqueMatched.size());

        MatchingCredentialsResponseDTO response = MatchingCredentialsResponseDTO.builder()
                .queryGroups(queryGroups)
                .isDcql(true)
                .build();

        return MatchingCredentialsDTO.builder()
                .matchingCredentialsResponse(response)
                .matchingCredentials(uniqueMatched)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DCQL credential matching helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns {@code true} when {@code vc} satisfies the given {@link CredentialQuery}.
     *
     * <p>Checks (in order):
     * <ol>
     *   <li>Format must match (case-insensitive string comparison).</li>
     *   <li>If the query specifies {@code claims}, every claim path must exist in the
     *       credential.  If the claim also specifies {@code values}, at least one value
     *       must match.</li>
     * </ol>
     */
    private boolean matchesDcqlQuery(VCCredentialResponse vc, CredentialQuery credentialQuery) {
        // Step 1: format check (ldp_vc, vc+sd-jwt, dc+sd-jwt).
        if (!formatsMatch(credentialQuery.getFormat(), vc.getFormat())) {
            return false;
        }
        // Step 2: meta constraints (vct_values for SD-JWT, type_values for LDP).
        if (!matchesDcqlMeta(vc, credentialQuery.getMeta())) {
            return false;
        }
        // Step 3: claim path checks (optional).
        if (credentialQuery.getClaims() != null) {
            return credentialQuery.getClaims().stream()
                    .allMatch(claimQuery -> matchesDcqlClaimPath(vc, claimQuery));
        }
        return true;
    }

    /** SD-JWT VC and DC formats share the same structure; treat them as compatible for DCQL. */
    private boolean formatsMatch(String queryFormat, String credentialFormat) {
        if (queryFormat.equalsIgnoreCase(credentialFormat)) {
            return true;
        }
        return CredentialFormat.isSdJwt(queryFormat) && CredentialFormat.isSdJwt(credentialFormat);
    }

    @SuppressWarnings("unchecked")
    private boolean matchesDcqlMeta(VCCredentialResponse vc, Map<String, Object> meta) {
        if (meta == null || meta.isEmpty()) {
            return true;
        }

        Object vctValuesObj = meta.get(META_VCT_VALUES);
        if (vctValuesObj instanceof List<?> vctValues && !vctValues.isEmpty()) {
            String credentialVct = extractVct(vc);
            if (credentialVct == null) {
                return false;
            }
            boolean vctMatches = vctValues.stream()
                    .anyMatch(expected -> credentialVct.equalsIgnoreCase(String.valueOf(expected)));
            if (!vctMatches) {
                return false;
            }
        }

        Object typeValuesObj = meta.get(META_TYPE_VALUES);
        if (typeValuesObj instanceof List<?> typeValues && !typeValues.isEmpty()) {
            Set<String> credentialTypes = extractCredentialTypes(vc);
            boolean typeMatches = typeValues.stream()
                    .anyMatch(typeCombo -> matchesTypeCombo(credentialTypes, typeCombo));
            if (!typeMatches) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesTypeCombo(Set<String> credentialTypes, Object typeCombo) {
        if (!(typeCombo instanceof List<?> combo) || combo.isEmpty()) {
            return false;
        }
        return combo.stream()
                .map(String::valueOf)
                .allMatch(credentialTypes::contains);
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractCredentialTypes(VCCredentialResponse vc) {
        if (!CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vc.getFormat())) {
            return Set.of();
        }
        CredentialFormatHandler handler = credentialFormatHandlerFactory.getHandler(vc.getFormat());
        Map<String, Object> properties = (Map<String, Object>) handler.extractAllCredentialProperties(vc);
        if (properties == null) {
            return Set.of();
        }
        return extractTypesFromValue(properties.get(TYPE));
    }

    private Set<String> extractTypesFromValue(Object typeValue) {
        if (typeValue instanceof List<?> list) {
            return list.stream().map(String::valueOf).collect(Collectors.toSet());
        }
        if (typeValue instanceof String type) {
            return Set.of(type);
        }
        return Set.of();
    }

    @SuppressWarnings("unchecked")
    private String extractVct(VCCredentialResponse vc) {
        if (!CredentialFormat.isSdJwt(vc.getFormat())) {
            return null;
        }
        CredentialFormatHandler handler = credentialFormatHandlerFactory.getHandler(vc.getFormat());
        Map<String, Map<String, Object>> allClaims =
                (Map<String, Map<String, Object>>) handler.extractAllCredentialProperties(vc);
        if (allClaims == null) {
            return null;
        }
        Map<String, Object> publicClaims = allClaims.get("publicClaims");
        if (publicClaims == null || publicClaims.get(VCT) == null) {
            return null;
        }
        return publicClaims.get(VCT).toString();
    }

    /**
     * Returns {@code true} when the credential contains a value at the path defined
     * in {@link ClaimsQuery}.  If the query also lists expected {@code values}, at
     * least one must equal the value found in the credential.
     */
    private boolean matchesDcqlClaimPath(VCCredentialResponse vc, ClaimsQuery claimQuery) {
        if (claimQuery.getPath() == null || claimQuery.getPath().isEmpty()) {
            return true;
        }

        // Build a JSONPath string from the path list, e.g. ["credentialSubject","name"] → "$.credentialSubject.name"
        String jsonPath = JSON_PATH_PREFIX + claimQuery.getPath().stream()
                .map(Object::toString)
                .collect(Collectors.joining("."));

        Object credentialData = getCredentialData(vc);
        List<Object> found = evaluateJsonPath(jsonPath, credentialData);
        if (found.isEmpty()) return false;

        // When the query specifies expected values, at least one must match.
        if (claimQuery.getValues() != null && !claimQuery.getValues().isEmpty()) {
            return claimQuery.getValues().stream()
                    .anyMatch(expected -> found.stream().anyMatch(actual -> dcqlValueMatches(actual, expected)));
        }
        return true;
    }

    /** Compares a credential field value against a DCQL {@link ClaimValue}. */
    private boolean dcqlValueMatches(Object actual, ClaimValue expected) {
        if (expected instanceof ClaimValue.StringValue sv) {
            return sv.getValue().equals(actual.toString());
        }
        if (expected instanceof ClaimValue.LongValue lv) {
            // Kotlin Long is a primitive long; box it before comparing with the Object `actual`.
            return Long.valueOf(lv.getValue()).equals(actual);
        }
        if (expected instanceof ClaimValue.BoolValue bv) {
            return Boolean.valueOf(bv.getValue()).equals(actual);
        }
        return false;
    }

    /**
     * Extracts the claim paths that the DCQL query requires but could not be found,
     * returned as dot-separated path strings for display in the UI.
     */
    private Set<String> extractMissingClaimsFromQuery(CredentialQuery credentialQuery) {
        if (credentialQuery.getClaims() == null) return Set.of();
        return credentialQuery.getClaims().stream()
                .filter(cq -> cq.getPath() != null && !cq.getPath().isEmpty())
                .map(cq -> cq.getPath().stream().map(Object::toString).collect(Collectors.joining(".")))
                .collect(Collectors.toSet());
    }

    private void validateInputParameters(PresentationDefinition presentationDefinition, String walletId, String base64Key) throws IllegalArgumentException {
        if (walletId == null || walletId.trim().isEmpty()) {
            throw new IllegalArgumentException("Wallet ID cannot be null or empty");
        }

        if (base64Key == null || base64Key.trim().isEmpty()) {
            throw new IllegalArgumentException("Base64 key cannot be null or empty");
        }

        if (presentationDefinition == null) {
            throw new IllegalArgumentException("Presentation definition cannot be null");
        }

        if (presentationDefinition.getInputDescriptors().isEmpty()) {
            throw new IllegalArgumentException("Presentation definition must contain at least one input descriptor");
        }

        IntStream.range(0, presentationDefinition.getInputDescriptors().size())
                .filter(i -> {
                    InputDescriptor descriptor = presentationDefinition.getInputDescriptors().get(i);
                    return descriptor.getId().trim().isEmpty();
                })
                .findFirst()
                .ifPresent(i -> { throw new IllegalArgumentException("Input descriptor at index " + i + " must have a valid ID"); });
    }

    private MatchingCredentialsResponseDTO createEmptyResponseWithMissingClaims(PresentationDefinition presentationDefinition) {
        log.info("No credentials found for wallet");
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(Collections.emptyList())
                .missingClaims(new HashSet<>(extractRequiredClaims(presentationDefinition)))
                .build();
    }

    private List<String> extractClaimsFromInputDescriptor(InputDescriptor inputDescriptor) {
        return extractClaimsFromFields(inputDescriptor.getConstraints().getFields(), false);
    }

    /**
     * Common method to extract claims from an array of fields.
     *
     * @param fields      List of Fields objects to extract claims from
     * @param deduplicate Whether to deduplicate claims using LinkedHashSet
     * @return List of extracted claim keys
     */
    private List<String> extractClaimsFromFields(List<Fields> fields, boolean deduplicate) {
        if (fields == null) {
            return Collections.emptyList();
        }

        Stream<String> claimsStream = fields.stream()
                .filter(Objects::nonNull)
                .filter(field -> !field.getPath().isEmpty())
                .flatMap(field -> field.getPath().stream())
                .map(this::extractClaimKeyFromPath)
                .filter(Objects::nonNull)
                .filter(claim -> !claim.isBlank());

        if (deduplicate) {
            return claimsStream.distinct().collect(Collectors.toList());
        } else {
            return claimsStream.collect(Collectors.toList());
        }
    }

    private boolean matchesInputDescriptor(VCCredentialResponse vc, InputDescriptor inputDescriptor) {
        Map<String, Map<String, List<String>>> formatToCheck = inputDescriptor.getFormat();

        if (!matchesFormat(vc, formatToCheck)) {
            return false;
        }

        if (inputDescriptor.getConstraints().getFields() != null) {
            return matchesConstraints(vc, inputDescriptor.getConstraints());
        }
        return true;
    }

    private boolean matchesFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        if (descriptorFormat == null) {
            return true;
        }

        String vcFormat = vc.getFormat();

        if (CredentialFormat.isSdJwt(vcFormat)) {
            String descriptorKey = resolveSdJwtDescriptorKey(vcFormat, descriptorFormat);
            if (descriptorKey != null) {
                return matchesSdJwtAlgorithm(vc, descriptorFormat, descriptorKey);
            }
        }
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(vcFormat) && descriptorFormat.containsKey(LDP_VC_FORMAT)) {
            return matchesLdpVcFormat(vc, descriptorFormat);
        }
        return false;
    }

    private boolean matchesLdpVcFormat(VCCredentialResponse vc, Map<String, Map<String, List<String>>> descriptorFormat) {
        Map<String, List<String>> ldpVcFormat = descriptorFormat.get(LDP_VC_FORMAT);

        if (ldpVcFormat == null) {
            return false;
        }

        if (!ldpVcFormat.containsKey(PROOF_TYPE_KEY)) {
            return false;
        }

        VCCredentialProperties ldpCredential = objectMapper.convertValue(vc.getCredential(), VCCredentialProperties.class);
        String vcProofType = ldpCredential.getProof() != null ? ldpCredential.getProof().getType() : null;
        List<String> requiredProofTypes = ldpVcFormat.get(PROOF_TYPE_KEY);

        if (requiredProofTypes == null || requiredProofTypes.isEmpty()) {
            return true;
        }

        return vcProofType != null && requiredProofTypes.contains(vcProofType);
    }

    private String resolveSdJwtDescriptorKey(String vcFormat, Map<String, Map<String, List<String>>> descriptorFormat) {
        if (descriptorFormat.containsKey(vcFormat)) {
            return vcFormat;
        }
        if (descriptorFormat.containsKey(CredentialFormat.VC_SD_JWT.getFormat())) {
            return CredentialFormat.VC_SD_JWT.getFormat();
        }
        if (descriptorFormat.containsKey(CredentialFormat.DC_SD_JWT.getFormat())) {
            return CredentialFormat.DC_SD_JWT.getFormat();
        }
        return null;
    }

    private boolean matchesSdJwtAlgorithm(VCCredentialResponse vc,
                                          Map<String, Map<String, List<String>>> requestFormat,
                                          String formatKey) {
        Map<String, List<String>> sdJwtFormat = requestFormat.get(formatKey);
        if (vc.getCredential() == null || !(vc.getCredential() instanceof String sdJwtString)) {
            return false;
        }

        if (!sdJwtFormat.containsKey(SD_JWT_ALG_VALUES_KEY)) {
            return false;
        }

        String sdJwtAlgorithm = extractSdJwtAlgorithm(sdJwtString);
        Map<String, List<String>> requestFormatMap = requestFormat.get(formatKey);
        if (requestFormatMap != null) {
            List<?> requestAlgorithms = requestFormatMap.get(SD_JWT_ALG_VALUES_KEY);
            if (requestAlgorithms != null) {
                return requestAlgorithms.contains(sdJwtAlgorithm);
            }
            return true; // If no specific algorithms are required, any algorithm is acceptable
        }
        return false;
    }

    private String extractSdJwtAlgorithm(String sdJwtString) {
        if (sdJwtString == null || sdJwtString.trim().isEmpty()) {
            return null;
        }
        try {
            Map<String, Object> header = JwtUtils.parseJwtHeader(sdJwtString);
            return (String) header.get(ALG);
        } catch (Exception e) {
            log.warn("Failed to extract algorithm from SD-JWT header", e);
            return null;
        }
    }

    private boolean matchesConstraints(VCCredentialResponse vc, Constraints constraints) {
        if (constraints.getFields() == null) {
            return true;
        }

        return constraints.getFields().stream().allMatch(field -> {
            if (field.getPath().isEmpty()) {
                return true;
            }
            return field.getPath().stream().anyMatch(path -> matchesFieldPath(vc, path, field.getFilter()));
        });
    }

    private boolean matchesFieldPath(VCCredentialResponse vc, String path, Filter filter) {
        Object credentialData = getCredentialData(vc);

        List<Object> matches = evaluateJsonPath(path, credentialData);

        if (matches.isEmpty()) {
            return false;
        }

        return matches.stream().anyMatch(match -> matchesFilter(match, filter));
    }

    private Object getCredentialData(VCCredentialResponse vc) {
        String format = vc.getFormat();
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vc.getFormat());

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return credentialFormatHandler.extractAllCredentialProperties(vc);
        }
        if (CredentialFormat.isSdJwt(format)) {
            return extractMergedSdJwtClaims(vc, credentialFormatHandler);
        }
        throw new InvalidRequestException(UNSUPPORTED_FORMAT.getErrorCode(), "Unsupported credential format: " + format);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> extractMergedSdJwtClaims(VCCredentialResponse vc,
                                                           CredentialFormatHandler credentialFormatHandler) {
        Map<String, ?> extractedMap = credentialFormatHandler.extractAllCredentialProperties(vc);
        if (extractedMap == null) {
            return Collections.emptyMap();
        }
        Map<String, Map<String, Object>> allCredentialProperties = (Map<String, Map<String, Object>>) extractedMap;
        Map<String, Object> credentialClaimsMap = new HashMap<>();
        allCredentialProperties.values().forEach(credentialClaimsMap::putAll);
        return credentialClaimsMap;
    }

    private boolean matchesFilter(Object match, Filter filter) {
        if (filter == null) {
            return true;
        }

        String matchValue = match.toString();
        return matchValue.contains(filter.getPattern());

    }

    private List<Object> evaluateJsonPath(String path, Object json) {
        if (path == null || path.trim().isEmpty()) {
            return Collections.emptyList();
        }

        if (!path.startsWith(JSON_PATH_PREFIX)) {
            return Collections.emptyList();
        }

        if (json == null) {
            return Collections.emptyList();
        }

        try {
            Object result = JsonPath.read(json, path);

            if (result == null) {
                return Collections.emptyList();
            }

            if (result instanceof List) {
                return (List<Object>) result;
            }

            return Collections.singletonList(result);

        } catch (PathNotFoundException e) {
            log.debug("Path not found in JSON: {}", path);
            return Collections.emptyList();
        }
    }

    private List<String> extractRequiredClaims(PresentationDefinition presentationDefinition) {

        List<Fields> allFields = presentationDefinition.getInputDescriptors().stream()
                .filter(id -> id.getConstraints().getFields() != null)
                .flatMap(id -> id.getConstraints().getFields().stream())
                .collect(Collectors.toList());

        return extractClaimsFromFields(allFields, true);
    }

    private String extractClaimKeyFromPath(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        int lastDot = path.lastIndexOf('.');
        String tail = lastDot >= 0 ? path.substring(lastDot + 1) : path;
        if (tail.startsWith("$")) {
            tail = tail.substring(1);
        }
        return tail;
    }

    private CredentialDTO buildAvailableCredential(DecryptedCredentialDTO decryptedCredentialDTO) {
        String issuerId = decryptedCredentialDTO.getCredentialMetadata().getIssuerId();
        String credentialType = decryptedCredentialDTO.getCredentialMetadata().getCredentialType();

        String credentialTypeDisplayName = "Unknown Credential";
        String credentialTypeLogo = null;
        Map<String, Object> publicClaimsMap;
        Map<String, Object> sdClaimsMap;

        List<String> publicClaims = new ArrayList<>();
        List<String> sdClaims = new ArrayList<>();

        try {
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
            if (issuerConfig != null) {
                VerifiableCredentialResponseDTO credentialResponse = VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, "en", decryptedCredentialDTO.getId());
                credentialTypeDisplayName = credentialResponse.getCredentialTypeDisplayName();
                credentialTypeLogo = credentialResponse.getCredentialTypeLogo();
            }
        } catch (InvalidIssuerIdException | ApiNotAccessibleException e) {
            log.warn("Failed to fetch issuer config for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
        }

        if (CredentialFormat.isSdJwt(decryptedCredentialDTO.getCredential().getFormat())) {
            CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory
                    .getHandler(decryptedCredentialDTO.getCredential().getFormat());
            Map<String, Map<String, Object>> allClaims = (Map<String, Map<String, Object>>) credentialFormatHandler
                    .extractAllCredentialProperties(decryptedCredentialDTO.getCredential());

            publicClaimsMap = allClaims.get("publicClaims");
            sdClaimsMap = allClaims.get("sdClaims");

            if (publicClaimsMap != null) {
                publicClaims = extractPublicClaimPaths(publicClaimsMap);
            }

            if (sdClaimsMap != null) {
                sdClaims = extractSdClaimPaths(sdClaimsMap);
            }

        }


        return CredentialDTO.builder()
                .credentialId(decryptedCredentialDTO.getId())
                .credentialTypeDisplayName(credentialTypeDisplayName)
                .credentialTypeLogo(credentialTypeLogo)
                .format(decryptedCredentialDTO.getCredential().getFormat())
                .claims(publicClaims)
                .sdClaims(sdClaims)
                .build();
    }

    private List<String> extractPublicClaimPaths(Map<String, Object> publicClaimsMap) {
        List<String> paths = new ArrayList<>();
        Object credentialSubject = publicClaimsMap.get(CREDENTIAL_SUBJECT);
        if (credentialSubject instanceof Map) {
            Map<String, Object> csMap = (Map<String, Object>) credentialSubject;
            collectPaths(csMap, "$", paths);
        } else {
            // Remove standard JWT claims and SD-JWT metadata
            List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", SD, "_sd_alg", "id");
            metadataKeys.forEach(publicClaimsMap::remove);
            collectPaths(publicClaimsMap, "$", paths);
        }
        return paths;
    }

    private List<String> extractSdClaimPaths(Map<String, Object> sdClaimsMap) {
        List<String> paths = new ArrayList<>();
        for (String key : sdClaimsMap.keySet()) {
            String cleanKey = key.startsWith(CREDENTIAL_SUBJECT_PREFIX)
                    ? key.substring(CREDENTIAL_SUBJECT_PREFIX.length())
                    : key;
            paths.add(JSON_PATH_PREFIX + cleanKey);
        }
        return paths;
    }

    private void collectPaths(Map<String, Object> publicClaimsMap, String prefix, List<String> paths) {
        for (Map.Entry<String, Object> entry : publicClaimsMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Skip _sd keys
            if (SD.equals(key)) {
                continue;
            }

            String currentPath = prefix + "." + key;

            if (value instanceof Map) {
                collectPaths((Map<String, Object>) value, currentPath, paths);
            } else if (value instanceof List<?> listValue) {
                if (hasUniformKeys(listValue)) {
                    paths.add(currentPath);
                } else {
                    paths.add(currentPath);
                    for (Object item : listValue) {
                        if (item instanceof Map<?, ?> mapItem) {
                            collectPaths((Map<String, Object>) mapItem, currentPath, paths);
                        }
                    }
                }
            } else {
                paths.add(currentPath);
            }
        }
    }

    private boolean hasUniformKeys(List<?> list) {
        List<Set<Object>> keySets = list.stream()
                .filter(item -> item instanceof Map<?, ?>)
                .map(item -> {
                    Map<?, ?> m = (Map<?, ?>) item;
                    return new HashSet<Object>(m.keySet());
                })
                .collect(Collectors.toList());
    
        if (keySets.size() < 2 || keySets.size() != list.size()) {
            return false;
        }

        Set<Object> intersectionKeys = new HashSet<>(keySets.getFirst());
        keySets.forEach(intersectionKeys::retainAll);

        return !intersectionKeys.isEmpty();
    }
}