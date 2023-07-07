package uk.gov.companieshouse.idvoidcpoc.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import net.minidev.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class Oidc {

    private static final Logger LOG = LoggerFactory.getLogger(Oidc.class);

    private final OIDCProviderMetadata providerMetadata;
    private final String idpUrl;
    private final ClientID clientId;

    @Value("${key.private}")
    private String privateKey;

    @Value("${key.onelogin.public}")
    private String oneLoginPublicKey;

    @Value( "${callback.url}")
    private String callback;

    public Oidc(@Value("${base.url}") String baseUrl, @Value("${client_id}") String clientId) {
        this.idpUrl = baseUrl;
        this.clientId = new ClientID(clientId);
        this.providerMetadata = loadProviderMetadata(baseUrl);
    }

    private OIDCProviderMetadata loadProviderMetadata(String baseUrl) {
        try {
            return OIDCProviderMetadata.resolve(new Issuer("https://oidc.integration.account.gov.uk/"));
        } catch (Exception e) {
            LOG.error("Unexpected exception thrown when loading provider metadata", e);
            throw new RuntimeException(e);
        }
    }

    public AuthorizationRequest buildAuthorizeRequest() throws URISyntaxException {
        LOG.info("Making Token Request");

        // The requested scope values for the token
        Scope scope = new Scope("openid","email");

        var authorizationRequestBuilder =
                new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(this.clientId),
                        new URI(this.callback))
                        .state(new State())
                        .nonce(new Nonce())
                        .endpointURI(new URI(this.idpUrl));

        return authorizationRequestBuilder.build();

    }

    public AuthorizationRequest buildIVAuthorizeRequest() throws URISyntaxException {
        // The requested scope values for the token
        Scope scope = new Scope("openid","email");

        String prompt = "none";
        Prompt authRequestPrompt;
        try {
            authRequestPrompt = Prompt.parse(prompt);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse prompt", e);
        }

        var claimsSetRequest = new ClaimsSetRequest();
        var identityEntry = new ClaimsSetRequest.Entry("https://vocab.account.gov.uk/v1/coreIdentityJWT")
                .withClaimRequirement(ClaimRequirement.ESSENTIAL);

        var passportEntry = new ClaimsSetRequest.Entry("https://vocab.account.gov.uk/v1/passport")
                .withClaimRequirement(ClaimRequirement.ESSENTIAL);

        claimsSetRequest = claimsSetRequest.add(identityEntry);
        claimsSetRequest = claimsSetRequest.add(passportEntry);

        // Create "vtr" array to request medium authentication (Cl.Cm) and a medium level of identity confidence (P2).
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("P2.Cl.Cm");

        var authorizationRequestBuilder =
                new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(this.clientId),
                        new URI(this.callback))
                        .state(new State())
                        .nonce(new Nonce())
                        .prompt(authRequestPrompt)
                        .endpointURI(new URI(this.idpUrl))
                        .customParameter("vtr", jsonArray.toJSONString());

        authorizationRequestBuilder.claims(
                new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest));

        return authorizationRequestBuilder.build();
    }
    public OIDCTokens makeTokenRequest(String authCode)
            throws URISyntaxException {
        LOG.info("Making Token Request");

        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode), new URI(this.callback));

        try {
            LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(5);
            Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
            JWTAuthenticationClaimsSet claimsSet =
                    new JWTAuthenticationClaimsSet(
                            this.clientId,
                            new Audience(this.providerMetadata.getTokenEndpointURI().toString()));
            claimsSet.getExpirationTime().setTime(expiryDate.getTime());

            var request =
                    new TokenRequest(
                            this.providerMetadata.getTokenEndpointURI(),
                            new PrivateKeyJWT(signJwtWithClaims(claimsSet.toJWTClaimsSet())),
                            codeGrant,
                            null,
                            null,
                            null);

            var tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

            if (!tokenResponse.indicatesSuccess()) {
                LOG.error("TokenRequest was unsuccessful");
                throw new RuntimeException(
                        tokenResponse.toErrorResponse().getErrorObject().toString());
            }

            LOG.info("TokenRequest was successful");

            Optional.of(tokenResponse)
                    .map(TokenResponse::toSuccessResponse)
                    .map(AccessTokenResponse::getTokens)
                    .map(Tokens::getAccessToken)
                    .map(AccessToken::getLifetime)
                    .ifPresentOrElse(
                            lifetime -> LOG.info("Access token expires in {}", lifetime),
                            () -> LOG.warn("No expiry on access token"));

            return tokenResponse.toSuccessResponse().getTokens().toOIDCTokens();

        } catch (ParseException | IOException e) {
            LOG.error("Unexpected exception thrown when making token request", e);
            throw new RuntimeException(e);
        }
    }

    public UserInfo makeUserInfoRequest(AccessToken accessToken)
            throws IOException, ParseException {
        LOG.info("Making userinfo request");
        var httpResponse =
                new UserInfoRequest(
                        this.providerMetadata.getUserInfoEndpointURI(),
                        new BearerAccessToken(accessToken.toString()))
                        .toHTTPRequest()
                        .send();

        var userInfoResponse = UserInfoResponse.parse(httpResponse);
        if (!userInfoResponse.indicatesSuccess()) {
            LOG.error("Userinfo request was unsuccessful");
            throw new RuntimeException(userInfoResponse.toErrorResponse().toString());
        }

        LOG.info("Userinfo request was successful");

        return userInfoResponse.toSuccessResponse().getUserInfo();
    }

    private SignedJWT signJwtWithClaims(JWTClaimsSet jwtClaimsSet) {
        PrivateKey pk;
        try{
            var kf = KeyFactory.getInstance("RSA");
            pk = (RSAPrivateKey)kf.generatePrivate(new PKCS8EncodedKeySpec(format(this.privateKey)));
        }catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        var signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), jwtClaimsSet);

        try {
            signedJWT.sign(new RSASSASigner(pk));
        } catch (JOSEException e) {
            LOG.error("Unable to sign secure request object", e);
            throw new RuntimeException("Unable to sign secure request object", e);
        }

        return signedJWT;
    }

    private byte[] format(String privateKey) throws IOException {
        var parse = Pattern.compile("(?m)(?s)^---*BEGIN.*---*$(.*)^---*END.*---*$.*");
        var encoded = parse.matcher(privateKey).replaceFirst("$1");

        return Base64.getMimeDecoder().decode(encoded);
    }

    public void validateIdToken(JWT idToken) throws MalformedURLException {
        LOG.info("Validating ID token");
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(30000, 30000);
        var idTokenValidator =
                new IDTokenValidator(
                        this.providerMetadata.getIssuer(),
                        this.clientId,
                        JWSAlgorithm.parse("ES256"),
                        this.providerMetadata.getJWKSetURI().toURL(),
                        resourceRetriever);

        try {
            idTokenValidator.validate(idToken, null);
        } catch (BadJOSEException | JOSEException e) {
            LOG.error("Unexpected exception thrown when validating ID token", e);
            throw new RuntimeException(e);
        }
    }

    public String[] decodeJWT(String jwt) {
        String[] chunks = jwt.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        String signature = new String(decoder.decode(chunks[2]));
        return new String[]{header, payload, signature};
    }

    public JSONObject getJSONPayloadFromJWT(String jwt) {
        String[] decodedJWT = decodeJWT(jwt);
        String data = decodedJWT[1];
        JSONObject jsonObj;
        try {
            jsonObj = new JSONObject(data);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
        return jsonObj;
    }

    public ArrayList<JSONObject> getJSONFromJWT(String jwt) {
        String[] decodedJWT = decodeJWT(jwt);
        ArrayList<JSONObject> jsonList2 = new ArrayList();
        for (int i = 0; i <= 1; i++) {
            String data = decodedJWT[i];
            JSONObject jsonObj;
            try {
                jsonObj = new JSONObject(data);
            } catch (JSONException e) {
                throw new RuntimeException(e);
            }
            jsonList2.add(jsonObj);
        }
        return jsonList2;
    }

    public void validateUserIdentityCredential (String coreIdentityJWT, String tokenSub) throws Exception {
        // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/process-identity-information/#validate-your-user-s-identity-credential

        LOG.info("coreIdentityJWT: " + coreIdentityJWT);

        ArrayList<JSONObject> jsonFromJWT = getJSONFromJWT(coreIdentityJWT);
        JSONObject header = jsonFromJWT.get(0);
        JSONObject payload = jsonFromJWT.get(1);

        // 1. check JWT `alg` header is `ES256`
        try {
            String alg = header.get("alg").toString();
            if (!Objects.equals(alg, "ES256")) {
                LOG.info("alg not ES256");
                throw new Exception();
            }
        } catch (JSONException e) {
            LOG.info("JSONException when checking alg");
            throw new RuntimeException(e);
        }

        // 2. Validate ES256 JWT Signature
        CoreIdentityValidator validator = CoreIdentityValidator.createValidator(oneLoginPublicKey);
        CoreIdentityValidator.Result isValidJWT = validator.isValid(coreIdentityJWT);
        if (isValidJWT.equals(CoreIdentityValidator.Result.INVALID) || validator.isValid(coreIdentityJWT).equals(CoreIdentityValidator.Result.NOT_VALIDATED)) {
                LOG.info("coreIdentityJWT not valid: " + isValidJWT);
                throw new Exception();
        }

        // 3. check `iss` claim is `https://identity.integration.account.gov.uk/`
        try {
            String iss = payload.get("iss").toString();
            if (!Objects.equals(iss, "https://identity.integration.account.gov.uk/")) {
                LOG.info("iss invalid");
                throw new Exception();
            }
        } catch (JSONException e) {
            LOG.info("JSONException when checking iss");
            throw new RuntimeException(e);
        }

        // 4. check `sub` claim matches the `sub` claim you received in the `id_token` from your token request
        try {
            String sub = payload.get("sub").toString();
            if (!sub.equals(tokenSub)) {
                LOG.info("sub invalid");
                throw new Exception();
            }
        } catch (JSONException e) {
            LOG.info("JSONException when checking sub");
            throw new RuntimeException();
        }

        // 5. check current time is before time in `exp` claim
        try {
            Instant exp = Instant.ofEpochSecond((Integer) payload.get("exp"));
            if (exp.compareTo(Instant.now()) < 0) {
                   LOG.info("EXPIRED");
                   throw new RuntimeException();
            }
        } catch (JSONException e) {
            LOG.info("JSONException when checking exp");
            throw new RuntimeException();
        }

        // 6. Check user's identity credential matches the level of confidence needed
        try {
            String vot = payload.get("vot").toString();
            if (!vot.equals("P2")) {
                throw new Exception();
            }
        } catch (JSONException e) {
            LOG.info("JSONException when checking vot");
            throw new RuntimeException();
        }
    }
}
