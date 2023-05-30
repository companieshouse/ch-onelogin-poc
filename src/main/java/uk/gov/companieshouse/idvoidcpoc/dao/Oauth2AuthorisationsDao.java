package uk.gov.companieshouse.idvoidcpoc.dao;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "oauth2_authorisations")
public class Oauth2AuthorisationsDao {

    @Id
    private String id;

    @Field("type")
    private String type;

    @Field("code")
    private String code;

    @Field("token_permissions")
    private TokenPermissionsDao tokenPermissions;

    @Field("user_details")
    private UserDetailsDao userDetails;

    @Field("code_associated_data")
    private String codeAssociatedData;

    @Field("requested_scope")
    private String requestedScope;

    @Field("permissions")
    private PermissionsDao permissions;

    @Field("code_valid_until")
    private int codeValidUntil;

    @Field("client_id")
    private String clientID;

    @Field("identity_provider")
    private String identityProvider;

    @Field("refresh_token_id")
    private String refreshTokenID;

    @Field("refresh_token_password")
    private String refreshTokenPassword;

    @Field("token")
    private String token;

    @Field("token_valid_until")
    private int tokenValidUntil;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public TokenPermissionsDao getTokenPermissions() {
        return tokenPermissions;
    }

    public void setTokenPermissions(TokenPermissionsDao tokenPermissions) {
        this.tokenPermissions = tokenPermissions;
    }

    public UserDetailsDao getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(UserDetailsDao userDetails) {
        this.userDetails = userDetails;
    }

    public String getCodeAssociatedData() {
        return codeAssociatedData;
    }

    public void setCodeAssociatedData(String codeAssociatedData) {
        this.codeAssociatedData = codeAssociatedData;
    }

    public String getRequestedScope() {
        return requestedScope;
    }

    public void setRequestedScope(String requestedScope) {
        this.requestedScope = requestedScope;
    }

    public PermissionsDao getPermissions() {
        return permissions;
    }

    public void setPermissions(PermissionsDao permissions) {
        this.permissions = permissions;
    }

    public int getCodeValidUntil() {
        return codeValidUntil;
    }

    public void setCodeValidUntil(int codeValidUntil) {
        this.codeValidUntil = codeValidUntil;
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(String identityProvider) {
        this.identityProvider = identityProvider;
    }

    public String getRefreshTokenID() {
        return refreshTokenID;
    }

    public void setRefreshTokenID(String refreshTokenID) {
        this.refreshTokenID = refreshTokenID;
    }

    public String getRefreshTokenPassword() {
        return refreshTokenPassword;
    }

    public void setRefreshTokenPassword(String refreshTokenPassword) {
        this.refreshTokenPassword = refreshTokenPassword;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public int getTokenValidUntil() {
        return tokenValidUntil;
    }

    public void setTokenValidUntil(int tokenValidUntil) {
        this.tokenValidUntil = tokenValidUntil;
    }
}
