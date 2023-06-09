package uk.gov.companieshouse.idvoidcpoc.controller;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.*;
import uk.gov.companieshouse.idvoidcpoc.dao.Oauth2AuthorisationsDao;
import uk.gov.companieshouse.idvoidcpoc.dao.OneLoginDataDao;
import uk.gov.companieshouse.idvoidcpoc.dao.UserDetailsDao;
import uk.gov.companieshouse.idvoidcpoc.dao.UsersDao;
import uk.gov.companieshouse.idvoidcpoc.repository.OauthRepository;
import uk.gov.companieshouse.idvoidcpoc.repository.UsersRepository;
import uk.gov.companieshouse.idvoidcpoc.utils.Oidc;
import uk.gov.companieshouse.session.Session;
import uk.gov.companieshouse.session.SessionImpl;

@Controller
@RequestMapping("/poc")
public class OAuthController {

    @Autowired
    private Oidc oidcClient;

    private final UsersRepository usersRepository;
    private final OauthRepository oauthRepository;

    @Autowired
    public OAuthController(UsersRepository usersRepository, OauthRepository oauthRepository) {
        this.usersRepository = usersRepository;
        this.oauthRepository = oauthRepository;
    }

    @Value("${client_id}")
    private String clientID;

    @Value("${base.url}")
    private String baseURI;

    @Value("${journey.level}")
    private String journeyLevel;
    private static final Logger LOG = LoggerFactory.getLogger(Oidc.class);

    @GetMapping("/oauth/login")
    public RedirectView loginBasic(@RequestParam(name = "redirect_url", required = false) String redirectURL,
            Model model,
            HttpServletRequest request, HttpServletResponse response) throws URISyntaxException {
        LOG.info("Authorizing with One Login");
        cleanCookies(response);
        if (redirectURL != null) {
            response.addCookie(new Cookie("redirect_url", redirectURL));
        }
        // Generate random state string for pairing the response to the request
        AuthorizationRequest authorizationRequest = oidcClient.buildAuthorizeRequest();

        // Get the state from the request
        State state = authorizationRequest.getState();

        // Store cookie in session with state value
        response.addCookie(new Cookie("state", state.toString()));

        Cookie c = oauth2GenerateProviderCookie(response);

        // Use authorization request to redirect user to One Login
        return new RedirectView(authorizationRequest.toURI().toString().concat("&nonce=12345"));
    }

    private static void cleanCookies(HttpServletResponse response) {
        Cookie c = new Cookie("redirect_url", null);
        c.setMaxAge(0);
        response.addCookie(c);
    }

    @GetMapping("/oauth/callback")
    public String callback(@CookieValue(value = "state") String cookieState,
            @CookieValue(value = "redirect_url", required = false) String redirectURL,
            @RequestParam(name = "state") String callbackState,
            @RequestParam(name = "code") String code,
            Model model,
            HttpServletRequest request, HttpServletResponse response)
            throws IOException, ParseException, URISyntaxException {
        LOG.info("Callback function after authorizing with One Login");

        // Check state
        if (!cookieState.equals(callbackState)) {
            LOG.error("State mismatch");
            return "error";
        }

        // Call /token endpoint to retrieve ID token, Access token and Refresh token
        OIDCTokens tokens = oidcClient.makeTokenRequest(code);

        // Validate token returned from One Login
        oidcClient.validateIdToken(tokens.getIDToken());

        // Get ID token from /token response
        String payload = tokens.getIDToken().getParsedParts()[1].decodeToString();

        // Call /userinfo endpoint
        var userInfo = oidcClient.makeUserInfoRequest(tokens.getAccessToken());

        // Add details to model to display on results page
        model.addAttribute("access_token", tokens.getAccessToken());
        model.addAttribute("id_token", payload);
        model.addAttribute("user_info", userInfo.getEmailAddress());

        model.addAttribute("phone_number", userInfo.getPhoneNumber());

        var coreIdentityJWT =
                userInfo.getStringClaim("https://vocab.account.gov.uk/v1/coreIdentityJWT");
        var passportIdentityJWT =
                userInfo.getClaim("https://vocab.account.gov.uk/v1/passport");

        String sub;
        try {
            sub = tokens.getIDToken().getJWTClaimsSet().getClaim("sub").toString();
        } catch (java.text.ParseException e) {
            LOG.info("error getting sub claim");
            throw new RuntimeException(e);
        }
        model.addAttribute("one_login_user_id", sub);

        List<UsersDao> user = usersRepository.findByEmail(userInfo.getEmailAddress());
        if (user.size() == 1) {
            LOG.info("Existing user found in mongo");
            String oneLoginUserId = user.get(0).getOneLoginData().getOneLoginUserId();
            if (!Objects.equals(oneLoginUserId, "") && !Objects.equals(oneLoginUserId, sub)) {
                LOG.error("ONE LOGIN USER ID [" + oneLoginUserId + "] does not match ID in MongoDB [" + oneLoginUserId + "]");
                throw new RuntimeException();
            }
            model.addAttribute("email_found", true);
            model.addAttribute("user_id", user.get(0).getId());
            storeOneLoginUserDetails(user.get(0), sub);
        } else {
            LOG.info("No existing user found in mongo. Adding now.");
            model.addAttribute("email_not_found", true);
            storeNewUserDetails(userInfo.getEmailAddress(), sub);
            user = usersRepository.findByEmail(userInfo.getEmailAddress());
        }

        if (coreIdentityJWT != null) {

            try {
                oidcClient.validateUserIdentityCredential(coreIdentityJWT, sub);
            } catch (Exception e) {
                LOG.info("User Identity Credentials Invalid: " + e.getMessage());
                throw new RuntimeException();
            }
            LOG.info("User Identity Credentials Valid");

            try {
                JSONObject userDetails = oidcClient.getJSONPayloadFromJWT(coreIdentityJWT).getJSONObject("vc").getJSONObject("credentialSubject");

                JSONArray nameObjects = userDetails.getJSONArray("name").getJSONObject(0).getJSONArray("nameParts");
                var names = new ArrayList();
                for (int i = 0; i < nameObjects.length(); i++) {

                    names.add(nameObjects.getJSONObject(i).get("value"));
                }
                String fullName = String.join(" ", names);

                model.addAttribute("full_name", fullName);

                model.addAttribute("date_of_birth", userDetails.getJSONArray("birthDate").getJSONObject(0).get("value"));

            } catch (JSONException e) {
                throw new RuntimeException(e);
            }
        }

        boolean coreIdentityClaimPresent = Objects.nonNull(coreIdentityJWT);
        model.addAttribute("core_identity_claim_present", coreIdentityClaimPresent);
        model.addAttribute("core_identity_claim", coreIdentityJWT);

        boolean passportIdentityClaimPresent = Objects.nonNull(passportIdentityJWT);
        model.addAttribute("passport_identity_claim_present", passportIdentityClaimPresent);
        model.addAttribute("passport_identity_claim", passportIdentityJWT);

        generateAndStoreAuthorisationCode(user.get(0));

        // __FLP cookie
        Cookie flpCookie = oauth2GenerateProviderCookie(response);
        response.addCookie(flpCookie);

        // __ZXS cookie
        Cookie zxsCookie = generateZXSCookie(response);
        response.addCookie(zxsCookie);

        // __SID cookie
        Cookie sidCookie = generateSIDCookie();
        response.addCookie(sidCookie);

        // Store session in redis
        Session newSession = new SessionImpl();
        Map<String, Object> mySessionData = newSession.getData();
        mySessionData.put("foo", "bar");
        mySessionData.put("expires", 1999999999);

        Map<String, Object> accessToken = new HashMap<>(){
            {
                put("access_token", "CDE9yYsRJ3M4CUX_hce3jernoWBLP7WFRIS9QNtzxL9fsKhnjW25mUuD8O9SYixZ5R99J78mrDt0Uzk4MudHEQ");
                put("expires_in", 3600);
                put("refresh_token", "_YI2Gawkvkb4qG7byKWysY5bGwQP3N98vpG5FWCuFkALWjHo9-z88VQiZvkFclRt4XS0rPNbvt0pGOVyUYj4Sw");
                put("token_type", "Bearer");
            }
        };

        Map<String, Object> userProfile = new HashMap<>(){
            {
                put("locale", "GB_en");
                put("permissions", new HashMap<>());
                put("scope", "https://identity.company-information.service.gov.uk/user.write-full");
                put("email", userInfo.getEmailAddress());
                put("forename", null);
                put("surname", null);
                put("id", "Y2VkZWVlMzhlZWFjY2M4MzQ3MT");
            }
        };

        Map<String, Object> signinInfo = new HashMap<>(){
            {
                put("access_token", accessToken);
                put("admin_permissions", "0");
                put("signed_in", 1);
                put("user_profile", userProfile);
                put(".hijacked", null);
                put(".zxs_key", "d0414a9c8383605f7eb7d77e608565b1072132b28415e69defdf9feff417c69a");
            }
        };
        mySessionData.put("signin_info", signinInfo);

        newSession.setCookieId("G58PIgF5746nNA+YoLfCA3XLMIENWRkb6BPSvmw1JxEztUKx2zlDgUc");
        newSession.store();

        if (journeyLevel.equals("result")) {
            LOG.info("journey level is result, so show results page");
            return "result";
        }

        LOG.info("journey level is not result, so continue with federated login");
        // if (redirectURL != null) {
        LOG.info("redirecting");
        String code2 = "rUMT3qffpPo-Lczc-jfKFFhZLbDd7QTA_Mk6ylieDCs";
        String state = "eyJhbGciOiJkaXIiLCJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..YTjMcZybySS-fTXgoyHgmw.1-L_lbSUx9K2oR28OdkQRY9kp2pXefAITZTNvq1IHP4Xhs06MwU8AZQEmms2XXFeUyoIC_8lBHsCQOfYZ0Qd_Q.za6qUbLHVgwHz5DiUtT7rg";
        // return "redirect:http://chs.local/oauth2/user/callback?state=" + state + "&code=" + code2;
        return "redirect:http://chs.local";
        // return "redirect:http://" + redirectURL;
        // }
    }

    @GetMapping("/oauth/iv")
    public RedirectView loginIV(Model model,
            HttpServletRequest request, HttpServletResponse response) throws URISyntaxException {
        LOG.info("Authorizing with Identity Verification");

        cleanCookies(response);
        
        // Generate random state string for pairing the response to the request
        AuthorizationRequest authorizationRequest = oidcClient.buildIVAuthorizeRequest();

        // Get the state from the request
        State state = authorizationRequest.getState();

        // Store cookie in session with state value
        response.addCookie(new Cookie("state", state.toString()));
        // Use this URI to send the end-user's browser to the server
        return new RedirectView(authorizationRequest.toURI().toString());
    }

    public void generateAndStoreAuthorisationCode(UsersDao user) {
        // Generate Code
        Random rd = new Random();
        byte[] arr = new byte[32];
        rd.nextBytes(arr);

        // Encode random bytes
        String code = Base64.getEncoder().withoutPadding().encodeToString(arr);

        // Create record for DB
        Oauth2AuthorisationsDao oad = new Oauth2AuthorisationsDao();

        oad.setCode(code);
        oad.setClientID("test_client_id");
        oad.setCodeValidUntil(Math.toIntExact(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) + 30));
        oad.setTokenValidUntil(Math.toIntExact(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) + 3600));

        UserDetailsDao udd = new UserDetailsDao();
        udd.setUserID(user.getId());
        udd.setEmail(user.getEmail());
        oad.setUserDetails(udd);
        oad.setIdentityProvider("companies_house");

        // TODO: Add more fields to Oauth2AuthorisationsDao

        // Store record in DB
        oauthRepository.insert(oad);
    }

    public void storeOneLoginUserDetails(UsersDao user, String oneLoginUserID) {
        user.getOneLoginData().setOneLoginUserId(oneLoginUserID);
        usersRepository.save(user);
    }

    public void storeNewUserDetails(String email, String oneLoginUserID) {
        UsersDao user = new UsersDao();
        user.setEmail(email);
        user.setOneLoginData(new OneLoginDataDao());
        user.getOneLoginData().setOneLoginUserId(oneLoginUserID);
        user.setLocale("GB_en");
        user.setCreated(LocalDateTime.now());
        usersRepository.insert(user);
    }

    public Cookie oauth2GenerateProviderCookie(HttpServletResponse response){
        LOG.info("Creating FLP cookie");

        String cookieContentEncoded = "eyJhbGciOiJkaXIiLCJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..m-qUaMN3dQKZACaEu6hziA.eLfNw9TmVtlMqpneiedsNUbvdaXTkfxv_bQCCMak9DY.bkdAZKEl8dBKCR0va-s4Fg";
        Cookie c = new Cookie("__FLP", cookieContentEncoded);
        c.setDomain("account.chs.local");
        c.setPath("/");
        return c;
    }

    public Cookie generateZXSCookie(HttpServletResponse response) {
        LOG.info("Creating ZXS cookie");

        String cookieContentEncoded = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldFIn0..alveCuvMTh3ENgPNAiP-Pg.2KIA0DwP5vXR6GrkMLX3QbQDBpPe6O4ugmCgd__mJZSoSVPBcMzm8MreocMHI0pAAc5LDS9dO4VGdTlHrNPbj-6qt2z-SNsH2hCkcgQ_DXg.D40_QZO4cgfjba7GJ4W3Qg";
        Cookie c = new Cookie( "__ZXS", cookieContentEncoded);
        c.setDomain("account.chs.local");
        c.setPath("/oauth2/user");
        return c;
    }

    public Cookie generateSIDCookie() {
        LOG.info("Creating SID cookie");
        String cookieContentEncoded = "G58PIgF5746nNA+YoLfCA3XLMIENWRkb6BPSvmw1JxEztUKx2zlDgUc";
        Cookie c = new Cookie( "__SID", cookieContentEncoded);
        c.setDomain("chs.local");
        c.setPath("/");
        return c;
    }
}
