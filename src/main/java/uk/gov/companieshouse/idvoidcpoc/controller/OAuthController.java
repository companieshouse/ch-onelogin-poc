package uk.gov.companieshouse.idvoidcpoc.controller;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
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
import java.util.*;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.*;
import uk.gov.companieshouse.idvoidcpoc.dao.Oauth2AuthorisationsDao;
import uk.gov.companieshouse.idvoidcpoc.dao.UsersDao;
import uk.gov.companieshouse.idvoidcpoc.repository.OauthRepository;
import uk.gov.companieshouse.idvoidcpoc.repository.UsersRepository;
import uk.gov.companieshouse.idvoidcpoc.utils.Oidc;

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
        // response.addCookie(new Cookie("__FLP", "HELLO"));

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

        List<UsersDao> user = usersRepository.findByEmail(userInfo.getEmailAddress());
        if (user.size() == 1) {
            model.addAttribute("email_found", true);
            model.addAttribute("user_id", user.get(0).getId());
        } else {
            model.addAttribute("email_not_found", true);
        }

        // Add details to model to display on results page
        model.addAttribute("access_token", tokens.getAccessToken());
        model.addAttribute("id_token", payload);
        model.addAttribute("user_info", userInfo.getEmailAddress());

        if (journeyLevel.equals("result")) {
            LOG.info("journey level is result, so show results page");
            return "result";
        }

        LOG.info("journey level is not result, so continue with federated login");
        if (redirectURL != null) {
            return "redirect:http://" + redirectURL;
        }

        generateAndStoreAuthorisationCode();
        Cookie c = oauth2GenerateProviderCookie(response);
        response.addCookie(c);
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            System.out.println(cookie.toString());
            System.out.println(cookie.getDomain());
        }

        System.out.println(request.getCookies());
        return "result";
    }

    @GetMapping("/oauth/iv")
    public RedirectView loginIV(Model model,
            HttpServletRequest request, HttpServletResponse response) throws URISyntaxException {
        LOG.info("Authorizing with Identity Verification");

        // Generate random state string for pairing the response to the request
        AuthorizationRequest authorizationRequest = oidcClient.buildIVAuthorizeRequest();

        // Use this URI to send the end-user's browser to the server
        return new RedirectView(authorizationRequest.toURI().toString());
    }

    public void generateAndStoreAuthorisationCode() {
        // Generate Code
        Random rd = new Random();
        byte[] arr = new byte[32];
        rd.nextBytes(arr);

        // Encode random bytes
        String code = Base64.getEncoder().encodeToString(arr);

        // Create record for DB
        Oauth2AuthorisationsDao oad = new Oauth2AuthorisationsDao();
        oad.setCode("test_code");
        oad.setClientID("test_client_id");
        oad.setCodeValidUntil(409281574);

        // TODO: Add user_details to Oauth2AuthorisationsDao

        // Store record in DB
        oauthRepository.insert(oad);
    }

    public Cookie oauth2GenerateProviderCookie(HttpServletResponse response) {
        LOG.info("Creating FLP cookie");

        String cookieContentEncoded = "eyJhbGciOiJkaXIiLCJ0eXAiOiJKV0UiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..m-qUaMN3dQKZACaEu6hziA.eLfNw9TmVtlMqpneiedsNUbvdaXTkfxv_bQCCMak9DY.bkdAZKEl8dBKCR0va-s4Fg";
        Cookie c = new Cookie("__FLP", cookieContentEncoded);
        c.setDomain("account.chs.local");
        return c;
    }
}
