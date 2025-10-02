package scot.gov.scotaccountclient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Controller handling all logout operations for the ScotAccount client
 * application.
 *
 * <p>
 * This controller manages three distinct logout flows:
 * </p>
 *
 * <h3>1. User-Initiated Front-Channel Logout</h3>
 * <p>
 * Endpoints: GET/POST /logout
 * </p>
 * <ul>
 * <li>Triggered when user clicks "logout" button</li>
 * <li>Clears local session and cookies</li>
 * <li>Redirects to ScotAccount's end_session_endpoint for complete logout</li>
 * <li>ScotAccount redirects back to /logout/logged-out when done</li>
 * </ul>
 *
 * <h3>2. OIDC Back-Channel Logout</h3>
 * <p>
 * Endpoint: POST /logout/backchannel
 * </p>
 * <ul>
 * <li>Called directly by ScotAccount Identity Provider</li>
 * <li>Receives signed JWT logout_token</li>
 * <li>Validates token signature and claims per OIDC spec</li>
 * <li>Invalidates local session</li>
 * <li>Returns HTTP 200 OK (no redirect)</li>
 * </ul>
 *
 * <h3>3. Post-Logout Callback</h3>
 * <p>
 * Endpoint: GET /logout/logged-out
 * </p>
 * <ul>
 * <li>Called by ScotAccount after front-channel logout completes</li>
 * <li>Simply redirects user back to home page</li>
 * </ul>
 *
 * @see <a href=
 *      "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC
 *      RP-Initiated Logout</a>
 * @see <a href=
 *      "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC
 *      Back-Channel Logout</a>
 */
@Controller
@RequestMapping("/logout")
public class LogoutController {
    private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);

    /** Application cookies to clear during logout */
    private static final String[] COOKIES_TO_DELETE = { "JSESSIONID", "XSRF-TOKEN" };

    /** OIDC event URI that must be present in backchannel logout tokens */
    private static final String LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout";

    /** ScotAccount's end_session_endpoint URL for RP-initiated logout */
    @Value("${scotaccount.logout-endpoint}")
    private String endSessionEndpoint;

    /** Expected JWT issuer for backchannel logout token validation */
    @Value("${spring.security.oauth2.client.provider.scotaccount.issuer-uri}")
    private String expectedIssuer;

    /** Expected JWT audience (client ID) for backchannel logout token validation */
    @Value("${spring.security.oauth2.client.registration.scotaccount.client-id}")
    private String expectedAudience;

    /** JWT utility for validating logout tokens */
    private final JwtUtil jwtUtil;

    public LogoutController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // ======================================================================================
    // USER-INITIATED LOGOUT (FRONT-CHANNEL)
    // ======================================================================================

    /**
     * Handles user-initiated logout via POST request.
     *
     * <p>
     * This endpoint is typically called when the user clicks a logout button/link.
     * Both GET and POST methods are supported for maximum compatibility.
     * </p>
     *
     * @param request  HTTP request
     * @param response HTTP response for setting cookies
     * @return Redirect to ScotAccount's logout endpoint or home page
     */
    @PostMapping
    public String initiateLogoutPost(HttpServletRequest request, HttpServletResponse response) {
        return performFrontChannelLogout(request, response);
    }

    /**
     * Handles user-initiated logout via GET request.
     *
     * <p>
     * This endpoint is typically called when the user clicks a logout button/link.
     * Both GET and POST methods are supported for maximum compatibility.
     * </p>
     *
     * @param request  HTTP request
     * @param response HTTP response for setting cookies
     * @return Redirect to ScotAccount's logout endpoint or home page
     */
    @GetMapping
    public String initiateLogoutGet(HttpServletRequest request, HttpServletResponse response) {
        return performFrontChannelLogout(request, response);
    }

    /**
     * Callback endpoint after ScotAccount completes the logout process.
     *
     * <p>
     * ScotAccount redirects the user here after successfully logging them out
     * at the Identity Provider level. This is the final step in the front-channel
     * logout flow.
     * </p>
     *
     * @param request HTTP request (may contain state parameter for validation)
     * @return Redirect to application home page
     */
    @GetMapping("/logged-out")
    public String handlePostLogoutCallback(HttpServletRequest request) {
        logger.info("Post-logout callback received from ScotAccount");
        return "redirect:/";
    }

    // ======================================================================================
    // BACKCHANNEL LOGOUT (SERVER-TO-SERVER)
    // ======================================================================================

    /**
     * Handles OIDC Back-Channel Logout requests from ScotAccount Identity Provider.
     *
     * <p>
     * <b>OIDC Back-Channel Logout Specification Compliance:</b>
     * </p>
     * <ul>
     * <li>Accepts POST with application/x-www-form-urlencoded body</li>
     * <li>Receives signed JWT in logout_token parameter</li>
     * <li>Validates JWT signature using JWKS endpoint</li>
     * <li>Validates all required JWT claims per spec</li>
     * <li>Returns HTTP 200 OK on success (no redirect)</li>
     * <li>Returns HTTP 400 Bad Request on validation failure</li>
     * <li>Sets Cache-Control: no-store header</li>
     * </ul>
     *
     * <p>
     * <b>Flow:</b>
     * </p>
     * <ol>
     * <li>ScotAccount sends POST with logout_token</li>
     * <li>Validate token parameter is present</li>
     * <li>Validate JWT signature and claims</li>
     * <li>Invalidate user's session</li>
     * <li>Return 200 OK</li>
     * </ol>
     *
     * @param request  HTTP request containing logout_token parameter
     * @param response HTTP response for setting headers
     * @return ResponseEntity with HTTP 200 OK or 400 Bad Request
     * @see <a href=
     *      "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC
     *      Back-Channel Logout Spec</a>
     */
    @PostMapping({ "/backchannel", "/back-channel" })
    @ResponseBody
    public ResponseEntity<Void> handleBackchannelLogout(HttpServletRequest request, HttpServletResponse response) {
        logger.info("[BACKCHANNEL-LOGOUT] Request received at {}", request.getRequestURI());

        // Step 1: Extract and validate logout_token parameter
        String logoutToken = request.getParameter("logout_token");
        if (logoutToken == null || logoutToken.trim().isEmpty()) {
            logger.warn("[BACKCHANNEL-LOGOUT] Missing logout_token parameter");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        logger.debug("[BACKCHANNEL-LOGOUT] Logout token received (truncated): {}...",
                logoutToken.substring(0, Math.min(40, logoutToken.length())));

        // Step 2: Validate JWT signature and claims
        try {
            validateLogoutToken(logoutToken);
        } catch (Exception e) {
            logger.error("[BACKCHANNEL-LOGOUT] Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        // Step 3: Invalidate local session
        invalidateSession(request);

        // Step 4: Set cache control header (spec recommendation)
        response.setHeader("Cache-Control", "no-store");

        logger.info("[BACKCHANNEL-LOGOUT] Successfully processed");
        return ResponseEntity.ok().build();
    }

    // ======================================================================================
    // PRIVATE HELPER METHODS
    // ======================================================================================

    /**
     * Performs the front-channel logout flow initiated by the user.
     *
     * <p>
     * <b>Steps:</b>
     * </p>
     * <ol>
     * <li>Extract ID token from authenticated user session</li>
     * <li>Clear Spring Security context</li>
     * <li>Invalidate HTTP session</li>
     * <li>Clear application cookies</li>
     * <li>Redirect to ScotAccount's end_session_endpoint with ID token hint</li>
     * </ol>
     *
     * @param request  HTTP request
     * @param response HTTP response for cookie manipulation
     * @return Redirect to ScotAccount logout or home page
     */
    private String performFrontChannelLogout(HttpServletRequest request, HttpServletResponse response) {
        try {
            logger.info("Front-channel logout initiated: {} {}", request.getMethod(), request.getRequestURI());

            // Step 1: Extract ID token for logout hint
            String idToken = extractIdTokenFromAuthentication();

            // Step 2: Clear local authentication state
            clearSecurityContext();
            invalidateSession(request);
            clearCookies(response);

            // Step 3: Redirect to ScotAccount for complete logout
            if (idToken != null) {
                String logoutUrl = buildScotAccountLogoutUrl(request, idToken);
                logger.info("Redirecting to ScotAccount end_session_endpoint");
                return "redirect:" + logoutUrl;
            } else {
                logger.warn("No ID token available - local logout only");
                return "redirect:/";
            }
        } catch (Exception e) {
            logger.error("Error during front-channel logout: {}", e.getMessage(), e);
            return "redirect:/?error=logout_error&message=" +
                    URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Extracts the ID token from the current authentication context.
     *
     * @return ID token string, or null if not available
     */
    private String extractIdTokenFromAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
                logger.debug("ID token extracted from authenticated user");
                return oidcUser.getIdToken().getTokenValue();
            } else {
                logger.debug("Principal is not OidcUser: {}",
                        oauthToken.getPrincipal().getClass().getSimpleName());
            }
        } else {
            logger.debug("No OAuth2 authentication found");
        }

        return null;
    }

    /**
     * Clears the Spring Security context.
     */
    private void clearSecurityContext() {
        SecurityContextHolder.clearContext();
        logger.debug("Security context cleared");
    }

    /**
     * Invalidates the HTTP session if one exists.
     *
     * @param request HTTP request containing the session
     */
    private void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionId = session.getId();

            // Clear all attributes before invalidation
            Enumeration<String> attributeNames = session.getAttributeNames();
            while (attributeNames.hasMoreElements()) {
                session.removeAttribute(attributeNames.nextElement());
            }

            // Invalidate the session
            try {
                session.invalidate();
                logger.debug("Session invalidated: {}", sessionId);
            } catch (IllegalStateException e) {
                logger.debug("Session already invalidated: {}", sessionId);
            }
        } else {
            logger.debug("No active session to invalidate");
        }
    }

    /**
     * Clears application cookies by setting them to expire immediately.
     *
     * @param response HTTP response for adding cookie headers
     */
    private void clearCookies(HttpServletResponse response) {
        Arrays.stream(COOKIES_TO_DELETE).forEach(cookieName -> {
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            response.addCookie(cookie);
            logger.debug("Cookie cleared: {}", cookieName);
        });
    }

    /**
     * Builds the complete logout URL for ScotAccount's end_session_endpoint.
     *
     * <p>
     * Constructs URL with required parameters:
     * </p>
     * <ul>
     * <li>id_token_hint - for identifying the user's session</li>
     * <li>post_logout_redirect_uri - where to redirect after logout</li>
     * <li>state - security parameter to prevent CSRF</li>
     * </ul>
     *
     * @param request HTTP request for constructing callback URL
     * @param idToken ID token to include as hint
     * @return Complete logout URL for redirect
     */
    private String buildScotAccountLogoutUrl(HttpServletRequest request, String idToken) {
        // Build the post-logout redirect URI
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();

        // Only include port if it's not a standard port
        boolean isStandardPort = (scheme.equals("http") && serverPort == 80) ||
                                 (scheme.equals("https") && serverPort == 443);

        String postLogoutRedirectUri;
        if (isStandardPort) {
            postLogoutRedirectUri = String.format("%s://%s/logout/logged-out", scheme, serverName);
        } else {
            postLogoutRedirectUri = String.format("%s://%s:%d/logout/logged-out", scheme, serverName, serverPort);
        }

        // Generate secure state parameter
        String state = generateSecureState();

        // Build the complete logout URL
        return UriComponentsBuilder.fromUriString(endSessionEndpoint)
                .queryParam("id_token_hint", idToken)
                .queryParam("post_logout_redirect_uri", postLogoutRedirectUri)
                .queryParam("state", state)
                .build()
                .toUriString();
    }

    /**
     * Generates a cryptographically secure random state parameter.
     *
     * @return Base64-encoded random state string
     */
    private String generateSecureState() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Validates a logout token JWT according to OIDC Back-Channel Logout
     * specification.
     *
     * <p>
     * <b>Validation performed:</b>
     * </p>
     * <ol>
     * <li>JWT signature verification using JWKS</li>
     * <li>Issuer (iss) matches expected ScotAccount issuer</li>
     * <li>Audience (aud) contains this client's ID</li>
     * <li>Issued At (iat) claim is present</li>
     * <li>Events claim contains backchannel-logout event URI</li>
     * <li>Either subject (sub) or session ID (sid) is present</li>
     * <li>Nonce claim is NOT present (per spec requirement)</li>
     * </ol>
     *
     * @param logoutToken The logout token JWT string to validate
     * @throws Exception if any validation check fails
     */
    private void validateLogoutToken(String logoutToken) throws Exception {
        // Validate JWT signature and parse claims
        Claims claims = jwtUtil.validateJwt(logoutToken);
        logger.debug("[BACKCHANNEL-LOGOUT] JWT signature validated, checking claims");

        // Validation 1: Issuer
        validateIssuer(claims);

        // Validation 2: Audience
        validateAudience(claims);

        // Validation 3: Issued At
        validateIssuedAt(claims);

        // Validation 4: Events claim
        validateEvents(claims);

        // Validation 5: Subject or Session ID
        validateSubjectOrSessionId(claims);

        // Validation 6: Nonce must NOT be present
        validateNonceAbsent(claims);

        logger.info("[BACKCHANNEL-LOGOUT] Logout token validation successful");
    }

    /**
     * Validates the issuer (iss) claim matches expected value.
     */
    private void validateIssuer(Claims claims) throws IllegalArgumentException {
        String issuer = claims.getIssuer();
        if (issuer == null || !issuer.equals(expectedIssuer)) {
            throw new IllegalArgumentException(
                    String.format("Invalid issuer: expected '%s', got '%s'", expectedIssuer, issuer));
        }
        logger.debug("[BACKCHANNEL-LOGOUT] Issuer valid: {}", issuer);
    }

    /**
     * Validates the audience (aud) claim contains this client's ID.
     * Audience can be either a single string or an array of strings.
     */
    private void validateAudience(Claims claims) throws IllegalArgumentException {
        Object audClaim = claims.get("aud");
        boolean isValid = false;

        if (audClaim instanceof String) {
            isValid = expectedAudience.equals(audClaim);
        } else if (audClaim instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> audiences = (List<String>) audClaim;
            isValid = audiences.contains(expectedAudience);
        }

        if (!isValid) {
            throw new IllegalArgumentException(
                    String.format("Invalid audience: expected '%s' in %s", expectedAudience, audClaim));
        }
        logger.debug("[BACKCHANNEL-LOGOUT] Audience valid: {}", audClaim);
    }

    /**
     * Validates the issued at (iat) claim is present.
     */
    private void validateIssuedAt(Claims claims) throws IllegalArgumentException {
        if (claims.getIssuedAt() == null) {
            throw new IllegalArgumentException("Missing required 'iat' (issued at) claim");
        }
        logger.debug("[BACKCHANNEL-LOGOUT] Issued at valid: {}", claims.getIssuedAt());
    }

    /**
     * Validates the events claim contains the backchannel logout event URI.
     */
    private void validateEvents(Claims claims) throws IllegalArgumentException {
        @SuppressWarnings("unchecked")
        Map<String, Object> events = claims.get("events", Map.class);

        if (events == null || !events.containsKey(LOGOUT_EVENT_URI)) {
            throw new IllegalArgumentException(
                    String.format("Missing or invalid 'events' claim - expected '%s'", LOGOUT_EVENT_URI));
        }
        logger.debug("[BACKCHANNEL-LOGOUT] Events claim valid");
    }

    /**
     * Validates that either subject (sub) or session ID (sid) claim is present.
     * Per OIDC spec, at least one must be present to identify the logout target.
     */
    private void validateSubjectOrSessionId(Claims claims) throws IllegalArgumentException {
        String sub = claims.getSubject();
        String sid = claims.get("sid", String.class);

        if (sub == null && sid == null) {
            throw new IllegalArgumentException("Either 'sub' or 'sid' claim must be present");
        }
        logger.debug("[BACKCHANNEL-LOGOUT] Subject/Session valid - sub: {}, sid: {}", sub, sid);
    }

    /**
     * Validates that nonce claim is NOT present.
     * Per OIDC Back-Channel Logout spec, logout tokens must not contain nonce.
     */
    private void validateNonceAbsent(Claims claims) throws IllegalArgumentException {
        String nonce = claims.get("nonce", String.class);
        if (nonce != null) {
            throw new IllegalArgumentException("Logout token must not contain 'nonce' claim (per OIDC spec)");
        }
    }
}
