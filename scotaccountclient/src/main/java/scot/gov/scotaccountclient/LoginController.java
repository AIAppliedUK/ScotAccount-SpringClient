package scot.gov.scotaccountclient;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Controller responsible for handling OAuth2/OIDC authentication outcomes in
 * the Scotaccount client application.
 * This controller implements both success and failure handling for the
 * authentication process,
 * managing token processing, session storage, and error handling.
 * 
 * Key responsibilities:
 * <ul>
 * <li>Processes successful OAuth2/OIDC authentication</li>
 * <li>Handles authentication failures</li>
 * <li>Manages token validation and storage</li>
 * <li>Maintains session state</li>
 * </ul>
 * 
 * On successful authentication:
 * <ul>
 * <li>Validates and decodes access tokens using JWT decoder</li>
 * <li>Processes ID tokens for OIDC users</li>
 * <li>Stores token information in the session</li>
 * <li>Manages OAuth2 authorized client state</li>
 * <li>Redirects to the home page</li>
 * </ul>
 * 
 * On authentication failure:
 * <ul>
 * <li>Logs detailed error information</li>
 * <li>Stores error details in the session</li>
 * <li>Provides error information to the user interface</li>
 * <li>Handles various failure scenarios (token errors, invalid client,
 * etc.)</li>
 * </ul>
 * 
 * Security features:
 * <ul>
 * <li>Token validation and verification</li>
 * <li>Secure session management</li>
 * <li>Error message sanitization</li>
 * <li>Comprehensive error logging</li>
 * </ul>
 */
@Controller
public class LoginController implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    /** Logger instance for this class */
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    /** Service for managing OAuth2 authorized clients */
    private final OAuth2AuthorizedClientService authorizedClientService;

    /** Decoder for validating JWTs */
    private final JwtDecoder jwtDecoder;

    /**
     * Constructs a new LoggedInController with the required dependencies.
     *
     * @param authorizedClientService Service for managing OAuth2 authorized clients
     * @param jwtDecoder              Decoder for validating JWTs
     */
    public LoginController(OAuth2AuthorizedClientService authorizedClientService, JwtDecoder jwtDecoder) {
        this.authorizedClientService = authorizedClientService;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Handles successful authentication by processing the OAuth2 token.
     *
     * @param request        The HTTP request
     * @param response       The HTTP response
     * @param authentication The successful authentication object
     * @throws IOException if there's an error processing the request/response
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        logger.info("Authentication successful for user: {}", authentication.getName());
        logger.debug("Authentication details: {}", authentication);

        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            logger.error("Authentication is not an OAuth2AuthenticationToken: {}", authentication.getClass().getName());
            response.sendRedirect("/?error=true&message=Invalid authentication type");
            return;
        }

        OAuth2AuthenticationToken oauth2Auth = (OAuth2AuthenticationToken) authentication;
        if (!(oauth2Auth.getPrincipal() instanceof OidcUser)) {
            logger.error("Principal is not an OidcUser: {}", oauth2Auth.getPrincipal().getClass().getName());
            response.sendRedirect("/?error=true&message=Invalid user type");
            return;
        }

        OidcUser oidcUser = (OidcUser) oauth2Auth.getPrincipal();
        HttpSession session = request.getSession();

        try {
            logger.debug("Loading authorized client for registration ID: {} and principal: {}",
                    oauth2Auth.getAuthorizedClientRegistrationId(), oauth2Auth.getName());

            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    oauth2Auth.getAuthorizedClientRegistrationId(),
                    oauth2Auth.getName());

            if (authorizedClient == null) {
                logger.error("No authorized client found for registration ID: {} and principal: {}",
                        oauth2Auth.getAuthorizedClientRegistrationId(), oauth2Auth.getName());
                session.setAttribute("token_error", "No authorized client found");
                response.sendRedirect("/");
                return;
            }

            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            String tokenValue = accessToken.getTokenValue();
            logger.debug("Access token obtained successfully");

            try {
                Jwt jwt = jwtDecoder.decode(tokenValue);
                Map<String, Object> claims = jwt.getClaims();
                logger.debug("JWT decoded successfully with claims: {}", claims);

                session.setAttribute("access_token", tokenValue);
                session.setAttribute("access_token_claims", claims);
                session.setAttribute("id_token", oidcUser.getIdToken().getTokenValue());
                logger.info("Session attributes set successfully");
            } catch (Exception e) {
                logger.error("Error decoding JWT", e);
                session.setAttribute("token_error", "Access token error: Invalid token");
            }
        } catch (Exception e) {
            logger.error("Error processing authentication success", e);
            session.setAttribute("token_error", "Error processing authentication: " + e.getMessage());
        }

        response.sendRedirect("/");
    }

    /**
     * Handles authentication failures by logging the error and redirecting to the
     * login page.
     *
     * @param request   The HTTP request
     * @param response  The HTTP response
     * @param exception The authentication exception that occurred
     * @throws IOException      if there's an error processing the request/response
     * @throws ServletException if there's a servlet-related error
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        logger.error("Authentication failed", exception);
        logger.error("Error message: {}", exception.getMessage());
        logger.error("Error type: {}", exception.getClass().getName());
        if (exception.getCause() != null) {
            logger.error("Root cause: {}", exception.getCause().getMessage());
        }
        logger.error("Request URI: {}", request.getRequestURI());
        logger.error("Query string: {}", request.getQueryString());

        HttpSession session = request.getSession();
        session.setAttribute("auth_error", exception.getMessage());
        session.setAttribute("auth_error_type", exception.getClass().getSimpleName());

        String encodedMessage = URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8.toString());
        response.sendRedirect("/?error=true&message=" + encodedMessage);
    }
}