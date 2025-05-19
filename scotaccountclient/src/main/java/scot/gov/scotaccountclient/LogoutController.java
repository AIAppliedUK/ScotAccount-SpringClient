package scot.gov.scotaccountclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Cookie;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Collections;

@Controller
@RequestMapping("/logout")
public class LogoutController {
    private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);
    private static final String[] COOKIES_TO_DELETE = {
            "JSESSIONID",
            "SCOTACCOUNT_SESSION",
            "access_token",
            "id_token",
            "refresh_token",
            "XSRF-TOKEN"
    };

    @Value("${scotaccount.logout-endpoint}")
    private String endSessionEndpoint;

    @PostMapping
    public String logoutPost(HttpServletRequest request, HttpServletResponse response) {
        return handleLogout(request, response);
    }

    @GetMapping
    public String logoutGet(HttpServletRequest request, HttpServletResponse response) {
        return handleLogout(request, response);
    }

    @GetMapping("/logged-out")
    public String loggedOut(HttpServletRequest request) {
        logger.info("Received post-logout redirect from ScotAccount");
        return "redirect:/";
    }

    private String handleLogout(HttpServletRequest request, HttpServletResponse response) {
        try {
            logger.info("Initiating logout process for {} request to {}", request.getMethod(), request.getRequestURI());
            logger.debug("Request headers: {}", Collections.list(request.getHeaderNames()).stream()
                    .collect(java.util.stream.Collectors.toMap(
                            name -> name,
                            request::getHeader)));

            // Get the ID token if user is authenticated
            String idToken = null;
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
                if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
                    idToken = oidcUser.getIdToken().getTokenValue();
                    logger.debug("Retrieved ID token from authentication");
                } else {
                    logger.warn("Principal is not an OidcUser: {}", oauthToken.getPrincipal().getClass().getName());
                }
            } else {
                logger.warn("Authentication is not an OAuth2AuthenticationToken: {}",
                        authentication != null ? authentication.getClass().getName() : "null");
            }

            // Clear the security context first
            SecurityContextHolder.clearContext();
            logger.debug("Cleared security context");

            // Invalidate the current session
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.debug("Invalidating session: {}", session.getId());
                // Clear all session attributes
                Enumeration<String> attributeNames = session.getAttributeNames();
                while (attributeNames.hasMoreElements()) {
                    String attributeName = attributeNames.nextElement();
                    session.removeAttribute(attributeName);
                }
                session.invalidate();
            } else {
                logger.debug("No active session found");
            }

            // Clear all relevant cookies
            Arrays.stream(COOKIES_TO_DELETE).forEach(cookieName -> {
                Cookie cookie = new Cookie(cookieName, null);
                cookie.setPath("/");
                cookie.setMaxAge(0);
                cookie.setHttpOnly(true);
                cookie.setSecure(true);
                response.addCookie(cookie);
                logger.debug("Cleared cookie: {}", cookieName);
            });

            // Construct the logout URL with the ID token and post-logout redirect
            if (idToken != null) {
                String postLogoutRedirectUri = request.getScheme() + "://" + request.getServerName() + ":" +
                        request.getServerPort() + "/logout/logged-out";
                String encodedRedirectUri = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8);
                String encodedIdToken = URLEncoder.encode(idToken, StandardCharsets.UTF_8);
                String state = generateState();
                String encodedState = URLEncoder.encode(state, StandardCharsets.UTF_8);

                String logoutUrl = UriComponentsBuilder.fromUriString(endSessionEndpoint)
                        .queryParam("id_token_hint", encodedIdToken)
                        .queryParam("post_logout_redirect_uri", encodedRedirectUri)
                        .queryParam("state", encodedState)
                        .build()
                        .toUriString();

                logger.info("Redirecting to ScotAccount logout endpoint: {}", logoutUrl);
                logger.debug("Logout parameters - id_token_hint: {}, post_logout_redirect_uri: {}, state: {}",
                        encodedIdToken, encodedRedirectUri, encodedState);
                return "redirect:" + logoutUrl;
            } else {
                logger.warn("No ID token found for logout");
                return "redirect:/";
            }
        } catch (Exception e) {
            logger.error("Error during logout process: {}", e.getMessage(), e);
            return "redirect:/?error=logout_error&message=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    private String generateState() {
        // Generate a random state parameter for security
        byte[] randomBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}