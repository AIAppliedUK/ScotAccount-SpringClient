package scot.gov.scotaccountclient;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller that handles the home page of the application.
 * 
 * <p>
 * This controller handles requests for the main entry point of the application,
 * displaying different content based on whether the user is authenticated or
 * not.
 * For authenticated users, it retrieves and displays their ScotAccount
 * attributes.
 * </p>
 */
@Controller
public class HomeController {
    /** Logger instance for this class */
    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    /** Service for managing authorized OAuth2 clients */
    private final OAuth2AuthorizedClientService authorizedClientService;

    /** Service for retrieving user attributes from ScotAccount. */
    private final AttributeService attributeService;

    /**
     * Constructs a HomeController with the required dependencies.
     *
     * @param authorizedClientService service for managing authorized OAuth2 clients
     * @param attributeService        service for retrieving user attributes from
     *                                ScotAccount
     */
    public HomeController(OAuth2AuthorizedClientService authorizedClientService, AttributeService attributeService) {
        this.authorizedClientService = authorizedClientService;
        this.attributeService = attributeService;
    }

    /**
     * Handles requests to the home page.
     * 
     * <p>
     * This method:
     * </p>
     * <ul>
     * <li>For unauthenticated users: displays the welcome page</li>
     * <li>For authenticated users: displays the welcome page with their user
     * information and attributes</li>
     * </ul>
     *
     * @param model the model for the view
     * @return the view name to render
     */
    @GetMapping("/")
    public String home(Model model) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (!(auth instanceof OAuth2AuthenticationToken)) {
                logger.info("No authenticated user");
                return "index";
            }

            // If user is authenticated, show the index page with user info
            OAuth2AuthenticationToken oauth2Auth = (OAuth2AuthenticationToken) auth;
            OAuth2User oauth2User = oauth2Auth.getPrincipal();
            logger.info("User is authenticated: {}", oauth2User.getName());

            // Log the available attributes for debugging
            logger.debug("Available user attributes: {}", oauth2User.getAttributes());

            // Get the authorized client to access the token
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    oauth2Auth.getAuthorizedClientRegistrationId(),
                    oauth2Auth.getName());

            if (authorizedClient != null) {
                OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
                if (accessToken != null) {
                    logger.debug("Access token obtained successfully");

                    // Check if we have the required scopes for attributes
                    Set<String> scopes = accessToken.getScopes();
                    if (scopes != null && scopes.contains("openid") &&
                            (scopes.contains("scotaccount.address") || scopes.contains("scotaccount.email"))) {
                        Map<String, Object> attributes = attributeService.fetchAttributes(accessToken.getTokenValue());
                        if (attributes != null) {
                            // Log the additional attributes for debugging
                            logger.debug("Additional attributes from endpoint: {}", attributes);
                            Object verifiedClaims = attributes.get("verified_claims");
                            if (verifiedClaims != null) {
                                logger.debug("Verified claims found: {}", verifiedClaims);
                                // Ensure verifiedClaims is a List
                                if (verifiedClaims instanceof List) {
                                    model.addAttribute("verifiedClaims", verifiedClaims);
                                } else {
                                    logger.warn("Verified claims is not a List: {}", verifiedClaims.getClass());
                                    model.addAttribute("verifiedClaims", Collections.emptyList());
                                }
                            } else {
                                logger.warn("No verified claims found in attributes");
                                model.addAttribute("verifiedClaims", Collections.emptyList());
                            }
                        } else {
                            logger.warn("No attributes returned from attribute service");
                            model.addAttribute("verifiedClaims", Collections.emptyList());
                        }
                    } else {
                        logger.info("Access token does not have required scopes for attributes. Current scopes: {}",
                                scopes);
                        model.addAttribute("verifiedClaims", Collections.emptyList());
                        model.addAttribute("needsVerification", true);
                    }
                } else {
                    logger.warn("No access token found in authorized client");
                    model.addAttribute("verifiedClaims", Collections.emptyList());
                }
            } else {
                logger.warn("No authorized client found");
                model.addAttribute("verifiedClaims", Collections.emptyList());
            }

            model.addAttribute("user", oauth2User);
            return "index";
        } catch (Exception e) {
            logger.error("Error in home method", e);
            throw e; // Let the error page handle it
        }
    }
}
