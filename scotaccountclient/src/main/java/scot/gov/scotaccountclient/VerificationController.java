package scot.gov.scotaccountclient;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.servlet.http.HttpSession;

/**
 * Controller for handling the verification flow after initial authentication.
 * This controller manages the process of requesting additional verified
 * attributes
 * from ScotAccount after the user has been authenticated.
 */
@Controller
public class VerificationController {

    private static final Logger logger = LoggerFactory.getLogger(VerificationController.class);
    private static final String SESSION_ACCESS_TOKEN_KEY = "verification_access_token";
    private static final String SESSION_SCOPES_KEY = "verification_scopes";
    private static final Set<String> ALLOWED_SCOPES = new HashSet<>(List.of(
            "openid",
            "scotaccount.gpg45.medium",
            "scotaccount.email",
            "scotaccount.address"));

    private final OAuth2AuthorizedClientService clientService;

    public VerificationController(OAuth2AuthorizedClientService clientService) {
        this.clientService = clientService;
    }

    /**
     * Displays the verification options page where users can select which
     * attributes
     * they want to verify.
     *
     * @param model   The Spring MVC model
     * @param user    The authenticated OIDC user
     * @param session The HTTP session
     * @return The name of the verification options template
     */
    @GetMapping("/verify")
    public String showVerificationOptions(
            Model model,
            @AuthenticationPrincipal OidcUser user,
            HttpSession session) {
        if (user == null) {
            logger.warn("Unauthenticated user attempted to access verification page");
            return "redirect:/login";
        }

        // Add user info and current verification status
        model.addAttribute("user", user);
        model.addAttribute("currentScopes", user.getAuthorities());
        model.addAttribute("allowedScopes", ALLOWED_SCOPES);

        // Add any error messages from redirects
        Object error = session.getAttribute("verificationError");
        if (error != null) {
            model.addAttribute("error", error);
            session.removeAttribute("verificationError");
        }

        return "verify";
    }

    /**
     * Handles the verification request by storing the requested scopes in the
     * session
     * and initiating a new OAuth2 flow with the additional scopes.
     *
     * @param scopes             The list of scopes requested for verification
     * @param authentication     The OAuth2 authentication token
     * @param session            The HTTP session
     * @param redirectAttributes For adding flash attributes
     * @return Redirect to the OAuth2 authorization endpoint
     */
    @PostMapping("/verify")
    public String requestVerification(
            @RequestParam(value = "scopes", required = false) List<String> scopes,
            OAuth2AuthenticationToken authentication,
            HttpSession session,
            RedirectAttributes redirectAttributes) {

        if (authentication == null) {
            logger.error("No authentication token present");
            redirectAttributes.addFlashAttribute("error", "You must be logged in to request verification");
            return "redirect:/";
        }

        if (scopes == null || scopes.isEmpty()) {
            logger.warn("No scopes selected for verification");
            redirectAttributes.addFlashAttribute("error", "Please select at least one verification option");
            return "redirect:/";
        }

        // Validate requested scopes
        if (!ALLOWED_SCOPES.containsAll(scopes)) {
            logger.error("Invalid scopes requested: {}", scopes);
            redirectAttributes.addFlashAttribute("error", "Invalid verification options selected");
            return "redirect:/";
        }

        try {
            OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
                    authentication.getAuthorizedClientRegistrationId(),
                    authentication.getName());

            if (client == null || client.getAccessToken() == null) {
                logger.error("No authorized client or access token found for user: {}", authentication.getName());
                redirectAttributes.addFlashAttribute("error", "Your session has expired. Please log in again.");
                return "redirect:/";
            }

            // Store verification data in session
            session.setAttribute(SESSION_ACCESS_TOKEN_KEY, client.getAccessToken().getTokenValue());

            // Ensure openid scope is included
            List<String> verificationScopes = new ArrayList<>(scopes);
            if (!verificationScopes.contains("openid")) {
                verificationScopes.add("openid");
            }
            session.setAttribute(SESSION_SCOPES_KEY, verificationScopes);

            logger.trace("[OIDC-FLOW] ================ VERIFICATION FLOW INITIATED ================");
            logger.trace("[OIDC-FLOW] Initiating verification flow for user {} with scopes: {}",
                    authentication.getName(), verificationScopes);

            return "redirect:/oauth2/authorization/scotaccount";

        } catch (Exception e) {
            logger.error("Error during verification request", e);
            redirectAttributes.addFlashAttribute("error", "An error occurred during verification. Please try again.");
            return "redirect:/";
        }
    }
}