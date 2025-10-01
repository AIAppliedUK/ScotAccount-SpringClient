package scot.gov.scotaccountclient;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Custom error controller for displaying user-friendly error pages.
 *
 * <p>Handles application errors and formats them into readable error pages
 * with appropriate details for troubleshooting OAuth2/OIDC authentication issues.</p>
 */
@Controller
public class ErrorController implements org.springframework.boot.web.servlet.error.ErrorController {
    private static final Logger logger = LoggerFactory.getLogger(ErrorController.class);

    private final ErrorAttributes errorAttributes;

    public ErrorController(ErrorAttributes errorAttributes) {
        this.errorAttributes = errorAttributes;
    }

    /**
     * Handles all application errors and displays a user-friendly error page.
     *
     * <p>Special handling for OAuth2 token exchange errors to provide detailed
     * diagnostic information.</p>
     *
     * @param request HTTP request
     * @param model   Model for view rendering
     * @return View name for error page
     */
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get error attributes
        ErrorAttributeOptions options = ErrorAttributeOptions.of(
                ErrorAttributeOptions.Include.MESSAGE,
                ErrorAttributeOptions.Include.EXCEPTION,
                ErrorAttributeOptions.Include.STACK_TRACE);

        ServletWebRequest webRequest = new ServletWebRequest(request);
        Map<String, Object> errorAttrs = errorAttributes.getErrorAttributes(webRequest, options);

        Integer status = (Integer) errorAttrs.get("status");
        String error = (String) errorAttrs.get("error");
        String message = (String) errorAttrs.get("message");
        String exception = (String) errorAttrs.get("exception");

        logger.error("Error page requested - Status: {}, Error: {}, Message: {}", status, error, message);

        // Get the actual exception from the request
        Throwable throwable = errorAttributes.getError(webRequest);

        // Check if this is a token exchange error
        boolean isTokenExchangeError = (message != null &&
                (message.contains("Error exchanging code for token") ||
                 (message.contains("401") && exception != null &&
                  exception.contains("CustomOAuth2AccessTokenResponseClient")))) ||
                (throwable != null && throwable.getMessage() != null &&
                 throwable.getMessage().contains("Error exchanging code for token"));

        if (isTokenExchangeError) {
            return handleTokenExchangeError(throwable, errorAttrs, model);
        }

        // Generic error handling
        model.addAttribute("status", status != null ? status : 500);
        model.addAttribute("error", error != null ? error : "Internal Server Error");
        model.addAttribute("message", message != null ? message : "An unexpected error occurred");
        model.addAttribute("timestamp", errorAttrs.get("timestamp"));

        return "error";
    }

    /**
     * Handles token exchange errors with detailed diagnostic information.
     *
     * @param throwable  The exception that occurred
     * @param errorAttrs Error attributes from Spring
     * @param model      Model for view rendering
     * @return View name for error page
     */
    private String handleTokenExchangeError(Throwable throwable,
                                           Map<String, Object> errorAttrs,
                                           Model model) {
        logger.error("Token exchange error detected");

        String rootCauseMessage = null;
        String tokenEndpoint = null;
        Integer httpStatus = null;

        if (throwable != null) {
            Throwable rootCause = getRootCause(throwable);
            rootCauseMessage = rootCause.getMessage();

            // Extract HTTP status and endpoint from error message
            if (rootCauseMessage != null) {
                if (rootCauseMessage.contains("401")) {
                    httpStatus = 401;
                }
                if (rootCauseMessage.contains("POST request for \"")) {
                    int startIdx = rootCauseMessage.indexOf("POST request for \"") + 18;
                    int endIdx = rootCauseMessage.indexOf("\"", startIdx);
                    if (endIdx > startIdx) {
                        tokenEndpoint = rootCauseMessage.substring(startIdx, endIdx);
                    }
                }
            }
        }

        // Build diagnostic information
        Map<String, String> diagnosticInfo = new LinkedHashMap<>();
        diagnosticInfo.put("HTTP Method", "POST");
        diagnosticInfo.put("Target Endpoint", tokenEndpoint != null ? tokenEndpoint : "Unknown");
        diagnosticInfo.put("HTTP Status", httpStatus != null ? httpStatus + " Unauthorized" : "401 Unauthorized");
        diagnosticInfo.put("Error Type", "OAuth2 Token Exchange Failure");
        diagnosticInfo.put("Authentication Method", "JWT Client Assertion (private_key_jwt)");

        // Add possible causes
        Map<String, String> possibleCauses = new LinkedHashMap<>();
        possibleCauses.put("Invalid Client Credentials",
                "The client_id or client assertion (JWT) may be incorrect or not recognized by ScotAccount");
        possibleCauses.put("JWT Signature Failure",
                "The JWT client assertion signature could not be verified. Check that the correct private key is being used");
        possibleCauses.put("Expired Authorization Code",
                "The authorization code may have expired (typically valid for 60 seconds)");
        possibleCauses.put("Authorization Code Reuse",
                "The authorization code may have already been used. Each code can only be exchanged once");
        possibleCauses.put("PKCE Verification Failed",
                "The code_verifier does not match the code_challenge sent during authorization");
        possibleCauses.put("Invalid Redirect URI",
                "The redirect_uri may not match the one registered with ScotAccount");

        // Add troubleshooting steps
        Map<String, String> troubleshootingSteps = new LinkedHashMap<>();
        troubleshootingSteps.put("1. Verify Client Registration",
                "Check that the client_id in application.properties matches the one registered in ScotAccount");
        troubleshootingSteps.put("2. Check Private Key",
                "Ensure the private key file is valid and matches the public key registered with ScotAccount");
        troubleshootingSteps.put("3. Review Application Logs",
                "Check logs/application.log for detailed request/response information");
        troubleshootingSteps.put("4. Verify Token Endpoint",
                "Confirm the token endpoint URL is correct in application.properties");
        troubleshootingSteps.put("5. Check Network Connectivity",
                "Ensure the application can reach " + (tokenEndpoint != null ? tokenEndpoint : "the ScotAccount token endpoint"));
        troubleshootingSteps.put("6. Review JWT Claims",
                "Check that the JWT client assertion contains correct iss, sub, aud, jti, exp, and iat claims");

        model.addAttribute("errorTitle", "Unable to Exchange Authorization Code for Access Token");
        model.addAttribute("errorSummary",
                "The application received an authorization code from ScotAccount but was unable to exchange it for an access token.");
        model.addAttribute("timestamp", errorAttrs.get("timestamp"));
        model.addAttribute("diagnosticInfo", diagnosticInfo);
        model.addAttribute("possibleCauses", possibleCauses);
        model.addAttribute("troubleshootingSteps", troubleshootingSteps);
        model.addAttribute("technicalDetails", rootCauseMessage);

        return "error";
    }

    /**
     * Gets the root cause of an exception chain.
     */
    private Throwable getRootCause(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }
}
