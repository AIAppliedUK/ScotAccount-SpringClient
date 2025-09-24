package scot.gov.scotaccountclient;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Web configuration class for the ScotAccount client application.
 * 
 * <p>
 * This class provides configuration for web-related beans and components,
 * such as HTTP client implementations and web utilities.
 * </p>
 */
@Configuration
public class WebConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebConfig.class);

    /**
     * Default constructor for WebConfig.
     * 
     * <p>
     * This constructor is used by Spring's dependency injection to create
     * the web configuration bean.
     * </p>
     */
    public WebConfig() {
        // Default constructor required by Spring
    }

    /**
     * Creates a RestTemplate bean for making HTTP requests.
     * 
     * <p>
     * The RestTemplate is used throughout the application for communicating
     * with external services, including the ScotAccount authentication and
     * attribute endpoints.
     * </p>
     * 
     * <p>
     * This implementation includes logging interceptors to log all HTTP
     * requests and responses, with special markers for ScotAccount calls.
     * </p>
     *
     * @return a configured RestTemplate instance with logging capabilities
     */
    @Bean
    public RestTemplate restTemplate() {
        // Create a buffering request factory to allow reading the response body
        // multiple times (for logging)
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        BufferingClientHttpRequestFactory bufferingRequestFactory = new BufferingClientHttpRequestFactory(
                requestFactory);

        RestTemplate restTemplate = new RestTemplate(bufferingRequestFactory);

        // Add logging interceptor
        ClientHttpRequestInterceptor loggingInterceptor = (request, body, execution) -> {
            String uri = request.getURI().toString();
            boolean isScotAccountCall = uri.contains("scotaccount.service.gov.scot");

            if (isScotAccountCall) {
                // Log the request with ScotAccount markers
                logger.trace("[SCOTACCOUNT-HTTP] ================ SCOTACCOUNT HTTP REQUEST ================");
                logger.trace("[SCOTACCOUNT-HTTP] URI: {}", uri);
                logger.trace("[SCOTACCOUNT-HTTP] Method: {}", request.getMethod());
                logger.trace("[SCOTACCOUNT-HTTP] Headers: {}", request.getHeaders());
                logger.trace("[SCOTACCOUNT-HTTP] Request body: {}", new String(body, StandardCharsets.UTF_8));
                logger.trace("[SCOTACCOUNT-HTTP] =================================================================");
            } else {
                // Log other requests with standard markers
                logger.debug("=========================== HTTP REQUEST ===========================");
                logger.debug("URI: {}", uri);
                logger.debug("Method: {}", request.getMethod());
                logger.debug("Headers: {}", request.getHeaders());
                logger.debug("Request body: {}", new String(body, StandardCharsets.UTF_8));
                logger.debug("=============================================================");
            }

            // Execute the request
            var response = execution.execute(request, body);

            if (isScotAccountCall) {
                // Log the response with ScotAccount markers
                logger.trace("[SCOTACCOUNT-HTTP] ================ SCOTACCOUNT HTTP RESPONSE ================");
                logger.trace("[SCOTACCOUNT-HTTP] Status code: {}", response.getStatusCode());
                logger.trace("[SCOTACCOUNT-HTTP] Headers: {}", response.getHeaders());

                byte[] responseBody = response.getBody().readAllBytes();
                logger.trace("[SCOTACCOUNT-HTTP] Response body: {}", new String(responseBody, StandardCharsets.UTF_8));
                logger.trace("[SCOTACCOUNT-HTTP] =================================================================");
            } else {
                // Log other responses with standard markers
                logger.debug("========================== HTTP RESPONSE ==========================");
                logger.debug("Status code: {}", response.getStatusCode());
                logger.debug("Headers: {}", response.getHeaders());

                byte[] responseBody = response.getBody().readAllBytes();
                logger.debug("Response body: {}", new String(responseBody, StandardCharsets.UTF_8));
                logger.debug("=============================================================");
            }

            return response;
        };

        restTemplate.setInterceptors(Collections.singletonList(loggingInterceptor));

        return restTemplate;
    }
}