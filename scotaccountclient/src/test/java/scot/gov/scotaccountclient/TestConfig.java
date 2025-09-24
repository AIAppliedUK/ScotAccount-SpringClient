package scot.gov.scotaccountclient;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test configuration for unit tests.
 * Provides beans needed for testing the application components.
 */
@TestConfiguration
public class TestConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ScotAccountProperties scotAccountProperties() {
        return new ScotAccountProperties();
    }

    @Bean
    public JwtUtil jwtUtil(ScotAccountProperties scotAccountProperties, RestTemplate restTemplate) {
        return new JwtUtil(scotAccountProperties, restTemplate);
    }
}