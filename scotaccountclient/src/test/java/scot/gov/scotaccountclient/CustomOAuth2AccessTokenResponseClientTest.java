package scot.gov.scotaccountclient;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
public class CustomOAuth2AccessTokenResponseClientTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private ObjectMapper objectMapper;

    private CustomOAuth2AccessTokenResponseClient tokenResponseClient;

    @BeforeEach
    void setUp() {
        tokenResponseClient = new CustomOAuth2AccessTokenResponseClient(jwtUtil, restTemplate);
        ReflectionTestUtils.setField(tokenResponseClient, "objectMapper", objectMapper);
    }

    @Test
    void createClientInstance_ShouldNotBeNull() {
        assertNotNull(tokenResponseClient);
    }
}