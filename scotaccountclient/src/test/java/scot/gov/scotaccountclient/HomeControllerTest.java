package scot.gov.scotaccountclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.ui.Model;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class HomeControllerTest {

    @Mock
    private OAuth2AuthorizedClientService authorizedClientService;

    @Mock
    private AttributeService attributeService;

    @Mock
    private OAuth2AuthenticationToken authenticationToken;

    @Mock
    private OAuth2User oauth2User;

    @Mock
    private Model model;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private OAuth2AuthorizedClient authorizedClient;

    @Mock
    private OAuth2AccessToken accessToken;

    private HomeController homeController;

    @BeforeEach
    void setUp() {
        homeController = new HomeController(authorizedClientService, attributeService);

        // Setup SecurityContextHolder mock
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void home_WhenNotAuthenticated_ShouldReturnIndexView() {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        String viewName = homeController.home(model);

        // Then
        assertEquals("index", viewName);
    }

    @Test
    void home_WhenAuthenticated_ShouldReturnIndexWithUserInfo() {
        // Given
        String accessTokenValue = "test-token";
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("name", "John Doe");
        attributes.put("email", "john@example.com");

        when(securityContext.getAuthentication()).thenReturn(authenticationToken);
        when(authenticationToken.getPrincipal()).thenReturn(oauth2User);
        when(authenticationToken.getAuthorizedClientRegistrationId()).thenReturn("scotaccount");
        when(authenticationToken.getName()).thenReturn("user1234");
        when(authorizedClientService.loadAuthorizedClient(eq("scotaccount"), eq("user1234")))
                .thenReturn(authorizedClient);
        when(authorizedClient.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn(accessTokenValue);
        when(attributeService.fetchAttributes(eq(accessTokenValue))).thenReturn(attributes);

        // When
        String viewName = homeController.home(model);

        // Then
        assertEquals("index", viewName);
        verify(model).addAttribute(eq("user"), eq(oauth2User));
        verify(model).addAttribute(eq("verifiedClaims"), any());
    }
}