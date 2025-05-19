package scot.gov.scotaccountclient;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

/**
 * Security configuration for the ScotAccount client application.
 * This class configures the OAuth2/OIDC client security settings and integrates
 * with ScotAccount's authentication service.
 * 
 * Key features:
 * <ul>
 * <li>OAuth2/OIDC client configuration with PKCE support</li>
 * <li>JWT-based client authentication using client assertions</li>
 * <li>Custom token response handling</li>
 * <li>Secure session management</li>
 * <li>Protected endpoint configuration</li>
 * </ul>
 * 
 * Security measures:
 * <ul>
 * <li>CSRF protection enabled with cookie-based tokens</li>
 * <li>Session fixation protection</li>
 * <li>Secure cookie configuration</li>
 * <li>PKCE for authorization code flow</li>
 * <li>JWT validation using JWKS</li>
 * </ul>
 * 
 * Protected endpoints:
 * <ul>
 * <li>Public: /, /login, /error, static resources</li>
 * <li>OAuth2: /oauth2/authorization/**, /login/oauth2/code/**</li>
 * <li>Protected: All other endpoints require authentication</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
        private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
        /** Repository for OAuth2 client registrations */
        private final ClientRegistrationRepository clientRegistrationRepository;

        /** JWT utility for token handling */
        private final JwtUtil jwtUtil;

        /**
         * Constructs a new SecurityConfig with the required dependencies.
         * 
         * @param clientRegistrationRepository Repository for OAuth2 client
         *                                     registrations, used for client
         *                                     configuration
         * @param jwtUtil                      JWT utility for token operations and
         *                                     validation
         */
        public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
                        JwtUtil jwtUtil) {
                this.clientRegistrationRepository = clientRegistrationRepository;
                this.jwtUtil = jwtUtil;
        }

        /**
         * Creates a custom OAuth2 authorization request resolver that enables PKCE.
         *
         * @param clientRegistrationRepository The client registration repository
         * @return The configured OAuth2AuthorizationRequestResolver
         */
        @Bean
        public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
                        ClientRegistrationRepository clientRegistrationRepository) {
                DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                                clientRegistrationRepository,
                                "/oauth2/authorization");

                resolver.setAuthorizationRequestCustomizer(
                                OAuth2AuthorizationRequestCustomizers.withPkce()
                                                .andThen(builder -> {
                                                        // Get scopes from session if present
                                                        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                                                                        .getRequestAttributes();
                                                        if (attributes != null) {
                                                                HttpServletRequest request = attributes.getRequest();
                                                                @SuppressWarnings("unchecked")
                                                                List<String> verificationScopes = (List<String>) request
                                                                                .getSession()
                                                                                .getAttribute("verification_scopes");

                                                                if (verificationScopes != null
                                                                                && !verificationScopes.isEmpty()) {
                                                                        // Use verification scopes from session
                                                                        builder.scopes(new HashSet<>(
                                                                                        verificationScopes));
                                                                        logger.debug("Configuring OAuth2 request with scopes: {}",
                                                                                        verificationScopes);
                                                                } else {
                                                                        // Default to openid scope for authentication
                                                                        builder.scope("openid");
                                                                        logger.debug("Configuring OAuth2 request with scope: openid");
                                                                }
                                                        } else {
                                                                // Default to openid scope if no request context
                                                                builder.scope("openid");
                                                                logger.debug("No request context available, using default scope: openid");
                                                        }
                                                }));

                return resolver;
        }

        /**
         * Creates a custom OAuth2 access token response client.
         *
         * @return The configured CustomOAuth2AccessTokenResponseClient
         */
        @Bean
        public CustomOAuth2AccessTokenResponseClient customAccessTokenResponseClient() {
                return new CustomOAuth2AccessTokenResponseClient(jwtUtil);
        }

        /**
         * Configures the security filter chain with OAuth2 and JWT settings.
         *
         * @param http The HttpSecurity object to configure
         * @return The configured SecurityFilterChain
         * @throws Exception if security configuration fails
         */
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf
                                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                                                .ignoringRequestMatchers("/oauth2/authorization/**",
                                                                "/login/oauth2/code/**"))
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/", "/error", "/webjars/**", "/css/**", "/js/**",
                                                                "/images/**", "/logout")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .oauth2Login(oauth2 -> oauth2
                                                .authorizationEndpoint(authorization -> authorization
                                                                .authorizationRequestResolver(
                                                                                this.authorizationRequestResolver(
                                                                                                clientRegistrationRepository)))
                                                .tokenEndpoint(token -> token
                                                                .accessTokenResponseClient(this
                                                                                .customAccessTokenResponseClient()))
                                                .loginPage("/")
                                                .defaultSuccessUrl("/", true))
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                                .maximumSessions(1)
                                                .expiredUrl("/login?expired")
                                                .and()
                                                .invalidSessionUrl("/login?invalid")
                                                .sessionFixation().newSession())
                                .logout(logout -> logout
                                                .disable());

                return http.build();
        }
}
