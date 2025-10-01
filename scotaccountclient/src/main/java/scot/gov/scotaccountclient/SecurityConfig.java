package scot.gov.scotaccountclient;

import java.util.HashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

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

        /** Configuration properties for ScotAccount integration */
        private final ScotAccountProperties scotAccountProperties;

        /**
         * Constructs a new SecurityConfig with the required dependencies.
         * 
         * @param clientRegistrationRepository Repository for OAuth2 client
         *                                     registrations, used for client
         *                                     configuration
         * @param scotAccountProperties        Configuration properties for ScotAccount
         *                                     integration
         */
        public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
                        ScotAccountProperties scotAccountProperties) {
                this.clientRegistrationRepository = clientRegistrationRepository;
                this.scotAccountProperties = scotAccountProperties;
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
                                                                        logger.trace("[OIDC-FLOW] ================ AUTHORIZATION REQUEST BUILDING ================");
                                                                        logger.trace("[OIDC-FLOW] Configuring OAuth2 request with scopes: {}",
                                                                                        verificationScopes);
                                                                } else {
                                                                        // Default to openid scope for authentication
                                                                        builder.scope("openid");
                                                                        logger.trace("[OIDC-FLOW] ================ AUTHORIZATION REQUEST BUILDING ================");
                                                                        logger.trace("[OIDC-FLOW] Configuring OAuth2 request with scope: openid");
                                                                }
                                                        } else {
                                                                // Default to openid scope if no request context
                                                                builder.scope("openid");
                                                                logger.trace("[OIDC-FLOW] ================ AUTHORIZATION REQUEST BUILDING ================");
                                                                logger.trace("[OIDC-FLOW] No request context available, using default scope: openid");
                                                        }
                                                }));

                return resolver;
        }

        /**
         * Creates a custom OAuth2 access token response client.
         *
         * @param restTemplate The global RestTemplate bean for HTTP requests
         * @return The configured CustomOAuth2AccessTokenResponseClient
         */
        @Bean
        public CustomOAuth2AccessTokenResponseClient customAccessTokenResponseClient(RestTemplate restTemplate) {
                // Create JwtUtil with proper dependencies
                JwtUtil jwtUtilWithRestTemplate = new JwtUtil(scotAccountProperties, restTemplate);
                return new CustomOAuth2AccessTokenResponseClient(jwtUtilWithRestTemplate, restTemplate);
        }

        /**
         * Custom access denied handler that logs access denials without stack traces.
         *
         * @return The configured AccessDeniedHandler
         */
        @Bean
        public AccessDeniedHandler accessDeniedHandler() {
                return (request, response, accessDeniedException) -> {
                        String principal = request.getUserPrincipal() != null
                                ? request.getUserPrincipal().getName()
                                : "anonymous";
                        logger.debug("Access denied for user '{}' attempting to access: {}",
                                principal, request.getRequestURI());
                        response.sendRedirect("/");
                };
        }

        /**
         * Custom authentication entry point that logs authentication failures without stack traces.
         *
         * @return The configured AuthenticationEntryPoint
         */
        @Bean
        public AuthenticationEntryPoint authenticationEntryPoint() {
                return (request, response, authException) -> {
                        logger.debug("User not authenticated, redirecting to login from: {}",
                                request.getRequestURI());
                        response.sendRedirect("/");
                };
        }

        /**
         * Configures the security filter chain with OAuth2 and JWT settings.
         *
         * @param http         The HttpSecurity object to configure
         * @param restTemplate The global RestTemplate bean for HTTP requests
         * @return The configured SecurityFilterChain
         * @throws Exception if security configuration fails
         */
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http, RestTemplate restTemplate) throws Exception {
                http
                                .csrf(csrf -> csrf
                                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                                                .ignoringRequestMatchers("/oauth2/authorization/**",
                                                                "/login/oauth2/code/**",
                                                                "/logout/backchannel",
                                                                "/logout/back-channel"))
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/", "/error", "/webjars/**", "/css/**", "/js/**",
                                                                "/images/**", "/logout", "/test/**",
                                                                "/logout/backchannel", "/logout/back-channel")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .exceptionHandling(exceptions -> exceptions
                                                .accessDeniedHandler(accessDeniedHandler())
                                                .authenticationEntryPoint(authenticationEntryPoint()))
                                .oauth2Login(oauth2 -> oauth2
                                                .authorizationEndpoint(authorization -> authorization
                                                                .authorizationRequestResolver(
                                                                                this.authorizationRequestResolver(
                                                                                                clientRegistrationRepository)))
                                                .tokenEndpoint(token -> token
                                                                .accessTokenResponseClient(this
                                                                                .customAccessTokenResponseClient(
                                                                                                restTemplate)))
                                                .loginPage("/")
                                                .defaultSuccessUrl("/", true)
                                                .failureHandler((request, response, exception) -> {
                                                        logger.trace("[OIDC-FLOW] ================ AUTHENTICATION FAILURE ================");
                                                        logger.trace("[OIDC-FLOW] Authentication failed", exception);
                                                        logger.trace("[OIDC-FLOW] Error message: {}",
                                                                        exception.getMessage());
                                                        logger.trace("[OIDC-FLOW] Error type: {}",
                                                                        exception.getClass().getName());
                                                        if (exception.getCause() != null) {
                                                                logger.trace("[OIDC-FLOW] Root cause: {}",
                                                                                exception.getCause().getMessage());
                                                        }
                                                        logger.trace("[OIDC-FLOW] Request URI: {}",
                                                                        request.getRequestURI());
                                                        logger.trace("[OIDC-FLOW] Query string: {}",
                                                                        request.getQueryString());
                                                        response.sendRedirect("/?error=true&message=" +
                                                                        java.net.URLEncoder.encode(
                                                                                        exception.getMessage(),
                                                                                        java.nio.charset.StandardCharsets.UTF_8));
                                                })
                                                .successHandler((request, response, authentication) -> {
                                                        logger.trace("[OIDC-FLOW] ================ AUTHENTICATION SUCCESS ================");
                                                        logger.trace("[OIDC-FLOW] Authentication successful for user: {}",
                                                                        authentication.getName());
                                                        logger.trace("[OIDC-FLOW] Authentication details: {}",
                                                                        authentication);
                                                        response.sendRedirect("/");
                                                }))
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                                .invalidSessionUrl("/login?invalid")
                                                .sessionFixation().newSession()
                                                .maximumSessions(1)
                                                .expiredUrl("/login?expired"))
                                .logout(logout -> logout
                                                .disable());

                return http.build();
        }
}