package scot.gov.scotaccountclient;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for ScotAccount integration.
 * 
 * <p>
 * This class binds custom properties from application.properties that are
 * specific to the ScotAccount client application. It provides type-safe
 * access to configuration values and enables proper IDE support and
 * validation.
 * </p>
 * 
 * <p>
 * Properties are bound using the prefix "scotaccount" and can be configured
 * in application.properties as:
 * </p>
 * 
 * <pre>
 * scotaccount.private-key-path=keys/ec_private_key.pem
 * scotaccount.public-key-path=keys/ec_public_key.pem
 * scotaccount.logout-endpoint=https://authz.integration.scotaccount.service.gov.scot/authorize/logout
 * </pre>
 */
@Component
@ConfigurationProperties(prefix = "scotaccount")
public class ScotAccountProperties {

    /** Path to the private key file used for JWT signing. */
    private String privateKeyPath = "keys/private.pem";

    /** Path to the public key file used for JWT validation. */
    private String publicKeyPath = "keys/public.pem";

    /** URL endpoint for ScotAccount logout functionality. */
    private String logoutEndpoint;

    /**
     * Gets the path to the private key file.
     * 
     * @return the private key file path
     */
    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    /**
     * Sets the path to the private key file.
     * 
     * @param privateKeyPath the private key file path
     */
    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    /**
     * Gets the path to the public key file.
     * 
     * @return the public key file path
     */
    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    /**
     * Sets the path to the public key file.
     * 
     * @param publicKeyPath the public key file path
     */
    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }

    /**
     * Gets the logout endpoint URL.
     * 
     * @return the logout endpoint URL
     */
    public String getLogoutEndpoint() {
        return logoutEndpoint;
    }

    /**
     * Sets the logout endpoint URL.
     * 
     * @param logoutEndpoint the logout endpoint URL
     */
    public void setLogoutEndpoint(String logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }
}
