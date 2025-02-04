package com.transunion.bse.mortgage.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Component
public class JwtTokenUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);

    @Value("${security.jwt.keyStore}")
    private String keyStore;

    @Value("${security.jwt.keyStorePassword}")
    private String keyStoreSecret;

    @Value("${security.jwt.keyPairAlias}")
    private String keyPairAlias;

    @Value("${security.jwt.keyPairPassword}")
    private String keyPairSecret;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Value("${security.jwt.audience}")
    private String audience;

    /**
     * Validates the JWT token by verifying its claims and signature.
     *
     * @param token The JWT token to validate.
     * @return True if valid, false otherwise.
     */
    public boolean validateJwtToken(String token) {
        try {
            PublicKey publicKey = getPublicKey();

            JwtParser parser = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .requireIssuer(issuer)
                    .requireAudience(audience)
                    .build();

            // Parse the claims
            Jws<Claims> claims = parser.parseClaimsJws(token);

            // Validate additional claims
            validateClaims(claims.getBody());

            LOGGER.info("JWT token validation successful.");
            return true;

        } catch (ExpiredJwtException e) {
            LOGGER.error("JWT token has expired: {}", e.getMessage());
        } catch (JwtException e) {
            LOGGER.error("JWT validation failed: {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Unexpected error during JWT validation: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Validates specific claims from the JWT token.
     *
     * @param claims The claims extracted from the JWT token.
     */
    private void validateClaims(Claims claims) {
        // Check expiration
        Date expiration = claims.getExpiration();
        if (expiration == null || expiration.before(new Date())) {
            throw new SecurityException("Token has expired");
        }

        // Check issued-at time (iat)
        Date issuedAt = claims.getIssuedAt();
        if (issuedAt == null || issuedAt.after(new Date())) {
            throw new SecurityException("Invalid issued-at (iat) claim");
        }

        // Add additional validations as needed (e.g., roles, custom claims)
    }

    /**
     * Retrieves the public key from the keystore.
     *
     * @return The public key.
     */
    private PublicKey getPublicKey() {
        try (FileInputStream input = new FileInputStream(keyStore)) {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(input, keyStoreSecret.toCharArray());
            return keystore.getCertificate(keyPairAlias).getPublicKey();
        } catch (Exception e) {
            LOGGER.error("Failed to load public key: {}", e.getMessage());
            throw new RuntimeException("Failed to load public key", e);
        }
    }
}
