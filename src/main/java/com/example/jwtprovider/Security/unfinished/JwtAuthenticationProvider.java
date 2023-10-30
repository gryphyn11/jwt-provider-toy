package com.example.jwtprovider.Security.unfinished;

import java.util.Collection;

import com.example.jwtprovider.Security.authentication.JwtBearerTokenAuthenticationConverter;
import com.example.jwtprovider.Security.authentication.JwtBearerTokenAuthenticationToken;
import com.example.jwtprovider.Security.authentication.JwtGrantedAuthoritiesConverter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTProcessor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import com.nimbusds.jwt.JWT ;

import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation of the {@link JWT}-encoded
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>s for protecting OAuth 2.0 Resource Servers.
 * <p>
 * <p>
 * This {@link AuthenticationProvider} is responsible for decoding and verifying a
 * {@link JWT}-encoded access token, returning its claims set as part of the
 * {@link Authentication} statement.
 * <p>
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following
 * algorithm:
 *
 * 1. If there is a "scope" or "scp" attribute, then if a {@link String}, then split by
 * spaces and return, or if a {@link Collection}, then simply return 2. Take the resulting
 * {@link Collection} of {@link String}s and prepend the "SCOPE_" keyword, adding as
 * {@link GrantedAuthority}s.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @since 5.1
 * @see AuthenticationProvider
 * @see SignedJWT#parse(String)
 */
public final class JwtAuthenticationProvider implements AuthenticationProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final JWTProcessor<? extends SecurityContext> jwtProcessor;
    private JwtBearerTokenAuthenticationConverter jwtAuthenticationConverter = new JwtBearerTokenAuthenticationConverter();
    private JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();


    public JwtAuthenticationProvider(JWTProcessor<? extends SecurityContext> jwtProcessor) {
        Assert.notNull(jwtProcessor, "jwtProcessor cannot be null");
        this.jwtProcessor = jwtProcessor;
    }


    /**
     * Decode and validate the
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
     * Token</a>.
     * @param authentication the authentication request object.
     * @return A successful authentication
     * @throws AuthenticationException if authentication failed for some reason
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtBearerTokenAuthenticationToken bearer = (JwtBearerTokenAuthenticationToken) authentication;
        SignedJWT jwt = bearer.getToken();
        try {
            JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);
            authentication.setAuthenticated(true);
            return authentication;
        } catch (BadJOSEException e) {
            throw new BadCredentialsException("Umable to process JWT bearer token", e);
        } catch (JOSEException e) {
            throw new BadCredentialsException("Unable to process JWT bearer token", e);
        } finally {
            bearer.setAuthenticated(false);
        }
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return JwtBearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
