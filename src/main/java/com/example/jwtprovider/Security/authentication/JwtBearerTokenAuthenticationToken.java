package com.example.jwtprovider.Security.authentication;

import java.text.ParseException;
import java.util.Collections;

import com.example.jwtprovider.Security.unfinished.JwtAuthenticationProvider;
import com.example.jwtprovider.Security.unfinished.JwtBearerTokenAuthenticationFilter;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} that contains a
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * Used by {@link JwtBearerTokenAuthenticationFilter} to prepare an authentication attempt
 * and supported by {@link JwtAuthenticationProvider}.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtBearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private final String tokenText;
    private final SignedJWT token;

    /**
     * Create a {@code BearerTokenAuthenticationToken} using the provided parameter(s)
     * @param signedJWT - the bearer token
     */
    public JwtBearerTokenAuthenticationToken(SignedJWT signedJWT) {
        super(Collections.emptyList());
        Assert.notNull(signedJWT, "Signed JWT field can not be empty.");
        this.tokenText = signedJWT.serialize();
        this.token = signedJWT;
    }

    public static JwtBearerTokenAuthenticationToken fromCompact(String compactToken) throws ParseException{
        SignedJWT jwt = SignedJWT.parse(compactToken);
        return new JwtBearerTokenAuthenticationToken(jwt);
    }


    /**
     * Get the
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
     * Token</a>
     * @return the token that proves the caller's authority to perform the
     * {@link javax.servlet.http.HttpServletRequest}
     */
    public String getTokenText() {
        return this.tokenText;
    }

    public SignedJWT getToken(){
        return this.token;
    }

    @Override
    public Object getCredentials() {
        return this.getTokenText();
    }

    @Override
    public Object getPrincipal() {
        return this.getTokenText();
    }

}