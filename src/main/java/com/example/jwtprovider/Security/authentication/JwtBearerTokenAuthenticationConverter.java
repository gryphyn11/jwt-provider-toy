package com.example.jwtprovider.Security.authentication;


import java.text.ParseException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Converts from a HttpServletRequest to {@link JwtBearerTokenAuthenticationConverter} that
 * can be authenticated.
 */

public class JwtBearerTokenAuthenticationConverter implements AuthenticationConverter {
    public static final String AUTHENTICATION_SCHEME_BEARER = "Bearer";
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public JwtBearerTokenAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public JwtBearerTokenAuthenticationConverter(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return this.authenticationDetailsSource;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setJwtGrantedAuthoritiesConverter(
            JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }

    public JwtBearerTokenAuthenticationToken convert(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null) {
            return null;
        } else {
            header = header.trim();
            if (!StringUtils.startsWithIgnoreCase(header, "Bearer")) {
                return null;
            } else if (header.equalsIgnoreCase("Bearer")) {
                throw new BadCredentialsException("Empty bearer token");
            } else {
                String token = header.substring(6);
                if( StringUtils.countOccurrencesOf(token, ".") < 2){
                    throw new BadCredentialsException("Invalid jwt bearer token");
                }
                JwtBearerTokenAuthenticationToken result;
                try {
                    result = JwtBearerTokenAuthenticationToken.fromCompact(token);
                } catch(ParseException ex){
                    throw new BadCredentialsException("Invalid jwt bearer token", ex);
                }
                result.setDetails(this.authenticationDetailsSource.buildDetails(request));
                return result;
            }
        }
    }

}
