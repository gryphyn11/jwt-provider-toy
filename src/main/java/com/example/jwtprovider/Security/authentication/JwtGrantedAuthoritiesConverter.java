package com.example.jwtprovider.Security.authentication;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

public final class JwtGrantedAuthoritiesConverter {

    private final Logger logger = LoggerFactory.getLogger(JwtGrantedAuthoritiesConverter.class);

    private static final String DEFAULT_AUTHORITY_PREFIX = "SCOPE_";

    private static final String DEFAULT_AUTHORITIES_CLAIM_DELIMITER = " ";

    private static final Collection<String> WELL_KNOWN_AUTHORITIES_CLAIM_NAMES = Arrays.asList("scope", "scp");

    private String authorityPrefix = DEFAULT_AUTHORITY_PREFIX;

    private String authoritiesClaimDelimiter = DEFAULT_AUTHORITIES_CLAIM_DELIMITER;

    private String authoritiesClaimName;

    /**
     * Extract {@link GrantedAuthority}s from the given {@link JWT}.
     * @param jwt The {@link JWT} token
     * @return The {@link GrantedAuthority authorities} read from the token scopes
     */
    public Collection<GrantedAuthority> convert(JWT jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : getAuthorities(jwt)) {
            grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
        }
        return grantedAuthorities;
    }

    public Collection<GrantedAuthority> convert(JWTClaimsSet jwtClaimsSet) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : getAuthorities(jwtClaimsSet, "scp")) {
            grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
        }
        return grantedAuthorities;
    }

    /**
     * Sets the prefix to use for {@link GrantedAuthority authorities} mapped by this
     * converter. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#DEFAULT_AUTHORITY_PREFIX}.
     * @param authorityPrefix The authority prefix
     * @since 5.2
     */
    public void setAuthorityPrefix(String authorityPrefix) {
        Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
        this.authorityPrefix = authorityPrefix;
    }

    /**
     * Sets the regex to use for splitting the value of the authorities claim into
     * {@link GrantedAuthority authorities}. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#DEFAULT_AUTHORITIES_CLAIM_DELIMITER}.
     * @param authoritiesClaimDelimiter The regex used to split the authorities
     * @since 6.1
     */
    public void setAuthoritiesClaimDelimiter(String authoritiesClaimDelimiter) {
        Assert.notNull(authoritiesClaimDelimiter, "authoritiesClaimDelimiter cannot be null");
        this.authoritiesClaimDelimiter = authoritiesClaimDelimiter;
    }

    /**
     * Sets the name of token claim to use for mapping {@link GrantedAuthority
     * authorities} by this converter. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#WELL_KNOWN_AUTHORITIES_CLAIM_NAMES}.
     * @param authoritiesClaimName The token claim name to map authorities
     * @since 5.2
     */
    public void setAuthoritiesClaimName(String authoritiesClaimName) {
        Assert.hasText(authoritiesClaimName, "authoritiesClaimName cannot be empty");
        this.authoritiesClaimName = authoritiesClaimName;
    }

    private String getAuthoritiesClaimName(JWT jwt) {
        if (this.authoritiesClaimName != null) {
            return this.authoritiesClaimName;
        }
        for (String claimName : WELL_KNOWN_AUTHORITIES_CLAIM_NAMES) {
            try {
                if (null != jwt.getJWTClaimsSet().getClaim(claimName)) {
                    return claimName;
                }
            } catch (ParseException e) {
                logger.trace("Error getting claim {} from JWT.", claimName, e);
            }
        }
        return null;
    }

    private Collection<String> getAuthorities(JWT jwt) {
        String claimName = getAuthoritiesClaimName(jwt);
        if (claimName == null) {
            logger.trace("Returning no authorities since could not find any claims that might contain scopes");
            return Collections.emptyList();
        }
        logger.trace("Looking for scopes in claim {}}", claimName);

        Object authorities;
        try {
            authorities = jwt.getJWTClaimsSet().getClaim(claimName);
        } catch (ParseException ex){
            logger.debug("Returning no authorities due to parsing error in JWT claims set.", ex);
            return Collections.emptyList();
        }
        if (authorities instanceof String) {
            if (StringUtils.hasText((String) authorities)) {
                return Arrays.asList(((String) authorities).split(this.authoritiesClaimDelimiter));
            }
            return Collections.emptyList();
        }
        if (authorities instanceof Collection) {
            return castAuthoritiesToCollection(authorities);
        }
        return Collections.emptyList();
    }

    private Collection<String> getAuthorities(JWTClaimsSet jwtClaimsSet, String authClaimsName) {
        Object authorities;
        authorities = jwtClaimsSet.getClaim(authClaimsName);
        if (authorities instanceof String) {
            if (StringUtils.hasText((String) authorities)) {
                return Arrays.asList(((String) authorities).split(this.authoritiesClaimDelimiter));
            }
            return Collections.emptyList();
        }
        if (authorities instanceof Collection) {
            return castAuthoritiesToCollection(authorities);
        }
        return Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    private Collection<String> castAuthoritiesToCollection(Object authorities) {
        return (Collection<String>) authorities;
    }

}