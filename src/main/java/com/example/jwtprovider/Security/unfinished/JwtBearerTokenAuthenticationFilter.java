package com.example.jwtprovider.Security.unfinished;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.jwtprovider.Security.authentication.JwtBearerTokenAuthenticationConverter;
import com.example.jwtprovider.Security.authentication.JwtBearerTokenAuthenticationToken;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests that contain an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate
 * a {@link JwtBearerTokenAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @author Jeongjin Kim
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750" target="_blank">The OAuth 2.0
 * Authorization Framework: Bearer Token Usage</a>
 * @see JwtAuthenticationProvider
 */
public class JwtBearerTokenAuthenticationFilter extends OncePerRequestFilter {
    private AuthenticationManager authenticationManager;
    private AuthenticationConverter authenticationConverter = new JwtBearerTokenAuthenticationConverter();
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private boolean ignoreFailure = false;

    public JwtBearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationProvider cannot be null");
        this.authenticationManager = authenticationManager;
    }

    /**
     * Extract any
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
     * Token</a> from the request and attempt an authentication.
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token;
        try {
            Authentication authenticationRequest = authenticationConverter.convert(request);
            if (authenticationRequest == null) {
                this.logger.trace("Did not process request since did not find bearer token");
                filterChain.doFilter(request, response);
                return;
            }
            Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authenticationResult);
            this.securityContextHolderStrategy.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticationResult));
            }
            filterChain.doFilter(request, response);
        }
        catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            this.securityContextHolderStrategy.clearContext();
            this.logger.trace("Failed to process authentication request", ex);
            //this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
            if (this.ignoreFailure) {
                filterChain.doFilter(request, response);
            }
            return;
        }
    }

    /**
     * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
     * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
     *
     * @since 5.8
     */
    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    /**
     * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} on
     * authentication success. The default action is not to save the
     * {@link SecurityContext}.
     * @param securityContextRepository the {@link SecurityContextRepository} to use.
     * Cannot be null.
     */
    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    /**
     * Set the {@link AuthenticationDetailsSource} to use. Defaults to
     * {@link WebAuthenticationDetailsSource}.
     * @param authenticationDetailsSource the {@code AuthenticationConverter} to use
     * @since 5.5
     */
    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }


    private boolean authenticationIsRequired(String subject) {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()) {
            return existingAuth instanceof JwtBearerTokenAuthenticationToken && !existingAuth.getName().equals(subject) ? true : existingAuth instanceof AnonymousAuthenticationToken;
        } else {
            return true;
        }
    }

    private static class BearerTokenResolver {
        public static String resolve(HttpServletRequest request){
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
                    return token;
                }
            }
        }
    }
}