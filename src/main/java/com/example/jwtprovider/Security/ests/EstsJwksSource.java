package com.example.jwtprovider.Security.ests;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;

@Component
public class EstsJwksSource
{
    public static final long JWKS_ENDPOINT_RATE_LIMIT = java.time.Duration.ofMinutes(3).toMillis();
    public static final long JWKS_ENDPOINT_OUTAGE_TOLERANCE = java.time.Duration.ofDays(1).toMillis();
    public static final long JWKS_CACHE_TTL = java.time.Duration.ofHours(1).toMillis();
    public static final long JWKS_CACHE_RETRY_TIME_OUT = java.time.Duration.ofMinutes(2).toMillis();
    private final static Logger logger = LoggerFactory.getLogger(EstsJwksSource.class);
    public final String estsBaseUrl;
    public final String jwkEndpoint;
    public final String estsClientId;
    public final String estsClientSecret;
    private final JWKSource<SecurityContext> jwkSource;

    public EstsJwksSource(
            @Value("${ESTS.BASE.URL}") String baseUrl,
            @Value("${ESTS.KEYSTORE.ENDPOINT}") String keystoreEndpoint,
            @Value("${ESTS.CLIENT.ID}") String clientId,
            @Value("${ESTS.CLIENT.SECRET}") String clientSecret
    ){
        this.estsBaseUrl = baseUrl;
        this.jwkEndpoint = keystoreEndpoint;
        //try{
                this.estsClientId = clientId;
                this.estsClientSecret = clientSecret;
        //}
        //Set up JWK resource retriever headers and Url.
        DefaultResourceRetriever estsJwkRetriever = new DefaultResourceRetriever();
        MultiValueMap <String, String> headers = new LinkedMultiValueMap<>();
        headers.add("x-ibm-client-id", this.estsClientId);
        headers.add("x-ibm-client-secret", this.estsClientSecret);
        estsJwkRetriever.setHeaders(headers);

        //Make ESTS Url
        URL estsUrl;
        try {
            estsUrl = new URL( this.estsBaseUrl + this.jwkEndpoint);
        } catch (MalformedURLException e) {
            logger.error("ESTS JK retrieval URL not well formed. Base:{} Endpoint:{}", this.estsBaseUrl, this.jwkEndpoint);
            throw new RuntimeException("ESTS JWK retrieval URL malformed.", e);
        }

        this.jwkSource = JWKSourceBuilder.create(estsUrl,estsJwkRetriever)
                .cache (JWKS_CACHE_TTL, JWKS_CACHE_RETRY_TIME_OUT)
                .outageTolerant (JWKS_ENDPOINT_OUTAGE_TOLERANCE)
                .rateLimited (JWKS_ENDPOINT_RATE_LIMIT)
                .retrying( true)
                .build();
    }

    public JWKSource<SecurityContext> getJwkSource() { return this.jwkSource; }

}
