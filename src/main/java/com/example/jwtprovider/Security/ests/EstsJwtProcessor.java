package com.example.jwtprovider.Security.ests;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.*;

import java.util.Arrays;
import java.util.HashSet;

public class EstsJwtProcessor {
    private JWTProcessor<SecurityContext> jwtProcessor;

    public EstsJwtProcessor(EstsJwksSource estsJwksSource){
        ConfigurableJWTProcessor<SecurityContext> defaultJwtProcessor = new DefaultJWTProcessor<>();
        this.jwtProcessor = defaultJwtProcessor;
        defaultJwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));

        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS384;

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                expectedJWSAlg,
                estsJwksSource.getJwkSource());
        defaultJwtProcessor.setJWSKeySelector(keySelector);

        JWTClaimsSetVerifier<SecurityContext> ver = new DefaultJWTClaimsVerifier<>(
                new HashSet<>(Arrays.asList("399-AOCB", "399-AOCB-AOCBSC", "399-AOCB-CDM")),
                new JWTClaimsSet.Builder()
                        .issuer("ups_jwt_int")
                        .subject("399-AOCB")
                        .build(),
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "scp",
                        JWTClaimNames.JWT_ID)),
                null);
        defaultJwtProcessor.setJWTClaimsSetVerifier(ver);
    }

    public JWTProcessor<SecurityContext> getJwtProcessor(){
        return this.jwtProcessor;
    }
}
