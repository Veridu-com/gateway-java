package com.veridu.gateway.sdk;

import com.veridu.gateway.exception.TokenVerificationFailed;
import java.io.UnsupportedEncodingException;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;

public class Callback {
    private String key;
    private String secret;
    private String gatewayUrl = "https://gateway.veridu.com/1.1/widget";
    private String username = null;
    private boolean pass = false;
    
    public Callback(String key, String secret, String gatewayUrl) {
        this.key = key;
        this.secret = secret;
        this.gatewayUrl = gatewayUrl;
    }
    
    public Callback(String key, String secret) {
        this.key = key;
        this.secret = secret;
    }
    
    public void checkCallbackSignature(String token, String tokenId) throws UnsupportedEncodingException, InvalidJwtException, MalformedClaimException, TokenVerificationFailed {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime()
            .setRequireIssuedAt()
            .setRequireNotBefore()
            .setAllowedClockSkewInSeconds(30)
            .setRequireSubject()
            .setExpectedIssuer(this.gatewayUrl)
            .setExpectedAudience(this.key)
            .setVerificationKey(new HmacKey(this.secret.getBytes("UTF-8")))
            .setRequireJwtId()
            .build();
        
        JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        if (jwtClaims.getJwtId().compareTo(tokenId) != 0) {
            throw new TokenVerificationFailed();
        }
        this.username = jwtClaims.getSubject();
        this.pass = jwtClaims.getClaimValue("pass", Boolean.class);
    }
    
    public String getUsername() {
        return this.username;
    }
    
    public boolean getPass() {
        return this.pass;
    }
}
