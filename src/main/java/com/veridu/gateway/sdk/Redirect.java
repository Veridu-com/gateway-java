package com.veridu.gateway.sdk;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.math.BigInteger;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

public class Redirect {
    private String key;
    private String secret;
    private String gatewayUrl = "https://gateway.veridu.com/1.1/widget";
    private String callbackUrl = null;
    private String templateName = null;
    private Integer signatureTTL = 3600;
    private String tokenId = null;
        
    private String generateTokenId() {
        this.tokenId = new BigInteger(80, new SecureRandom()).toString(32);
        return this.tokenId;
    }

    private long getUnixtime() {
        return (System.currentTimeMillis() / 1000L);
    }

    public Redirect(String key, String secret, String gatewayUrl) {
        this.key = key;
        this.secret = secret;
        this.gatewayUrl = gatewayUrl;
    }

    public Redirect(String key, String secret) {
        this.key = key;
        this.secret = secret;
    }

    public String generateUrl(String username) throws UnsupportedEncodingException, JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(this.key);
        claims.setAudience(this.gatewayUrl);
        claims.setExpirationTime(NumericDate.fromSeconds(this.getUnixtime() + this.signatureTTL.longValue()));
        claims.setJwtId(this.generateTokenId());
        claims.setIssuedAt(NumericDate.fromSeconds(this.getUnixtime()));
        claims.setNotBefore(NumericDate.fromSeconds(this.getUnixtime()));
        claims.setSubject(username);
        claims.setClaim("url", this.callbackUrl);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKey(new HmacKey(this.secret.getBytes("UTF-8")));

        return jws.getCompactSerialization();
    }

    public String generateUrl() throws UnsupportedEncodingException, JoseException {
        return this.generateUrl(null);
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getCallbackUrl() {
        return this.callbackUrl;
    }

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public String getTemplateName() {
        return this.templateName;
    }

    public void setSignatureTTL(Integer signatureTTL) {
        this.signatureTTL = signatureTTL;
    }

    public Integer getSignatureTTL() {
        return this.signatureTTL;
    }

    public String getTokenId() {
        return this.tokenId;
    }
        
}
