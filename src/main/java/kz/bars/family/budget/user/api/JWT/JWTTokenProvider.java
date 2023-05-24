package kz.bars.family.budget.user.api.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import kz.bars.family.budget.user.api.exeption.TokenExpiredException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
@Log4j2
public class JWTTokenProvider {

    public String generateAccessToken(String userName, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", roles);
        return accessTokenCreator(claims, userName);
    }

    public String accessTokenCreator(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTSecurityConstants.AUTH_TOKEN_EXPIRATION_TIME))
                .signWith(getSignedKey(JWTSecurityConstants.AUTH_SECRET_KEY), SignatureAlgorithm.HS256).compact();
    }

    public boolean validateAccessToken(String accessToken, UserDetails userDetails) {
        final String userName = extractUsernameFromToken(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY);
        return (userName.equals(userDetails.getUsername()) &&
                !isTokenExpired(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY));
    }

    public String generateRefreshToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("UUID", UUID.randomUUID().toString()); // генерация UUID для записи в БД
        return refreshTokenCreator(claims, userName);
    }

    public String refreshTokenCreator(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTSecurityConstants.REFRESH_TOKEN_EXPIRATION_TIME))
                .signWith(getSignedKey(JWTSecurityConstants.REFRESH_SECRET_KEY), SignatureAlgorithm.HS256).compact();
    }

    public boolean validateRefreshToken(String refreshToken, UserDetails userDetails) {
        final String userName = extractUsernameFromToken(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY);
        return (userName.equals(userDetails.getUsername()) &&
                !isTokenExpired(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY));
    }

    public String extractUsernameFromToken(String theToken, String theKey) {
        return extractClaim(theToken, theKey, Claims::getSubject);
    }

    public String extractUUIDFromToken(String theToken, String theKey) {
        return extractClaim(theToken, theKey, claims -> claims.get("UUID", String.class));
    }

    public Date extractExpirationTimeFromToken(String theToken, String theKey) {
        return extractClaim(theToken, theKey, Claims::getExpiration);
    }

    private <T> T extractClaim(String theToken, String theKey, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(theToken, theKey);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String theToken, String theKey) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignedKey(theKey))
                    .build()
                    .parseClaimsJws(theToken)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            // Обработка исключения при просроченном токене
            log.error("!Token has expired, token={}", theToken);
            throw new TokenExpiredException("Token has expired");
        }
    }

    private boolean isTokenExpired(String theToken, String theKey) {
        return extractExpirationTimeFromToken(theToken, theKey).before(new Date());
    }

    private Key getSignedKey(String theKey) {
        byte[] keyByte = Base64.getEncoder().encode(theKey.getBytes());
        return Keys.hmacShaKeyFor(keyByte);
    }

}
