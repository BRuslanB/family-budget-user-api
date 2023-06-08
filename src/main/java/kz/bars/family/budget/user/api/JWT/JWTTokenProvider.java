package kz.bars.family.budget.user.api.JWT;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import kz.bars.family.budget.user.api.exeption.TokenExpiredException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JWTTokenProvider {

    public String generateAccessToken(String userName, String fullName, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", roles);
        claims.put("fullname", fullName);
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
        try {
            final String userName = extractUsernameFromToken(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY);
            return (userName.equals(userDetails.getUsername()) &&
                    !isTokenExpired(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY));
        } catch (TokenExpiredException ex) {
            // Handling an exception for an expired or erroneous token
            return false;
        }
    }

    public String generateRefreshToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        // Generation of UUID for writing to the database
        claims.put("UUID", UUID.randomUUID().toString());
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
        try {
            final String userName = extractUsernameFromToken(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY);
            return (userName.equals(userDetails.getUsername()) &&
                    !isTokenExpired(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY));
        } catch (TokenExpiredException ex) {
            // Handling an exception for an expired or erroneous token
            return false;
        }
    }

    public String extractUsernameFromToken(String theToken, String theKey) {
        try {
            return extractClaim(theToken, theKey, Claims::getSubject);
        } catch (TokenExpiredException ex) {
            // Handling an exception for an expired or erroneous token
            throw new TokenExpiredException("Token has expired or invalid token");
        }
    }

    public String extractUUIDFromToken(String theToken, String theKey) {
        return extractClaim(theToken, theKey, claims -> claims.get("UUID", String.class));
    }

    public Date extractExpirationTimeFromToken(String theToken, String theKey) {
        return extractClaim(theToken, theKey, Claims::getExpiration);
    }

    private <T> T extractClaim(String theToken, String theKey, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = extractAllClaims(theToken, theKey);
            return claimsResolver.apply(claims);
        } catch (TokenExpiredException ex) {
            // Handling an exception for an expired or erroneous token
            throw new TokenExpiredException("Token has expired or invalid token");
        }
    }

    private Claims extractAllClaims(String theToken, String theKey) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignedKey(theKey))
                    .build()
                    .parseClaimsJws(theToken)
                    .getBody();
        } catch (ExpiredJwtException | MalformedJwtException ex) {
            // Handling an exception for an expired or erroneous token
            throw new TokenExpiredException("Token has expired or invalid token");
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
