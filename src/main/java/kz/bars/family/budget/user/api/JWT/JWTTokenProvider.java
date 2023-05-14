package kz.bars.family.budget.user.api.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JWTTokenProvider {

    public String generateToken(String userName, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", roles);
        return tokenCreator(claims, userName);
    }

    public String tokenCreator(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWTSecurityConstants.EXPIRATION_TIME))
                .signWith(getSignedKey(), SignatureAlgorithm.HS256).compact();
    }

    public String extractUsernameFromToken(String theToken) {
        return extractClaim(theToken, Claims::getSubject);
    }

    public Date extractExpirationTimeFromToken(String theToken) {
        return extractClaim(theToken, Claims::getExpiration);
    }

    public Boolean validateToken(String theToken, UserDetails userDetails) {
        final String userName = extractUsernameFromToken(theToken);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(theToken));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignedKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String theToken) {
        return extractExpirationTimeFromToken(theToken).before(new Date());
    }

    private Key getSignedKey() {
//        byte[] keyByte = JWTSecurityConstants.SECRET_KEY.getBytes();
        byte[] keyByte = Base64.getEncoder().encode(JWTSecurityConstants.SECRET_KEY.getBytes());
        return Keys.hmacShaKeyFor(keyByte);
    }

}
