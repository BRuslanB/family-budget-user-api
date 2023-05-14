package kz.bars.family.budget.user.api.JWT;

public class JWTSecurityConstants {
    public static final String[] UN_SECURED_URLs = {"/api/auth/**", "/api-docs/**", "/swagger-ui/**",
            "/info", "/healthcheck", "/metrics"};
    public static final String[] SECURED_URLs = {"/api/users/**"};
    public static final String SECRET_KEY = "MySecretKeyGenJWT_for_Budget_API";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final long EXPIRATION_TIME = 60*60*1000; // 60 minutes

}
