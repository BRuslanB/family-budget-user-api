package kz.bars.family.budget.user.api.JWT;

public class JWTSecurityConstants {
    public static final String[] UN_SECURED_URLs = {"/api/auth/**", "/api-docs/**", "/swagger-ui/**",
            "/info", "/healthcheck", "/metrics"};
    public static final String[] SECURED_URLs = {"/api/users/**"};
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String AUTH_SECRET_KEY = "MySecretKeyGenAuthorizationToken";
    public static final String REFRESH_SECRET_KEY = "MySecretKeyGenRefreshToken";
    public static final String AUTH_HEADER_STRING = "Authorization";
    public static final String REFRESH_HEADER_STRING = "Refresh-Token";
    public static final long AUTH_TOKEN_EXPIRATION_TIME = 60*1000*60; // 60 minutes
//    public static final long AUTH_TOKEN_EXPIRATION_TIME = 60*1000; // 1 minute
    public static final long REFRESH_TOKEN_EXPIRATION_TIME = 60*1000*60*24*30L; // 1 month
//    public static final long REFRESH_TOKEN_EXPIRATION_TIME = 60*1000*5; // 5 minute

}
