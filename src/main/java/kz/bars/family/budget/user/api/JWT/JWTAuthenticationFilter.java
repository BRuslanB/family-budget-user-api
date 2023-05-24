package kz.bars.family.budget.user.api.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTAuthenticationFilter extends OncePerRequestFilter {

    JWTTokenProvider jwtTokenProvider;
    UserDetailsService userDetailsService;

    public void setTokenService(JWTTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Проверка наличия access token в заголовке запроса
        String authHeader = request.getHeader(JWTSecurityConstants.AUTH_HEADER_STRING);
        String accessToken = null;
        String userName = null;

        if (authHeader != null && authHeader.startsWith(JWTSecurityConstants.TOKEN_PREFIX)) {
            accessToken = authHeader.substring(7);
            userName = jwtTokenProvider.extractUsernameFromToken(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY);
        }

        if (userName != null & SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            // Валидация access token
            if (jwtTokenProvider.validateAccessToken(accessToken, userDetails)) {
                var authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Проверка наличия refresh token в заголовке запроса и его валидации
        String refreshHeader = request.getHeader(JWTSecurityConstants.REFRESH_HEADER_STRING);
        String refreshToken = null;
        userName = null;

        if (refreshHeader != null && refreshHeader.startsWith(JWTSecurityConstants.TOKEN_PREFIX)) {
            refreshToken = refreshHeader.substring(7);
            userName = jwtTokenProvider.extractUsernameFromToken(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY);
        }

        if (refreshToken != null && userName != null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            if (userDetails != null) {

                // Валидация refresh token
                if (jwtTokenProvider.validateRefreshToken(refreshToken, userDetails)) {
                    // Пропускаем запросы на /api/auth/refreshtoken
                    if (request.getRequestURI().equals("/api/auth/refreshtoken")) {
                        // Передаем обработку на контроллер refreshToken
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }

}
