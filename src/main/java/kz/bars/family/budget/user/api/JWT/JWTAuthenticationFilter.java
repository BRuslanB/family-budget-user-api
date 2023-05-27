package kz.bars.family.budget.user.api.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.bars.family.budget.user.api.exeption.TokenExpiredException;
import kz.bars.family.budget.user.api.exeption.UserNotFoundException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Log4j2
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

        // Проверка наличия access token или refresh token в заголовке запроса
        String authHeader = request.getHeader(JWTSecurityConstants.AUTH_HEADER_STRING);
        String refreshHeader = request.getHeader(JWTSecurityConstants.REFRESH_HEADER_STRING);

        if (authHeader == null && refreshHeader == null) { // Если оба заголовка равны null, пропускаем фильтр

            filterChain.doFilter(request, response);
            return;

        } else if (authHeader != null) { // При наличии access token в заголовке запроса

            String accessToken;
            String userName = null;

            if (authHeader.startsWith(JWTSecurityConstants.TOKEN_PREFIX) &&
                    authHeader.length() > JWTSecurityConstants.TOKEN_PREFIX.length()) {

                accessToken = authHeader.substring(JWTSecurityConstants.TOKEN_PREFIX.length());
                try {
                    userName = jwtTokenProvider.extractUsernameFromToken(accessToken, JWTSecurityConstants.AUTH_SECRET_KEY);
                } catch (TokenExpiredException ex) {
                    log.error("!Access Token has expired or invalid, token={}", accessToken);
                }

                if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                    try {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                        // Валидация access token
                        if (jwtTokenProvider.validateAccessToken(accessToken, userDetails)) {
                            var authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                                    userDetails.getAuthorities());
                            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authToken);
                        }
                    } catch (UserNotFoundException ignored) {
                    }
                }

            } else {

                filterChain.doFilter(request, response); //пропускаем фильтр
                return;
            }

        } else { // При наличии refresh token в заголовке запроса

            String refreshToken;
            String userName = null;

            if (refreshHeader.startsWith(JWTSecurityConstants.TOKEN_PREFIX) &&
                    refreshHeader.length() > JWTSecurityConstants.TOKEN_PREFIX.length()) {

                refreshToken = refreshHeader.substring(JWTSecurityConstants.TOKEN_PREFIX.length());
                try {
                    userName = jwtTokenProvider.extractUsernameFromToken(refreshToken, JWTSecurityConstants.REFRESH_SECRET_KEY);
                } catch (TokenExpiredException ex) {
                    log.error("!Refresh Token has expired or invalid, token={}", refreshToken);

                    filterChain.doFilter(request, response); //пропускаем фильтр
                    return;
                }

                if (userName != null) {

                    try {
                        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                        // Валидация refresh token
                        if (jwtTokenProvider.validateRefreshToken(refreshToken, userDetails)) {
                            // Пропускаем запросы на /api/auth/refreshtoken
                            if (request.getRequestURI().equals("/api/auth/refreshtoken")) {
                                // Передаем обработку на контроллер refreshToken, пропускаем фильтр
                                filterChain.doFilter(request, response);
                                return;
                            }
                        }
                    } catch (UserNotFoundException ignored) {
                    }
                }

            } else {

                filterChain.doFilter(request, response); //пропускаем фильтр
                return;
            }
        }

        filterChain.doFilter(request, response); //пропускаем фильтр
    }

}
