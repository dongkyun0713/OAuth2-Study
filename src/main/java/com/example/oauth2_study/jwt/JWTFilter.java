package com.example.oauth2_study.jwt;

import com.example.oauth2_study.dto.CustomOAuth2User;
import com.example.oauth2_study.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;

public class JWTFilter extends OncePerRequestFilter {

    private static final String LOGIN_URI_PATTERN = "^/login(?:/.*)?$";
    private static final String OAUTH2_URI_PATTERN = "^/oauth2(?:/.*)?$";
    private static final String AUTHORIZATION_COOKIE_NAME = "Authorization";
    private static final String TOKEN_EXPIRED_MESSAGE = "토큰 만료";

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();

        // 로그인 및 OAuth2 요청에 대해서는 JWT 검사를 건너뜀
        if (shouldSkipAuthentication(requestUri)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = extractAuthorizationToken(request);

        if (authorization == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            handleJwtAuthentication(authorization);

        } catch (ExpiredJwtException e) {
            handleExpiredJwtException(response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldSkipAuthentication(String requestUri) {
        return requestUri.matches(LOGIN_URI_PATTERN) || requestUri.matches(OAUTH2_URI_PATTERN);
    }

    private String extractAuthorizationToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(AUTHORIZATION_COOKIE_NAME)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void handleJwtAuthentication(String token) throws ExpiredJwtException {
        if (jwtUtil.isExpired(token)) {
            throw new ExpiredJwtException(null, null, TOKEN_EXPIRED_MESSAGE);
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserDTO userDTO = UserDTO.createFromJwt(username, role);
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private void handleExpiredJwtException(HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, TOKEN_EXPIRED_MESSAGE);
    }
}
