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

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();

        // 로그인 및 OAuth2 요청에 대해서는 JWT 검사를 건너뜀
        if (requestUri.matches("^/login(?:/.*)?$") || requestUri.matches("^/oauth2(?:/.*)?$")) {
            filterChain.doFilter(request, response);
            return;
        }

        // cookie들을 불러온 뒤 Authorization Key에 담긴 쿠키를 찾음
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("Authorization")) {
                    authorization = cookie.getValue();
                }
            }
        }

        // Authorization 헤더 검증
        if (authorization == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰
        String token = authorization;

        try {
            // 토큰 소멸 시간 검증
            if (jwtUtil.isExpired(token)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
                return;
            }

            // 토큰에서 username과 role 획득
            String username = jwtUtil.getUsername(token);
            String role = jwtUtil.getRole(token);

            // userDTO를 생성하여 값 set
            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setRole(role);

            // UserDetails에 회원 정보 객체 담기
            CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

            // 스프링 시큐리티 인증 토큰 생성
            Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
            // 세션에 사용자 등록
            SecurityContextHolder.getContext().setAuthentication(authToken);

        } catch (ExpiredJwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
