package com.example.oauth2_study.oauth2;

import com.example.oauth2_study.dto.CustomOAuth2User;
import com.example.oauth2_study.entity.Role;
import com.example.oauth2_study.jwt.JWTUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private static final long JWT_EXPIRATION_TIME_SECONDS = 60 * 60 * 60; // 3 hours in seconds
    private static final String AUTHORIZATION_COOKIE_NAME = "Authorization";
    private static final int COOKIE_EXPIRATION_TIME_SECONDS = 60 * 60 * 60;
    private static final String DEFAULT_REDIRECT_URL = "/";
    private static final String REDIRECT_URL = "http://localhost:3000/";

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        String role = extractRoleFromAuthorities(authentication.getAuthorities());

        String token = jwtUtil.createJwt(username, role, JWT_EXPIRATION_TIME_SECONDS);

        addJwtCookie(response, token);
        redirectToHomePage(response);
    }

    private String extractRoleFromAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        if (iterator.hasNext()) {
            return iterator.next().getAuthority();
        }
        return Role.ROLE_USER.name(); // 기본 역할 설정
    }

    private void addJwtCookie(HttpServletResponse response, String token) {
        Cookie cookie = createCookie(token);
        response.addCookie(cookie);
    }

    private Cookie createCookie(String value) {
        Cookie cookie = new Cookie(AUTHORIZATION_COOKIE_NAME, value);
        cookie.setMaxAge(COOKIE_EXPIRATION_TIME_SECONDS);
        //cookie.setSecure(true);
        cookie.setPath(DEFAULT_REDIRECT_URL);
        cookie.setHttpOnly(true);
        return cookie;
    }

    private void redirectToHomePage(HttpServletResponse response) throws IOException {
        response.sendRedirect(REDIRECT_URL);
    }
}
