package com.example.oauth2_study.config;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import com.example.oauth2_study.jwt.JWTFilter;
import com.example.oauth2_study.oauth2.CustomSuccessHandler;
import com.example.oauth2_study.service.CustomOAuth2UserService;
import com.example.oauth2_study.jwt.JWTUtil;
import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String[] PERMITTED_URLS = {
            "/"
    };

    private static final String ALLOWED_ORIGIN = "http://localhost:3000";
    private static final String ALLOWED_METHODS_ALL = "*";
    private static final String ALLOWED_HEADERS_ALL = "*";
    private static final long MAX_AGE_SECONDS = 3600L;
    private static final String EXPOSED_COOKIE_HEADER = "Set-Cookie";
    private static final String EXPOSED_AUTHORIZATION_HEADER = "Authorization";

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler,
                          JWTUtil jwtUtil) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        configureCors(http);
        configureHttpSecurity(http);
        configureJwtFilter(http);
        configureOAuth2Login(http);
        configureAuthorization(http);
        configureSessionManagement(http);
        return http.build();
    }

    private void configureCors(HttpSecurity http) throws Exception {
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Collections.singletonList(ALLOWED_ORIGIN));
            configuration.setAllowedMethods(Collections.singletonList(ALLOWED_METHODS_ALL));
            configuration.setAllowCredentials(true);
            configuration.setAllowedHeaders(Collections.singletonList(ALLOWED_HEADERS_ALL));
            configuration.setMaxAge(MAX_AGE_SECONDS);
            configuration.setExposedHeaders(Collections.singletonList(EXPOSED_COOKIE_HEADER));
            configuration.setExposedHeaders(Collections.singletonList(EXPOSED_AUTHORIZATION_HEADER));
            return configuration;
        }));
    }

    private void configureHttpSecurity(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);
    }

    private void configureJwtFilter(HttpSecurity http) throws Exception {
        http.addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);
    }

    private void configureOAuth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                        .userService(customOAuth2UserService))
                .successHandler(customSuccessHandler)
        );
    }

    private void configureAuthorization(HttpSecurity http) throws Exception {
       for (String url : PERMITTED_URLS) {
           http.authorizeHttpRequests(auth -> auth
                   .requestMatchers(antMatcher(url)).permitAll()
                   .anyRequest().authenticated());

       }
    }

    private void configureSessionManagement(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
}
