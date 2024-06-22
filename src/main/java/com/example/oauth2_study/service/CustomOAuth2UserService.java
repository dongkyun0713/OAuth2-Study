package com.example.oauth2_study.service;

import com.example.oauth2_study.dto.CustomOAuth2User;
import com.example.oauth2_study.dto.GoogleResponse;
import com.example.oauth2_study.dto.NaverResponse;
import com.example.oauth2_study.dto.OAuth2Response;
import com.example.oauth2_study.dto.UserDTO;
import com.example.oauth2_study.entity.Role;
import com.example.oauth2_study.entity.SocialType;
import com.example.oauth2_study.entity.User;
import com.example.oauth2_study.repository.UserRepository;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info(String.valueOf(oAuth2User));

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = createOAuth2Response(registrationId, oAuth2User.getAttributes());

        if (oAuth2Response == null) {
            return null; // 처리할 수 없는 등록 ID인 경우 null 반환
        }

        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        User existData = userRepository.findByUsername(username);

        if (existData == null) {
            User user = createUserFromOAuth2Response(username, oAuth2Response);
            userRepository.save(user);

            UserDTO userDTO = createUserDTO(username, oAuth2Response.getName());
            return new CustomOAuth2User(userDTO);
        }

        updateUserFromOAuth2Response(existData, oAuth2Response);
        userRepository.save(existData);

        UserDTO userDTO = createUserDTO(username, oAuth2Response.getName());
        return new CustomOAuth2User(userDTO);
    }

    private OAuth2Response createOAuth2Response(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equals(SocialType.naver.name())) {
            return new NaverResponse(attributes);
        } else if (registrationId.equals(SocialType.google.name())) {
            return new GoogleResponse(attributes);
        }
        return null;
    }

    private User createUserFromOAuth2Response(String username, OAuth2Response oAuth2Response) {
        return User.newUser(username, oAuth2Response.getName(), oAuth2Response.getEmail(), Role.ROLE_USER.name());
    }

    private void updateUserFromOAuth2Response(User user, OAuth2Response oAuth2Response) {
        user.update(oAuth2Response.getName(), oAuth2Response.getEmail());
    }

    private UserDTO createUserDTO(String username, String name) {
        return UserDTO.newUserDTO(username, name, Role.ROLE_USER.name());
    }
}
