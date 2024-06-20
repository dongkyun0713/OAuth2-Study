package com.example.oauth2_study.controller;

import com.example.oauth2_study.dto.UserDTO;
import com.example.oauth2_study.repository.UserRepository;
import com.example.oauth2_study.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/profile")
    public ResponseEntity<UserDTO> getUserProfile(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return getUserDTOResponseEntity(oAuth2User, userRepository);
    }

    static ResponseEntity<UserDTO> getUserDTOResponseEntity(
            @AuthenticationPrincipal OAuth2User oAuth2User,
            UserRepository userRepository) {
        if (oAuth2User == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = oAuth2User.getAttribute("username");
        if (username == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }

        UserEntity userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(userEntity.getUsername());
        userDTO.setName(userEntity.getName());
        userDTO.setRole(userEntity.getRole());

        return ResponseEntity.ok(userDTO);
    }
}
