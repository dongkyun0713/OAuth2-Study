package com.example.oauth2_study.dto;

import com.example.oauth2_study.entity.Role;
import com.example.oauth2_study.entity.User;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private String username;
    private String name;
    private String role;


    public static UserDTO newUserDTO(String username, String name, String role) {
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setName(name);
        userDTO.setRole(role);
        return userDTO;
    }

    public static UserDTO createFromJwt(String username, String role) {
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);
        return userDTO;
    }
}
