package org.example.spring_oauth2_authorization_server.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterDTO {

    private String clientName;
    private String redirectUris;
    private String postLogoutRedirectUris;
    private String scopes;

}