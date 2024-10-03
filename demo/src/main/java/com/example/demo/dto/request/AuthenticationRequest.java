package com.example.demo.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

//username, pass ng dùng nhập vào
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AuthenticationRequest {
    String username;
    String password;
}
