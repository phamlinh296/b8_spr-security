package com.example.demo.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AuthenticationResponse {
    boolean authenticated; //true nếu nhập đúng username, pass

    //vid9. thay vì trả về true/false, thì trả về token cho cac lần req tiếp theo.
    String token;
}
