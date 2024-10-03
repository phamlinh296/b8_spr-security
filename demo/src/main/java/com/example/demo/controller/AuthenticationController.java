package com.example.demo.controller;

import com.example.demo.dto.request.ApiResponse;
import com.example.demo.dto.request.AuthenticationRequest;
import com.example.demo.dto.request.IntrospectRequest;
import com.example.demo.dto.response.AuthenticationResponse;
import com.example.demo.dto.response.IntrospectResponse;
import com.example.demo.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor //tự động autowired các bean final
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)//đánh dấu all là final
public class AuthenticationController {
    AuthenticationService authenticationService;

    //check đăng nhập đúng k và trả về token
    @PostMapping("/token")
//    ApiResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
//        boolean result= authenticationService.authenticate(request);
//        return ApiResponse.<AuthenticationResponse>builder()
//                .result(AuthenticationResponse.builder()//set thuộc tính result của apirespose
//                        .authenticated(result)
//                        .build())
//                .build();
//    }
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        var result= authenticationService.authenticate(request);//đtg authenresponse
        return ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();
        //thuộc tính result của apiresponse là đtg authenticationresponse
    }

    //2. check token có valid ko
    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> authenticate(@RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        var result= authenticationService.introspect(request);//đtg authenresponse
        return ApiResponse.<IntrospectResponse>builder()
                .result(result)
                .build();
        //thuộc tính result của apiresponse là đtg authenticationresponse
    }
}
