package com.example.demo.service;

import com.example.demo.dto.request.AuthenticationRequest;
import com.example.demo.dto.request.IntrospectRequest;
import com.example.demo.dto.response.AuthenticationResponse;
import com.example.demo.dto.response.IntrospectResponse;
import com.example.demo.exception.AppException;
import com.example.demo.exception.ErrorCode;
import com.example.demo.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
@Slf4j// thêm anno này của lombok mới dùng đc  log.error("Cannot create token", e);
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {
    @NonFinal//đánh dấu nonfinal để ko inject vào constructor
    @Value("${jwt.signerKey}")//@value để đọc biến từ file yaml
//    @Value("sEzN49A5eMzybTam7Km8m5KHpF36Vp+YnVZ/B5VaVsUrHvgDBvnIEy/MznZGVl+5")
    //singer key, chữ kí này làm cho dù mình ko issue 1 token, nhưng có nó sẽ vẫn verify được
    //>> chữ kí này rất qtr >> cần bve chặt chẽ >> k để ở đây mà kbao trong application.yaml
    //để khi devops deploy lên mtruong cao hơn, họ sẽ dùng signer key khác để đảm bảo an toàn
    protected String SIGNER_KEY;

    UserRepository userRepository; //lấy ttin từ db

    //pthuc xác thực trả về true/fale khi đăng nhập đúng
//    public boolean authenticate2(AuthenticationRequest request){
//        //lấy user từ db theo username mà request cung cấp
//        var user= userRepository.findByUsername(request.getUsername())//var tự động suy diễn kiểu dl
//                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
//        //lay ra user rồi >> khớp pass của request với user
//        PasswordEncoder passwordEncoder= new BCryptPasswordEncoder(10);
//        return passwordEncoder.matches(request.getPassword(), user.getPassword());
//    }

    //token: thay vì trả về true/false thì sẽ trả về token: set gtri cho boolean, string
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        var user= userRepository.findByUsername(request.getUsername())
                .orElseThrow(()-> new AppException(ErrorCode.USER_NOT_EXISTED));
        //lấy user> khớp pass, set thuojc tính boolean
        PasswordEncoder passwordEncoder= new BCryptPasswordEncoder(10);
        boolean authenticated=passwordEncoder.matches(request.getPassword(), user.getPassword());
        //nếu pas ko khớp thì trả về lỗi unauthenticated.
        if(!authenticated)
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        //thành công thì gen token, - thư viện nimbusds; và return kqua
        var token= generateToken(request.getUsername());
        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)//k cần lắm, thích thì cho
                .build();
    }

    //pthuc cục bộ tạo token =nimbus
    private String generateToken(String username){
        //1. header- thuật toán sd
        JWSHeader jwsHeader=new JWSHeader(JWSAlgorithm.HS512);
        //2. ndung gửi đi trong token. ND qtr gồm
        JWTClaimsSet jwtClaimsSet= new JWTClaimsSet.Builder()
                .subject(username)//đại diện user đăng nhập
                .issuer("devteria.com")//domain service
                .issueTime(new Date())//hiện tại
                .expirationTime(new Date(
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()
                )) //set token hết hạn sau 1h
                .claim("customClaim","Custom")
                .build();
        Payload payload= new Payload(jwtClaimsSet.toJSONObject());
//tao obj token:
        JWSObject jwsObject=new JWSObject(jwsHeader, payload);
        try {
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));////MACSigner() nhận tham số là 1 chuỗi 32byte
            return jwsObject.serialize();// return obj ở đây
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }
    }
    //2. valid token
    public IntrospectResponse introspect(IntrospectRequest request)
            throws JOSEException, ParseException {
        var token = request.getToken();

        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());
        SignedJWT signedJWT = SignedJWT.parse(token);

        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        var verified = signedJWT.verify(verifier);

        return IntrospectResponse.builder()
                .valid(verified && expiryTime.after(new Date()))
                .build();
    }
    //Lấy token từ request.
    //Sử dụng JWSVerifier và MACVerifier để xác thực chữ ký của token.
    //Lấy thời gian hết hạn của token từ phần JWTClaimsSet.
    //Xác thực token thông qua verify() và kiểm tra thời gian hết hạn của token có còn hợp lệ hay không.
    //Trả về một đối tượng IntrospectResponse với kết quả xác thực.
}

