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
    //Token gồm một phần chữ ký được tạo từ khóa bí mật đó và nội dung của token (payload).
    // Điều này giúp bảo vệ nội dung token khỏi bị chỉnh sửa bởi các bên không tin cậy.

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
        //2.  payload- nd chính của JWT, chứa các thông tin (claims) về người dùng và token, để gửi đi
        JWTClaimsSet jwtClaimsSet= new JWTClaimsSet.Builder()
                .subject(username)//đại diện user đăng nhập
                .issuer("devteria.com")// service phát hành token
                .issueTime(new Date())// thời gian phát hành token
                .expirationTime(new Date(
                        Instant.now().plus(1, ChronoUnit.HOURS).toEpochMilli()
                )) //set token hết hạn sau 1h
                .claim("customClaim","Custom")//thêm ttin tuỳ chỉnh
                .build();
        Payload payload= new Payload(jwtClaimsSet.toJSONObject()); //payload xây dựng từ JWTClaimsSet và chuyển thành đối tượng JSONObject để mã hóa.
//tao obj token:
        JWSObject jwsObject=new JWSObject(jwsHeader, payload); //Tạo đối tượng JWT với header và payload.
        try { // mã hóa token bằng cách sd MAC (Message Authentication Code) và key bí mật (SIGNER_KEY).
            jwsObject.sign(new MACSigner(SIGNER_KEY.getBytes()));////MACSigner() nhận tham số là 1 chuỗi 32byte
            //SIGNER_KEY.getBytes(): Nhận key bí mật (key này phải có ít nhất 32 bytes để tương thích với HS512).
            //jwsObject.sign(): Tạo chữ ký cho token bằng thuật toán được định nghĩa trong header (HS512).
            return jwsObject.serialize();// return obj ở đây
            //Chuỗi JWT sẽ được trả về dưới dạng String, đây là token hoàn chỉnh bao gồm: header, payload, và signature.
        } catch (JOSEException e) {//Bắt lỗi nếu xảy ra sự cố trong quá trình tạo token.
            log.error("Cannot create token", e);//Ghi lại thông báo lỗi nếu không thể tạo token
            throw new RuntimeException(e);
        }
    }
    //2. valid token
    public IntrospectResponse introspect(IntrospectRequest request)
            throws JOSEException, ParseException {
        var token = request.getToken();

        JWSVerifier verifier = new MACVerifier(SIGNER_KEY.getBytes());//mã hóa bằng MAC nên verify vc bằng MAC
        //chuyển token(chuỗi kí tự mã hóa) thành đối tượng SignedJWT.(đtg thao tác đc để lấy thông tin)
        SignedJWT signedJWT = SignedJWT.parse(token);//phân tích chuỗi token thành 3 phần: header, payload (claims), và signature.

        //1. ktr hết hạn chưa
        Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime(); //Lấy expiration time từ claims của token.
        //2. ktr chữ ký
        var verified = signedJWT.verify(verifier);
        //verify(verifier) sẽ kiểm tra xem chữ ký này có đúng không,
        // nghĩa là token có thực sự đến từ server (xác thực) và chưa bị chỉnh sửa (toàn vẹn)

        //verifier (MACVerifier) tạo ra từ khóa bí mật (SIGNER_KEY).
        //dùng để xác minh token JWT chưa bị thay đổi và đến từ nguồn phát hành đáng tin cậy.
        //verify() để check 2 cái: signedJWT- với verifier

        return IntrospectResponse.builder()
                .valid(verified && expiryTime.after(new Date())) //Xđ xem token có hợp lệ hay không dựa trên hai điều kiện
                .build();
        //verified: xác minh token có chữ ký hợp lệ (được phát hành bởi máy chủ với khóa bí mật đúng).
        //expiryTime.after(new Date()): Token chưa hết hạn.
        //(tgian hết hạn của token là sau tgian hiện tại (nghĩa là token vẫn còn hiệu lực).
    }
    //CÁCH HOẠT ĐỘNG:
    //Lấy token từ request.
    //Sử dụng JWSVerifier và MACVerifier để xác thực chữ ký của token.
    //Lấy thời gian hết hạn của token từ phần JWTClaimsSet.
    //Xác thực token thông qua verify() và kiểm tra thời gian hết hạn của token có còn hợp lệ hay không.
    //Trả về một đối tượng IntrospectResponse với kết quả xác thực.

    //Phương thức này nhận một yêu cầu chứa JWT token từ client.
    //Nó kiểm tra tính hợp lệ của token bằng cách:
    //Kiểm tra chữ ký số để xác nhận rằng token không bị thay đổi và được phát hành bởi server.
    //Kiểm tra thời gian hết hạn để đảm bảo token vẫn còn hiệu lực.
    //Nếu token hợp lệ (cả về chữ ký và thời gian), phương thức sẽ trả về một đối tượng IntrospectResponse với valid = true. Nếu không, valid sẽ là false.
}

