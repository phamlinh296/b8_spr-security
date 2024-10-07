package com.example.demo.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;

@Configuration //run các pthuc public có @bean
@EnableWebSecurity
public class SecurityConfig {
    private final String[] PUBLIC_ENDPOINTS = {
            "/users", "/auth/token", "/auth/introspect", "/auth/logout", "/auth/refresh"
    };

    @Value("${jwt.signerKey}")
    private String signerKey;
    //1. Cấu hình bộ lọc bảo mật (SecurityFilterChain)
    // xem yc http nào cần xác thực, yc nào k
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        //Cho phép all yc POST đến các endpoint công khai (PUBLIC_ENDPOINTS): ko cần xác thực (.permitAll())
        httpSecurity.authorizeHttpRequests(request ->// cấp phép cho các yêu cầu HTTP.
                request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()//yc khác yc ng dùng phải được xác thực
        );

        //JWT trong OAuth2: để xác thực người dùng.
        //JWT (sử dụng khóa ký) được cấu hình để xác minh các token JWT hợp lệ.
        httpSecurity.oauth2ResourceServer(oauth2 ->// cấu hình ứng dụng như 1máy chủ tài nguyên OAuth 2.0, và sd JWT để xác thực.
                oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder()))// Thiết lập bộ giải mã JWT
        );
        //.oauth2ResourceServer(): Chỉ định rằng ứng dụng hđ như 1 máy chủ tài nguyên
        //.jwt(): chỉ định rằng Access Token mà client gửi lên sẽ là JWT. JWT là một loại token chứa thông tin mã hóa (claims) và được ký với một khóa bí mật.
        //jwtConfigurer.decoder(jwtDecoder()): Thiết lập bộ giải mã JWT để ktra tính hợp lệ của token.
        //jwtDecoder(): tạo bộ giải mã JWT.  trả về đối tượng JwtDecoder,
        // giúp server giải mã JWT và ktra xem token có hợp lệ không.
        // JwtDecoder ktra các thông tin trong token (vd: chữ ký số, tgina hết hạn, quyền truy cập).

        //giải thích:
        //1. client gửi yc kèm jwt trong header, dạng: Authorization: Bearer <jwt-token>
        //2. app đc cấu hình thành OAuth2 Resource Server để ktra jwt trong header
        //3. oauth2.jwt() nghĩa là token cần giải mã ở đây là jwt()
        //4. jwtConfigurer.decoder(jwtDecoder()): thiết lập bô giải mã jwt
            // jwtDecoder():trả về đối tượng JwtDecoder với khóa bí mật và thuật toán cụ thể để giải mã JWT
        //JwtDecoder giải mã thành công JWT, sẽ trích xuất các ttin như
        //  subject (ai là chủ sở hữu token),
        //  scope (phạm vi quyền hạn),
        //  expiration (thời gian hết hạn), và
        //  kiểm tra xem JWT có hợp lệ:
        //  Nếu JWT không hợp lệ: Resource Server từ chối yc và trả về phản hồi lỗi (401 Unauthorized) cho client.

        //vô hiệu hóa CSRF: vì ứng dụng này sd JWT, không cần lưu trữ phiên và bảo vệ CSRF.
//        httpSecurity.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        // CSRF thường bị vô hiệu hóa khi lviệc với các API không trạng thái (stateless)
        // như OAuth2 và JWT, vì ko sd bảo mật dựa trên phiên làm việc (session-based security).
        //vhh để tránh các kiểm tra không cần thiết, giúp đơn giản hóa và tăng hiệu suất hệ thống.

        //API là "không trạng thái" (stateless): là yc từ client đến server là độc lập,
        // Mỗi yc chứa all thông tin cần thiết để server xác thực và xử lý (token JWT chứa tất cả thông tin cần thiết về người dùng)
        // server ko lưu giữ thông tin nào về trạng thái của người dùng
        return httpSecurity.build();
    }

    //2.Cấu hình bộ giải mã JWT:để giải mã các JWT được gửi từ phía client
    @Bean
    JwtDecoder jwtDecoder() { // trả về JwtDecoder, để giải mã các token JWT
        //1. Tạo khóa bí mật (SecretKeySpec) (chuyển khóa kí thành mảng byte)
        SecretKeySpec secretKeySpec = new SecretKeySpec(signerKey.getBytes(), "HS512");//tên ttoan điền đây k qtr
        return NimbusJwtDecoder
                .withSecretKey(secretKeySpec)//2. Tạo bộ giải mã JWT (JwtDecoder)
                .macAlgorithm(MacAlgorithm.HS512)//giải mã các JWT được ký bằng thuật toán này.
                .build();
    }
    //>> tạo bộ giải mã JwtDecoder: = nimbus với khóa bí mật + thuật toán
}

//quy trình:
//1. người dùng gửi yc tới server, JWT sẽ đính kèm vào header của yc (thường là header Authorization).
//2. ktra yc: (vd này)
//  - yc POST đến endpoint công khai >> k cần xác thực
//  - yc khác:  cần xác thực JWT.
//3. Giải mã, xác thực JWT:
//  - giải mã JWT: sd JwtDecoder (sd khóa bí mật (signerKey) và thuật toán HMAC-SHA512 để giải token jwt)
//  > hợp lệ: truy cập; ko hợp lệ: từ chối + lỗi

//Resource Server
//1 ứng dụng/ ng dùng muốn truy cập tài nguyên (API, dl người dùng,.)
// >> phải gửi token đến Resource Server, để kiểm tra tính hợp lệ của token mới cho truy cập.
//OAuth2 Resource Server: Là một Resource Server trong kiến trúc OAuth2,
//sd JWT là token xác thực