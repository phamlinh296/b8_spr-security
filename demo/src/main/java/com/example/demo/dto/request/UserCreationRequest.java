package com.example.demo.dto.request;

import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
//class lưu cc gtri truyền vào
//@Getter
//@Setter
@Data //các dto hay dùng luôn Data (=getter, set, equals() và hashCode(),toString():, Constructor:)
@NoArgsConstructor //tự tạo cons ko tham số (khi truyền dl theo consturct)
@AllArgsConstructor //tạo cons có tham số
@Builder //nhớ thêm ms tạo đc đtg theo buider(); (ko truyền theo construct)
@FieldDefaults(level = AccessLevel.PRIVATE)// xđ phạm vi truy cập cho all biến mà ko ghi phạm vi truy cajp
public class UserCreationRequest {
//    @Size(min=3, message = "username  must have at least 3 characters")
    @Size(min=3, message = "USERNAME_INVALID")//phải để "" này giống error code ko, để như trên đc ko? YEP, phải để trùng tên enum, khác là lỗi.
    String username;

//    @Size(min=8, message = "pw must have at least 8 characters")
    @Size(min=8, message = "INVALID_PASSWORD")//nếu hằng này viet sai + xra TH invalid pass (pass< 8 kí tự) thì mới gọi đến INVALID_KEY
    String password;
    String firstName;
    String lastName;
    LocalDate dob; //tự nhận private do đã có @FieldDefaults ở trên.

}
