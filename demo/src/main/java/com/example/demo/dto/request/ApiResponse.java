package com.example.demo.dto.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import lombok.experimental.FieldDefaults;

//chứa all fill để chuẩn hóa cho api của mình
//class: response api chuẩn
@Data
@FieldDefaults(level = AccessLevel.PRIVATE)

@Builder
@NoArgsConstructor
@AllArgsConstructor

@JsonInclude(JsonInclude.Include.NON_NULL) //thêm chỉ để nếu cái fill nào null thì ko in ra, chỉ in cái ko null
public class ApiResponse<T>{//cách viết k cần cố định kiểu dl trả về
    @Builder.Default//gắn gtri mặc định cho builder (để những thuộc tính có sẵn gtri (vd code=1001) thì sau sẽ nhận gtri đó luôn, mà k phải set buider().code(1001) nữa
    int code= 1001;
    String message;
    T result;// kiểu trả về thay đổi tùy vào từng api, nên đặt là T


    //sao chỉ là 1 class bthg mà dùng postman n lại ra cấu trúc theo thứ tự thuộc tính à
    //kiểu postman n dựa vào đâu mà lại coi cái này là 1 apiresponse?
    //vì trả về dạng json nên tự chuyển đtg apiresponse thành json
}

//1. Tại sao không cần toString() mà vẫn trả về được đối tượng?
//việc trả về đối tượng dạng JSON ko phụ thuộc vào việc ĐN phương thức toString().
// Đây là nhờ vào cơ chế serialization (tuần tự hóa) của các thư viện như Jackson
// mà Spring Boot sd để tự động chuyển đổi các đối tượng Java thành JSON.

//Khi Spring Boot xử lý một đối tượng ApiResponse, Jackson sẽ dựa vào các getter để tạo JSON: