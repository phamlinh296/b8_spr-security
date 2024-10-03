package com.example.demo.exception;

import com.example.demo.dto.request.ApiResponse;
import com.example.demo.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

//khi chưa viết class này thì: các exception k đc thực thi
//kiểu khi điền get 1 user qua đường dẫn sai >> ko hiển thị user not fount mà hiển thị lỗi 500

@ControllerAdvice// lắng nghe tất cả các exception trong ứng dụng.
public class GlobalExceptionHandler {
    //all excep runtime (vd: trùng user,..)
//    @ExceptionHandler(value = RuntimeException.class)
//    ResponseEntity<String> handlingRunTimeException(RuntimeException exception){ //trả về phản hồi ex là 1 string
//        return ResponseEntity.badRequest().body(exception.getMessage());
//    }


//    @ExceptionHandler(value = RuntimeException.class)
//    ResponseEntity<ApiResponse> handlingRunTimeException(RuntimeException exception){//trả về phản hồi là 1 apiresponse dạng json, chứa message là ex.
//        ApiResponse<User> apiResponse=new ApiResponse<>();
//        apiResponse.setCode(1001);//ĐỂ tùy chỉnh setcode thì đn class Errorcode
//        apiResponse.setMessage(exception.getMessage());//ex runtimeexcep có pthuc getMessage à? uh, getMessage() là một phương thức của Throwable (class cha của RuntimeException), và nó được sử dụng để lấy thông điệp lỗi được truyền vào khi exception được tạo ra.
//        return ResponseEntity.badRequest().body(apiResponse);
//    }

    //app exception - trả về code tùy chỉnh
    @ExceptionHandler(value = AppException.class)//bắt laoij ex này khi service ném ra
    ResponseEntity<ApiResponse> handlingAppException(AppException exception){//trả về phản hồi là 1 apiresponse dạng json, chứa message là ex.
        ApiResponse<User> apiResponse=new ApiResponse<>();

        ErrorCode errorCode= exception.getErrorCode();//lấy lỗi từ appexception

        apiResponse.setCode(errorCode.getCode());//tùy chỉnh setcode thì đn class Errorcode
        apiResponse.setMessage(exception.getMessage());//để ntn đc k, hay phải để errorCode.getMessage()
        return ResponseEntity.badRequest().body(apiResponse);//trả về đtg api chuẩn hóa theo json
    }
    //all exception còn lại, chưa định nghĩa
    @ExceptionHandler(value = Exception.class)
    ResponseEntity<ApiResponse> handlingException(Exception exception){
        ApiResponse<User> apiResponse=new ApiResponse<>();
        apiResponse.setCode(ErrorCode.UNCATEGORIZED_EXCEPTION.getCode());
        apiResponse.setMessage(ErrorCode.UNCATEGORIZED_EXCEPTION.getMessage());    //getmessage của errorCode lấy trong message trong errorcode
//        apiResponse.setMessage(exception.getMessage());      //getmessage của exception thì lấy gtri throw trong pthuc ở service
        return ResponseEntity.badRequest().body(apiResponse);
    }

    // ex khi ko thỏa mãn valid (đủ số kí tự..) //ko đc để đồng thời cái này vs cái dưới, k thì lỗi. vì bắt cùng 1 exception
//    @ExceptionHandler(value = MethodArgumentNotValidException.class)
//    ResponseEntity<String> handlingValidation(MethodArgumentNotValidException exception){
//        return ResponseEntity.badRequest().body(exception.getFieldError().getDefaultMessage());
//    }

    //ex khi ko thỏa mãn valid (đủ số kí tự..)- trả về chuẩn hóa api
    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    ResponseEntity<ApiResponse> handlingValidationApi (MethodArgumentNotValidException exception){
        ApiResponse<User> apiResponse= new ApiResponse<>();

        String enumKey= exception.getFieldError().getDefaultMessage();//lấy thông điệp lỗi. vd @NotNull(message = "NAME_IS_NULL") thì in ra 'NAME_IS_NULL"
        ErrorCode errorCode= ErrorCode.INVALID_KEY;//gán lỗi type vào error trc khi error nhận các gtri lỗi khác
//nếu error nhận các lỗi khác thì chạy bthg, nếu lỗi type thì valueof() gây lỗi và phải catch lại lỗi đó
        try {
            errorCode= ErrorCode.valueOf(enumKey);//pthuc valueOf() có sẵn vs đtg enum; >> phải để message trùng với tên lỗi trong enum (thì ad Enum.valueOf() mới đúng)(neu k de trùng thì phải viết thêm class ánh xạ)
            // lấy ra hằng số enum có tên trùng với chuỗi được cung cấp.
            // Nếu chuỗi không khớp với bất kỳ hằng số nào, Java sẽ ném ra ngoại lệ IllegalArgumentException.
        } catch (IllegalArgumentException argumentException){

        }
        apiResponse.setMessage(errorCode.getMessage());
        apiResponse.setCode(errorCode.getCode());
        return ResponseEntity.badRequest().body(apiResponse);
    }
}
