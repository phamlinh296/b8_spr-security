package com.example.demo.exception;

public class AppException extends RuntimeException{
    private ErrorCode errorCode;


    public AppException(ErrorCode errorCode) {//chỗ này có tham số
        super(errorCode.getMessage());//vì lỗi này lưu vào cons của cha,>>khớp vào getmessage() của cha
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
}
//tsao phải có super():
//vì khi khai báo 1 class ex tùy chỉnh, phải truyền ex cho cha là throwable or runtimeexception thì
//getmessage của cha mới nhận đc message và lưu trữ nó.
//nếu k gọi, cha ko lưu message, sau gọi getmessage() sẽ trả về null

//super(errorCode.getMessage()): thông báo lỗi từ ErrorCode được truyền lên lớp cha
// và lưu trữ trong thuộc tính message của Throwable - lớp cha của RuntimeException

//NHỚ: CHỈ KHI LỚP CON OVERRIDE PTHUC CỦA CHA, THÌ ĐTG LỚP CON. GETMESSAGE() MỚI TRẢ VỀ GIÁ TRỊ CỦA CON
//KHÔNG OVERRIDE THÌ N SẼ TRẢ VỀ GTRI CUỦA CHA.

//cha có contruct này
//public RuntimeException(String message) {
//    super(message);  // Lưu thông báo lỗi vào đối tượng Exception
//}