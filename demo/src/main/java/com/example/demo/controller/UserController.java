package com.example.demo.controller;

import com.example.demo.dto.request.ApiResponse;
import com.example.demo.dto.request.UserCreationRequest;
import com.example.demo.dto.response.UserResponse;
import com.example.demo.entity.User;
import com.example.demo.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController//sao dùng rest mà k dùng controller?
@RequestMapping("/users")//chung cho các pthuc http
public class UserController {
    @Autowired
    private UserService userService;//nhớ autowwrite

    //truyền dlieu để tạo đtg
//    @PostMapping
//    ApiResponse<User> createUserr(@RequestBody @Valid UserCreationRequest request){//map dữ liệu vào request
//        ApiResponse<User> apiResponse= new ApiResponse<>();
//        apiResponse.setResult(userService.createUser(request));//result là đtg user
//        return apiResponse;//gọi đến pthuc của service
//    }
    //Api <UserResponse>
    @PostMapping
    ApiResponse<UserResponse> createUserr2(@RequestBody @Valid UserCreationRequest request){//map dữ liệu vào request
        ApiResponse<UserResponse> apiResponse= new ApiResponse<>();
        apiResponse.setResult(userService.createUser2(request));//result là đtg user
        return apiResponse;//gọi đến pthuc của service
    }
    //nếu trả về đtg:
//    User createUserr(@RequestBody @Valid UserCreationRequest request){//map dữ liệu vào request
//        User user= userService.createUser(request);//result là đtg user
//        return user;//gọi đến pthuc của service
//    }
//userService.createUser(request) trả về một đối tượng (ví dụ: User) sau khi tạo người dùng.
//setResult() sẽ gán đối tượng này vào thuộc tính result của ApiResponse
//Khi API trả về ApiResponse, Jackson sẽ gọi getResult() để lấy giá trị result và serialize nó vào JSON.
// Tương tự với các thuộc tính khác như code và message.
// tóm lại, Jackson tự động gọi các getter như getCode(), getMessage(), và getResult() để tạo ra các trường trong JSON mà không cần phải tự tạo định dạng đó.

    //get đtg
    //trả về userresponse thay vì user
    @GetMapping("/{userId}")
    UserResponse getUserr(@PathVariable("userId") String id){// phải đủ biến ("userId") ko thì lỗi
        return userService.getUser(id);
    }

    @GetMapping
    List<User> getList(){
        return userService.getAllUsers();
    }

    //cập nhật
    @PutMapping("/{userId}")
    UserResponse updateUserr(@PathVariable("userId") String id, @RequestBody UserCreationRequest request){
        return userService.updateUser(id, request);
    }
    //delete
    @DeleteMapping("/{userId}")
    String deleteUserr(@PathVariable("userId") String id){
        userService.deleteUser(id);
        return "đã xóa";
    }
}
