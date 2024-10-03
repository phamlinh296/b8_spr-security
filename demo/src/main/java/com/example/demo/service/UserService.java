package com.example.demo.service;

import com.example.demo.dto.request.UserCreationRequest;
import com.example.demo.dto.request.UserCreationRequest;
import com.example.demo.dto.response.UserResponse;
import com.example.demo.entity.User;
import com.example.demo.exception.AppException;
import com.example.demo.exception.ErrorCode;
import com.example.demo.mapper.UserMapper;
import com.example.demo.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;//truyền repo để sd pthuc crud luôn
    @Autowired
    private UserMapper userMapper; //truyền đtg của interface mapper
    //1.tao dtg: excep là tổn tại rồi thì báo đã tồn tại
    public User createUser(@Valid UserCreationRequest request){
        if(userRepository.existsByUsername(request.getUsername()))
//            throw new RuntimeException("user existed");//nếu muốn tạo ngle tùy chỉnh thì vào appException
            throw new AppException(ErrorCode.USER_EXISTED);//ex tùy chỉnh
//            throw new RuntimeException("Uncategorized");
    //thử dùng builder của Lombok
        //bthg:
//        UserCreationRequest request1= new UserCreationRequest();
        //dùng builder: linh động trong tạo đtg, ko cần phải theo quy chuẩn construct nào, vì truyền thuộc tính kiểu j thì n cx tạo đc
//        UserCreationRequest request2= UserCreationRequest.builder()
//                .firstName("")
//                .lastName("")
//                .build();

        //thay all đống này = dùng mapper:
//        User user= new User();
//        user.setUsername(request.getUsername());
//        user.setPassword(request.getPassword());
//        user.setFirstName(request.getFirstName());
//        user.setLastName(request.getLastName());
//        user.setDob(request.getDob());
        //mapper
//        user= userMapper.toUser(request);//map request vào user, trả ve user
        User user= userMapper.toUser(request);//map request vào user, trả ve user
//        User user= new User();
//        user.setUsername(request.getUsername());
//        user.setPassword(request.getPassword());
//        user.setFirstName(request.getFirstName());
//        user.setLastName(request.getLastName());
//        user.setDob(request.getDob());

        //mã hóa pass, để pass từ request (vd: 1222333) trả về sau khi post sẽ là pass= hằng
        PasswordEncoder passwordEncoder= new BCryptPasswordEncoder(10);//10- (độ mạnh) của thuật toán mã hóa BCrypt.
        // Cụ thể, đây là số vòng lặp (iterations) mà thuật toán BCrypt sẽ thực hiện để mã hóa mật khẩu.
        //Mức giá trị 10 là mức trung bình phổ biến, cân bằng giữa độ an toàn và hiệu suất.
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        //ts ko encode pass của user
        //mà encode pass cua request, xong set lại vào user???????????????
        //do mã hóa request clear hơn, dễ bảo trì hơn nếu sau có thay đổi; mã hóa user cx đc nma k clear
        return userRepository.save(user);
    }

    //nếu dùng để api trả về Userresponse
    public UserResponse createUser2(@Valid UserCreationRequest request){
        if(userRepository.existsByUsername(request.getUsername()))
            throw new AppException(ErrorCode.USER_EXISTED);
        User user= userMapper.toUser(request);// chuyển request sang user
        PasswordEncoder passwordEncoder= new BCryptPasswordEncoder(10);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        //2. chuyển user đã lưu vào db>> userrespose
        return userMapper.toUserResponse(userRepository.save(user));
        //ts ko chuyển trực tiếp request sang userresponse luôn?
        //vì còn lưu vào db làm vc khác,
        //cx có thể chuyển trực tiếp từ request sang dto, mà k qua user, khi:
        //tạm thời, ko cần lưu vào user, client > nhận phản hồi luôn (dto)
    }

    //2. get theo id
    public UserResponse getUser(String userId){
        return userMapper.toUserResponse(userRepository.findById(userId) //cái trong () này là trả về User
                .orElseThrow(() -> new RuntimeException("User not found")));//chỉ in ra khi viết class exception
    }
    //3. update theo id
    public UserResponse updateUser(String userId, UserCreationRequest request){
//        User user= getUser(userId);// gọi luôn gétUser() mà k cần đtg, vì getUser là pthuc của chính class này

        //vì sửa trả về userresponse, nên: getuser ở trên b đổi
        User user= userRepository.findById(userId) //cái trong () này là trả về User
                .orElseThrow(() -> new RuntimeException("User not found"));
//        user.setPassword(request.getPassword());
//        user.setFirstName(request.getFirstName());
//        user.setLastName(request.getLastName());
//        user.setDob(request.getDob());

        //dùng mapper
        userMapper.updateUser(user, request);//map request vào user đã lấy
        return userMapper.toUserResponse(userRepository.save(user));
    }

    //3.5 cách viết kế thừa trực tiếp getuser ở trên dc ko
   //hnhu ko, vì trả về đối tg dạng userrespone, còn vẫn phải lấy user từ db theo id ra, rồi update
    // còn ko lấy đc userresponse từ db thì phải, vì n chỉ là kiểu trả về,
    //vd get ra userrespone ở trên theo id rồi, thì map vào request kiểu gì đúng ko
    //k map đc, nên vaaxn phải bđ từ User xong map


    //4. xóa 1 người theo id
    public void deleteUser(String id){
        userRepository.deleteById(id);
    }
    //5. get list user
    public List<User> getAllUsers(){
        return userRepository.findAll();
    }
}
