package com.example.demo.mapper;

import com.example.demo.dto.request.UserCreationRequest;
import com.example.demo.dto.request.UserCreationRequest;
import com.example.demo.dto.response.UserResponse;
import com.example.demo.entity.User;
import jakarta.validation.Valid;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")// Kbao interface là một mapper của MapStruct và tích hợp với Spring.
public interface UserMapper {
    @Mapping(source = "firstName", target = "firstName")//thêm vào cho chắc, k thêm lúc đc lúc ko
    User toUser(@Valid UserCreationRequest request); // ánh xạ các thuộc tính từ UserCreationRequest sang User.
    void updateUser (@MappingTarget User user, UserCreationRequest request);//@MappingTarget để map 2 cái này vào
//    @Mapping(source = "firstName", target = "lastName")//map first của user mình get ra sang last của userresponse, trả ra màn. VD: user có first= hanh >> last của userrespone=hanh; và first của response vẫn map btg= hanh
//    @Mapping(target = "firstName", ignore = true)//ignore thuộc tính firstname, ko map >> first của target (userrespon)= null.
    UserResponse toUserResponse(User user);//map user vào userresponse.
    //viết như trên đc do all đều có thuộc tính map tương ứng, dob sang dob, pas> pas
    //còn nếu map khác thuộc tính:  first sang lastName thì:
    //thêm anno Mapping trước pthuc đó

}
// spring" là ko bắt buộc
// khi dùng "spring", nó sẽ tích hợp với Spring Framework và cho phép sd @Autowired
// hoặc constructor injection để tiêm phụ thuộc mapper vào các class khác

//Nếu chỉ khai báo interface UserMapper mà ko có @Mapper(componentModel = "spring"),
// Spring không thể quản lý nó như một bean và sẽ
// ko thể tiêm phụ thuộc thông qua @Autowired hoặc constructor injection.

//Để Spring có thể quản lý 1 bean và cho phép tiêm phụ thuộc,
// đối tượng đó phải được Spring biết đến và quản lý bởi Spring IoC container.

//2. tsao dùng interface mà ko phải class:
//MapStruct là thư viện chuyên dụng cho việc ánh xạ (mapping) giữa các đối tượng.
// Khi định nghĩa một interface với các phương thức ánh xạ,
// MapStruct sẽ tự động tạo ra một class thực thi (implementation)
// cho interface đó trong thời gian biên dịch.
//>>>> chỉ cần dùng inter, còn mapstruct tuw triển khai class
