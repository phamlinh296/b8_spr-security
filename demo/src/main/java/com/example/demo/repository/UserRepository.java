package com.example.demo.repository;

import com.example.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

//lớp này viết chỉ để lay pthuc cho user dùng luôn
@Repository
public interface UserRepository extends JpaRepository<User,String > {

    boolean existsByUsername(String userName);//kiểm tra xem một username đã tồn tại trong csdl hay chưa
    //nma sao chưa override thân mà cx bt là so sánh gtri dlieu request với data đã có nhỉ
    //à vì là:
    //existsBy...: là cú pháp đặc biệt của Spring Data JPA. Spring sẽ tự động tạo ra câu
    // truy vấn SELECT tương ứng để kiểm tra sự tồn tại của một bản ghi.
    // kiểm tra sự tồn tại của bản ghi dựa trên cột username trong bảng user
    //Nó sẽ dịch phương thức thành một câu SQL:
    //SELECT COUNT(*) > 0 FROM user WHERE username = ?
    //Với ? là tham số userName được truyền vào.
    Optional<User> findByUsername(String username);
    //Trong Spring Data JPA, phương thức findByUsername(String username) thường được
    // định nghĩa với kiểu trả về là Optional<User>: cho phép trả về null (k tìm thấy ng dùng)
    //nếu trả về là User thì phải tự kiểm tra và xử lý các trường hợp null bên ngoài phương thức.
}

// sd các phương thức mặc định mà JpaRepository cung cấp mà ko cần viết thêm code nào.


//kiểu all logic, tương tác vs đtg (csdl) thì sẽ làm vs repo.
//repo đại diện cho csdl
//chứ k làm vs entity
