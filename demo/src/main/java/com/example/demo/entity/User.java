package com.example.demo.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

import java.time.LocalDate;

@Getter
@Setter//các dto hay dùng luôn Data (=getter, set, equals() và hashCode(),toString():, Constructor:)
@NoArgsConstructor //tự tạo cons ko tham số (khi truyền dl theo consturct)
@AllArgsConstructor //tạo cons có tham số
@Builder
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)// có nhất thiết phải có dòng này
    private String id;
    private String username;
    private String password; // cái này nó tự gen hay c viết đó, t tải y tutor đó, c xem tutor ko, xin link nèo
    private String firstName;
    private String lastName;
    private LocalDate dob;

}
