package me.hyeok.jwttutorial.dto;

import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDTO {

    @NotNull
    @Size(min = 3, max = 50)  // @Valid 관련 어노테이션 추가
    private String username;

    @NotNull
    @Size(min = 3, max = 100)
    private String password;
}
