package com.baimurzin.itlabel.core.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotEmpty;
import java.io.Serializable;

/**
 * Contains public information
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserAccountDTO implements Serializable {
    private static final long serialVersionUID = -5796134399691582320L;

    private Long id;

    @NotEmpty
    private String email;

    private String avatar;

    private String name;

}
