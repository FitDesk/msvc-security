package com.security.mappers;

import com.security.dtos.autorization.UserDTO;
import com.security.entity.UserEntity;
import com.security.config.MapStructConfig;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(config = MapStructConfig.class, uses = {RoleMapper.class})
public interface UserMapper {

    @Mapping(target = "roles", source = "roles")
    UserDTO toDTO(UserEntity userEntity);

    @Mapping(target = "password", ignore = true)
    @Mapping(target = "accountNonExpired", ignore = true)
    @Mapping(target = "accountNonLocked", ignore = true)
    @Mapping(target = "credentialsNonExpired", ignore = true)
    UserEntity toEntity(UserDTO userDTO);

}
