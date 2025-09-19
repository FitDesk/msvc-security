package com.security.mappers;

import com.security.dtos.RoleDTO;
import com.security.entity.RoleEntity;
import com.security.config.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface RoleMapper {
    RoleDTO toDTO(RoleEntity roleEntity);

    RoleEntity toEntity(RoleDTO roleDTO);
}
