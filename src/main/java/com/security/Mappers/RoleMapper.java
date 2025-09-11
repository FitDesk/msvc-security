package com.security.Mappers;

import com.security.DTOs.RoleDTO;
import com.security.Entity.RoleEntity;
import com.security.config.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(config = MapStructConfig.class)
public interface RoleMapper {
    RoleDTO toDTO(RoleEntity roleEntity);

    RoleEntity toEntity(RoleDTO roleDTO);
}
