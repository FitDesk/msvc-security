package com.security.dtos.roles;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Map;

@Data
@AllArgsConstructor
public class RoleStatisticsDto {
    private long totalUsers;
    private long activeUsers;
    private long inactiveUsers;
    private long suspendedUsers;
    private Map<String, Long> roleCounts;
}
