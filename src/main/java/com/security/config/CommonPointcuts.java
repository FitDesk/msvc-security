package com.security.config;


import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class CommonPointcuts {
    @Pointcut("execution(* com.security.services.*.*(..))")
    public void greetingLoggerServices(){}

    @Pointcut("execution(* com.security.controllers.*.*(..))")
    public void greetingLoggerControllers(){}
}
