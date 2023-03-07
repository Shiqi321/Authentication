package com.authentication.Handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;

import java.lang.reflect.Method;

public class CustomisedAsyncExceptionHandler implements AsyncUncaughtExceptionHandler {
    private final Logger logger = LoggerFactory.getLogger(CustomisedAsyncExceptionHandler.class);
    @Override
    public void handleUncaughtException(Throwable throwable, Method method, Object... objects) {
        logger.error("Method name - " + method.getName(), throwable);
        for (Object param : objects) {
            logger.error("Parameter value - " + param);
        }
    }
}
