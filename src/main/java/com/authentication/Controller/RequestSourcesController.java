package com.authentication.Controller;

import com.authentication.Model.ResultData;
import com.authentication.Service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

@RestController
public class RequestSourcesController {

    private Logger logger = LoggerFactory.getLogger(RequestSourcesController.class);

    @Autowired
    private JwtService jwtService;

    @GetMapping("/requestSources")
    public ResultData requestSources(@RequestHeader("user_id")String userId) {
        return ResultData.success("success");
    }

}
