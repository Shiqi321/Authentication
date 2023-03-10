package com.authentication.Controller;


import com.authentication.Model.ResultData;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class pubKeyController {

    @Value("${puk.access_token.bucket}")
    private String pubAccessBucketName;
    @Value("${puk.access_token.key}")
    private String pubAccessKeyName;

    @Value("${puk.refresh_token.bucket}")
    private String pubRefreshBucketName;
    @Value("${puk.refresh_token.key}")
    private String pubRefreshKeyName;

    @GetMapping("/requirePub")
    public ResultData requirePub(@RequestParam("type") String type) {
        String uri = "";
        switch (type) {
            case "access_token":
                uri = pubAccessBucketName + "/" + pubAccessKeyName;
                break;
            case "refresh_token":
                uri = pubRefreshBucketName + "/" + pubRefreshKeyName;
                break;
        }
        return ResultData.success(uri);
    }
}
