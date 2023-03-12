package com.authentication.Model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;



@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResultData {

    private static final int SUCCESS_CODE = 200;
    private int code;
    private Object data;

    public static ResultData success()
    {
        ResultData r = new ResultData();
        r.setCode(SUCCESS_CODE);
        return r;
    }

    public static ResultData success(Object data)
    {
        ResultData r = new ResultData();
        r.setCode(SUCCESS_CODE);
        r.setData(data);
        return r;
    }



    public static ResultData error(Error error)
    {
        return error(error.getCode());
    }



    public static ResultData error(int code)
    {
        ResultData r = new ResultData();
        r.setCode(code);
        return r;
    }

}
