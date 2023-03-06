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
    private static final int ERROR_CODE = 400;
    private static final String SUCCESS_MSG = "success";
    private static final String ERROR_MSG = "ERROR";


    private int code;
    private Object data;
    private String message;

    public static ResultData success()
    {
        ResultData r = new ResultData();
        r.setCode(SUCCESS_CODE);
        r.setMessage(SUCCESS_MSG);
        return r;
    }

    public static ResultData success(Object data)
    {
        ResultData r = new ResultData();
        r.setCode(SUCCESS_CODE);
        r.setMessage(SUCCESS_MSG);
        r.setData(data);
        return r;
    }

    public static ResultData success(String msg)
    {
        ResultData r = new ResultData();
        r.setCode(SUCCESS_CODE);
        r.setMessage(msg);
        return r;
    }



    public static ResultData error(Error error, String tip)
    {
        if (tip != null && StringUtils.isNotBlank(tip))
        {
            tip = "，" + tip;
        }
        else
        {
            tip = "";
        }
        return error(error.getCode(), error.getErrMsg() + tip);
    }

    public static ResultData error(Error error)
    {
        return error(error, null);
    }


    public static ResultData error(int code, String msg)
    {
        ResultData r = new ResultData();
        r.setCode(code);
        r.setMessage(msg);
        return r;
    }


}
