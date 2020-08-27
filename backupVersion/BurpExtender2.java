package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

public class BurpExtender implements IBurpExtender,IHttpListener {

    private burp.IBurpExtenderCallbacks callbacks;
    private PrintWriter burpStdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("BssReqResLogger");
        callbacks.registerHttpListener(this);   // 将Burp中请求响应的流量监听器注册进来

        burpStdout = new PrintWriter(callbacks.getStdout(),true);

        burpStdout.println("Begin listening...");
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        String sendtohost = "";

        List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
//        burpStdout.println("当前headers:"+headers);
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
//            if (iter.next().contains("Content-Type"))
//                iter.remove();
            String currentHeader = iter.next();
            if (currentHeader.startsWith("Host:"))
                sendtohost = currentHeader.split(":")[1].trim();
            burpStdout.println(currentHeader);
        }

        if (messageIsRequest){
            String request = new String(messageInfo.getRequest());
//            burpStdout.println("原始请求：\n" + request);

            if (!sendtohost.contains("127.0.0.1")){
                burpStdout.println("当前请求Host中不包含字符串：127.0.0.1，将本请求重新修改转发：");
                try {
                    URL get_url = new URL("http://127.0.0.1/recUrl");   // 只能设置get请求

                    IParameter body_param = helpers.buildParameter("","",IParameter.PARAM_BODY);    // 在GET请求后添加参数
                    byte[] get_req_arr = helpers.buildHttpRequest(get_url);
                    get_req_arr = helpers.addParameter(get_req_arr,body_param);
                    byte[] post_req_arr = helpers.toggleRequestMethod(get_req_arr); // 将GET及数据部分转换为POST及数据部分，数据部分会变为一个等号

                    String toModifyRequest = helpers.bytesToString(post_req_arr);
                    burpStdout.println("修改headers前：" + toModifyRequest);
                    burpStdout.println("修改前显示结束.\n");

//                    String modifiedRequest = modifyRequest(toModifyRequest);
//
//                    burpStdout.println("修改headers后：\n" + modifiedRequest);
//                    burpStdout.println("修改后显示结束.开始发送到处理中心...\n");

                    byte[] selfResponse = callbacks.makeHttpRequest("127.0.0.1", 9090, false, helpers.stringToBytes(toModifyRequest));
                    burpStdout.println(helpers.bytesToString(selfResponse));

                }catch (Exception e){
                    e.printStackTrace();
                }
            }
            else {
                burpStdout.println("当前请求包含字符串：127.0.0.1，不对本地请求包进行转发。");
            }
        }
        else{
            String response = new String(messageInfo.getResponse());
            burpStdout.println("响应：\n" + response);

        }
    }

    // 去掉因为Burp转换导致的不兼容问题，主要进行：
    // 1. 修改Content-Type字段，
    // 2. 从get到post部分数据换行符的转换
    // 3. 将POST数据部分进行编码后发送，否则发生问题
    private String modifyRequest(String request){

        String modifiedRequest = "";
        String[] lines = request.split("\n");

        String body_content = "@@@@@@@@@@@@@@\n"+ request + "\n@@@@@@@@@@@@@@"; // 首先增加@@@字符串作为原始内容开头和结束标志
        burpStdout.println("重新组装的数据部分：\n"+body_content);
        body_content = body_content.replace("\n","$$$$");   // 然后进行\n的编码，否则在发送时会发生异常
        burpStdout.println("重新组装数据编码：\n"+body_content);


        for(int i = 0;i<lines.length;i++){
            if (lines[i].contains("Content-Type"))
                modifiedRequest += "Content-Type: text/plain;charset=UTF-8\n";
            else if (lines[i].trim().contains("="))   // 内容部分
                modifiedRequest += lines[i].replace("=",body_content);  // 更改Burp自动转换的后的错误
            else
                modifiedRequest += lines[i] + "\n";
        }

        return modifiedRequest;
    }
}
