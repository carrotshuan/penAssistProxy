package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import burp.IRequestInfo;
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

//        IHttpService iHttpService = messageInfo.getHttpService();

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

                    String body_content = "@@@@@@@@@@@@@@\n"+ request + "\n@@@@@@@@@@@@@@";    // 一个\n对应burp中的=&符号
                    burpStdout.println("重新组装的数据部分：\n"+body_content);
                    body_content = body_content.replace("\n","$$$$");
                    burpStdout.println("重新组装数据编码：\n"+body_content);

                    // todo:替换等号为重新组装后的编码数据发送
                    IParameter body_param = helpers.buildParameter("","",IParameter.PARAM_BODY);
                    byte[] get_req_arr = helpers.buildHttpRequest(get_url);
                    get_req_arr = helpers.addParameter(get_req_arr,body_param);
                    byte[] post_req_arr = helpers.toggleRequestMethod(get_req_arr); // 将GET及数据部分转换为POST及数据部分

                    String toModifyRequest = helpers.bytesToString(post_req_arr);
                    burpStdout.println("修改headers前：" + toModifyRequest);
                    burpStdout.println("修改前显示结束.");

                    String modifiedRequest = modifyRequest(toModifyRequest);

                    burpStdout.println("修改headers后：" + modifiedRequest);
                    burpStdout.println("修改后显示结束.");

                    byte[] selfResponse = callbacks.makeHttpRequest("127.0.0.1", 9090, false, helpers.stringToBytes(modifiedRequest));
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

    // 去掉因为Burp转换导致的不兼容问题，主要是Content-Type字段，和从get到post部分数据换行符的变化
    private String modifyRequest(String request){

        String modifiedRequest = "";
        String[] lines = request.split("\n");

        for(int i = 0;i<lines.length;i++){
            if (lines[i].contains("Content-Type"))
                modifiedRequest += "Content-Type: text/plain;charset=UTF-8\n";
            else if (lines[i].contains("@@@@@@@@@@@@@@"))   // 内容部分
                modifiedRequest += lines[i].replaceAll("=&","\n").replace("=","");  // 更改Burp自动转换的后的错误
            else
                modifiedRequest += lines[i] + "\n";
        }

        return modifiedRequest;
    }
}
