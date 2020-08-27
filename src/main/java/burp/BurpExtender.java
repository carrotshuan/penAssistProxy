package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import burp.IRequestInfo;
public class BurpExtender implements IBurpExtender,IHttpListener {

    private burp.IBurpExtenderCallbacks callbacks;
    private PrintWriter burpStdout;

    // Burp发送过来的请求使用该字符串进行包装
    private final String headerAndTailSplitCharacter = "@HEADTAILCHAR@";
    // Burp每一行使用该字符作为起始，防止一个换行符被替换过滤的情况
    private final String middleSplitCharacter = "@MIDDLECHAR@";
    // Burp的换行符使用该字符替换
    private final String burpSplitCharacter = "=&";
    // 将Burp发送数据部分中，使用的默认换行符转换为该字符串，接收后再转换回去
    private final String burpEncodeSplitChar = "@BURPENCODESPLITCHAR@";
    // 等号会被Burp过滤掉，发送前进行转码
    private final String burpEncodeEqualChar = "@BURPEQUALCHAR@";
    // 与号会被Burp作为换行符，发送前进行转码
    private final String burpEncodeAndChar = "@BURPANDCHAR@";

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
            burpStdout.println("原始请求：\n" + request);

            if (!sendtohost.contains("127.0.0.1")){
                burpStdout.println("当前请求Host中不包含字符串：127.0.0.1，将本请求重新修改转发：");
                try {
                    URL get_url = new URL("http://127.0.0.1/recUrl");   // 只能设置get请求

                    /**
                     *
                     * 在给BURP进行转发前，先将部分特殊字符进行编码，防止Burp在处理时发生错误
                     * */
                    // 整个请求使用headerAndTailSplitCharacter值作为开头和结尾结束符
                    String body_content = headerAndTailSplitCharacter+"\n"+ request + "\n"+headerAndTailSplitCharacter;
                    // 不把换行符编码，Burp发送时就会过滤掉中间的换行符
                    body_content = body_content.replace("\n",middleSplitCharacter);
                    // 默认将换行符当做一个空赋值""=""和GET中的数据连接符，即=&。如果发送的请求中，数据包含=&，后续可尝试更改
                    // 则burp在使用POST发送时会报错，先转换为其他字符，接收后再进行转换
                    body_content = body_content.replace(burpSplitCharacter, burpEncodeSplitChar);
                    // 替换数据中的等号部分，否则Burp发送时与原数据不一致
                    body_content = body_content.replace("=",burpEncodeEqualChar);
                    // 替换编码前的&，否则Burp会作为换行符，导致解析问题
                    body_content = body_content.replace("&", burpEncodeAndChar);

                    burpStdout.println("重新组装数据和编码数据，替换换行符、=&、=和&字符：\n"+middleSplitCharacter+"\n"+body_content);

                    IParameter body_param = helpers.buildParameter(body_content,"",IParameter.PARAM_BODY);
                    byte[] get_req_arr = helpers.buildHttpRequest(get_url);
                    get_req_arr = helpers.addParameter(get_req_arr,body_param);
                    byte[] post_req_arr = helpers.toggleRequestMethod(get_req_arr); // 将GET及数据部分转换为POST及数据部分

                    String toModifyRequest = helpers.bytesToString(post_req_arr);
                    burpStdout.println("数据部分编码后，修改Header内容前：\n" + toModifyRequest);
                    burpStdout.println("修改Header前显示结束.\n");

                    String modifiedRequest = modifyRequest(toModifyRequest);

                    burpStdout.println("修改Header后：\n" + modifiedRequest);
                    burpStdout.println("修改Header后显示结束.开始发送到服务中心...\n");

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
            if (lines[i].contains("Content-Type") && !lines[i].contains(headerAndTailSplitCharacter))   // 最后一行包含Content-Type，只修改header部分
                modifiedRequest += "Content-Type: */*\n";
//            else if (lines[i].contains("@@@@@@@@@@@@@@"))   // 内容部分
//                modifiedRequest += lines[i].replaceAll("=&","\n").replace("=","");  // 更改后，Burp无法识别数据格式，会报错
            else
                modifiedRequest += lines[i] + "\n";
        }

        return modifiedRequest;
    }
}
