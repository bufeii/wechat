#!/usr/bin/python
# -*- coding: utf-8 -*-
# author:wtc
# document: https://github.com/sbzhu/weworkapi_python/tree/master/callback
"""
    Created on 2021/7/9 15:19
"""
import hashlib
import ierror
import xml.etree.cElementTree as et
from WXBizMsgCrypt3 import WXBizMsgCrypt
from flask import Flask,request
from CheckPy.tcp_port import check_tcp_port_PG
# http://tcandyj.top:8888/sms

app = Flask(__name__)
@app.route('/sms',methods=['GET','POST'])
def sms():
    """
    @return: 消息体签名校验
    """
    sToken = 'dDrgScWRFUe95mYJKmJm20IsS'
    sEncodingAESKey = 'uIBoGlGPWGNejAtxH2k6KbykX9eDEYwEWXZk3RJFlZC'
    sCorpID = 'wwc4cb679fd7911d16'
    wxcpt = WXBizMsgCrypt(sToken, sEncodingAESKey, sCorpID)
    sVerifyMsgSig = request.args.get('msg_signature')
    sVerifyTimeStamp = request.args.get('timestamp')
    sVerifyNonce = request.args.get('nonce')
    sVerifyEchoStr = request.args.get('echostr')
    # 验证url
    if request.method == "GET":
        return_api_status, return_sEchoStr = wxcpt.VerifyURL(sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce, sVerifyEchoStr)
        if return_api_status == 0 :
            return return_sEchoStr
        else:
            print ("ERR: VerifyURL ret: " + str(return_api_status))
            exit()
    # 接口客户端消息，并触发事件
    if request.method == "POST":
        ret, sMsg = wxcpt.DecryptMsg(request.data, sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce)
        xml_tree = et.fromstring(sMsg)
        content = xml_tree.find("Content").text
        if content == "检测端口":
            cmd_result = check_tcp_port_PG()
            print (cmd_result)
        else:
            cmd_result = "执行失败"
        print (cmd_result)
        # 企业微信将触发事件结果返回给客户端
        sRespData = "<xml>" \
                    "<ToUserName><![CDATA[TianCiwang]]></ToUserName>" \
                    "<FromUserName><![CDATA[wwc4cb679fd7911d16]]></FromUserName>" \
                    "<CreateTime>1348831860</CreateTime>" \
                    "<MsgType><![CDATA[text]]></MsgType>" \
                    "<Content><![CDATA[{}]]></Content></xml>".format(cmd_result)
        ret, sEncryptMsg = wxcpt.EncryptMsg(sRespData, sVerifyNonce, sVerifyTimeStamp)
        return sEncryptMsg

if __name__ == '__main__':
    app.debug = True
    app.run(host="0.0.0.0",port=80)

