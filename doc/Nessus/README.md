# Nessus CSV自动翻译

使用[Nessus官方中文漏洞库](https://zh-cn.tenable.com/plugins)，将Nessus导出CSV的部分英文描述字段（``Name``、``Synopsis``、``Description``、``Solution``）翻译成中文。翻译时仅采用``Plugin ID``匹配，并修改原始CSV的对应字段（不存在时则新建）。

## 使用方式

``` 
usage: Nessus [-h] path [path ...]

positional arguments:
  path          file path or dir path

optional arguments:
  -h, --help    show this help message and exit
```

- 可以打开一个或多个csv文件。如果使用exe，则可以直接把文件拖到exe上打开。
- 转换输出时，使用原始文件名增加后缀*_converted.csv。
- 转换时优先使用本地数据库``vulns.sqlite3``，之后使用官方中文漏洞库的信息，之后使用服务端漏洞库。
- 未联网时，仅可使用本地数据库翻译，并跳过所有未命中缓存的``Plugin ID``。
- 在stdout输出INFO级别日志，在程序同目录下converter.log输出DEBUG级别日志。

## 服务端MySQL漏洞库

``user``: ``nessus``

``password``: ``rcE7tEIgY3xpgsAIwnIibDzjBIwvvkn4``

``host``: ``node-ali.chenqlz.top``

