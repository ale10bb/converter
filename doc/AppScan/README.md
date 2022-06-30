# XML转换 - AppScan to cpnsStandard

读取AppScan的XML文件，转换成测评能手标准格式。

## 支持文件格式

AppScan XML version 2.42 （"文件"-"导出"-"扫描结果为XML"-"针对 ASE 9.0.3.1 以及更新版本"）。

## 转换原则

- 扫描起始URL(starting-url) -> 资产名
- 漏洞类别(issue-type) join threat-class/security-risk/fix-recommendation -> 漏洞名(./SCAN-DATA/HOST/DATA/VULNERABLITY) with 漏洞类别/风险等级/修复建议
- 漏洞详情(issue) join url/entity/test-http-traffic-> 漏洞详情(./SCAN-DATA/HOST/DATA/VULNERABLITY/DETAILS) with URL/参数/请求/响应

## 使用说明

``` 
usage: AppScan [-h] path [path ...]

positional arguments:
  path        file path or dir path

optional arguments:
  -h, --help  show this help message and exit
```

- 可以打开一个或多个XML文件。如果使用exe，则可以直接把文件拖到exe上打开。
- 转换输出时，使用原始文件名增加后缀*_converted.xml。
- 在stdout输出INFO级别日志，在程序同目录下converter.log输出DEBUG级别日志。