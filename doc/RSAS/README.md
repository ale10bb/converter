# XML转换 - RSAS to cpnsStandard

读取绿盟科技"远程安全评估系统"的HTML文件，转换成测评能手标准格式。

## 支持文件格式

绿盟科技"远程安全评估系统"V6.0导出的安全评估报告（index.html）。

## 使用说明

``` 
usage: RSAS [-h] path [path ...]

positional arguments:
  path        file path or dir path

optional arguments:
  -h, --help  show this help message and exit
```

- 可以打开一个或多个HTML文件。如果使用exe，则可以直接把文件拖到exe上打开。
- 转换输出时，使用原始文件名增加后缀*_converted.xml。
- 在stdout输出INFO级别日志，在程序同目录下converter.log输出DEBUG级别日志。