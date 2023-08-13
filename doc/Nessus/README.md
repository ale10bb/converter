# Nessus CSV 自动翻译

使用[Nessus 官方中文漏洞库](https://zh-cn.tenable.com/plugins)，将 Nessus 导出 CSV 的部分英文描述字段（`Name`、`Synopsis`、`Description`、`Solution`）翻译成中文。翻译时仅采用`Plugin ID`匹配，并修改原始 CSV 的对应字段（不存在时则新建）。

## 使用方式

```
usage: Nessus [-h] path [path ...]

positional arguments:
  path          file path or dir path

optional arguments:
  -h, --help    show this help message and exit
```

- 可以打开一个或多个 csv 文件。如果使用 exe，则可以直接把文件拖到 exe 上打开。
- 转换输出时，使用原始文件名增加后缀\*\_converted.csv。
- 转换时优先使用本地数据库`vulns.sqlite3`，之后使用官方中文漏洞库的信息。
- 未联网时，仅可使用本地数据库翻译，并跳过所有未命中缓存的`Plugin ID`。
- 在 stdout 输出 INFO 级别日志，在程序同目录下 converter.log 输出 DEBUG 级别日志。
