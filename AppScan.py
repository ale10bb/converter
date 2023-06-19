# -*- coding: UTF-8 -*-
import os
import logging
import argparse
import xml.etree.ElementTree as ET
import re

import utils

if __name__ == "__main__":
    logger = logging.getLogger("AppScan")
    # argparse：只需传入path，无其他开关
    parser = argparse.ArgumentParser(
        prog="AppScan", description="读取AppScan的XML文件，转换成测评能手标准格式，转换结果分别保存至每个原始文件的同目录下。"
    )
    parser.add_argument("path", nargs="+", help="file path or dir path")
    args = parser.parse_args()
    logger.info("共输入 {} 个文件/文件夹，处理中".format(len(args.path)))
    target = utils.walk(args.path, [".xml"])
    for item in target:
        try:
            logger.info('当前文件: "{}"'.format(item))
            srcXMLRoot = ET.ElementTree().parse(item)
            if (
                srcXMLRoot.tag != "xml-report"
                or srcXMLRoot.get("name") != "AppScan Report"
            ):
                raise ValueError("Not an AppScan XML.")
            xmlExportVersion = srcXMLRoot.get("xmlExportVersion")
            logger.debug("xmlExportVersion: {}".format(xmlExportVersion))
            newRoot = ET.Element("REPORT")

            # ====读写扫描基本信息====
            # bugfix: 10.0.5以上的版本存在bug，无法导出扫描时间
            try:
                timeResult = srcXMLRoot.find(
                    "./scan-information/scan-date-and-time"
                ).text
                assert timeResult
                logger.debug("scan-date-and-time: {}".format(timeResult))
            except:
                logger.warning('未读取到 "./scan-information/scan-date-and-time"')
                timeResult = "1970/1/1 00:00:00"
            try:
                taskResult = srcXMLRoot.find("./scan-information/scan-name").text
                assert taskResult
                logger.debug("scan-name: {}".format(taskResult))
            except:
                logger.warning('未读取到 "./scan-information/scan-name"')
                taskResult = "null"
            ET.SubElement(
                newRoot,
                "SCANINFO",
                {
                    "FILE_ID": "Converted",
                    "MAKERS": "HCL",
                    "POLICY": "完全扫描",
                    "SCANTASK": taskResult,
                    "SCANTIME": timeResult,
                    "TOOLNAME": "AppScan Standard",
                },
            )

            # ====读取起始url，用作扫描资产 ====
            # 并在此生成host外部格式
            assetUrl = srcXMLRoot.find("./scan-configuration/starting-url").text
            logger.debug("starting-url: {}".format(assetUrl))
            newDataRoot = ET.SubElement(newRoot, "SCANDATA", {"TYPE": "WEB"})
            newHostRoot = ET.SubElement(newDataRoot, "HOST", {"WEB": assetUrl})
            ET.SubElement(newHostRoot, "WEBSERVERBANNER")
            ET.SubElement(newHostRoot, "SERVERVERSION")
            ET.SubElement(newHostRoot, "TECHNOLOGIES")
            newHostDataRoot = ET.SubElement(newHostRoot, "DATA")

            # ====构建字典====
            # 漏洞整改建议
            fixRecommendationGroup = {}
            for fixRecommendationNode in srcXMLRoot.find("./fix-recommendation-group"):
                # 该版本xml中，fix-recommendation可能会针对asp/j2ee/php提出不同的建议，但一定有general
                # 为了省力，仅读取general的整改建议
                # 每个node下，还需要进入<general><fixRecommendation type="General">两层标签，之后读取text、去除None、拼接
                fixRecommendationGroup[fixRecommendationNode.get("id")] = "\n".join(
                    filter(
                        None,
                        [
                            fixRecommendationContent.text
                            for fixRecommendationContent in fixRecommendationNode.findall(
                                "./general/fixRecommendation/*"
                            )
                        ],
                    )
                )
            logger.debug(
                "fix-recommendation-group: {}".format(
                    list(fixRecommendationGroup.keys())
                )
            )
            # 漏洞种类
            threatClassGroup = {}
            for threatClassNode in srcXMLRoot.find("./threat-class-group"):
                threatClassGroup[threatClassNode.get("id")] = threatClassNode.text
            logger.debug("threat-class-group: {}".format(list(threatClassGroup.keys())))
            # 漏洞简述
            securityRiskGroup = {}
            for securityRiskNode in srcXMLRoot.find("./security-risk-group"):
                securityRiskGroup[securityRiskNode.get("id")] = securityRiskNode.text
            logger.debug(
                "security-risk-group: {}".format(list(securityRiskGroup.keys()))
            )
            # 漏洞涉及url
            urlGroup = {}
            for urlNode in srcXMLRoot.find("./url-group"):
                urlGroup[urlNode.get("id")] = urlNode.find("./name").text
            logger.debug("url-group: {}".format(list(urlGroup.keys())))
            # 实体参数
            entityGroup = {}
            for entityNode in srcXMLRoot.find("./entity-group"):
                # issue(200819-1)某些xml中，entity的<name>标签没有内容，导致转换报错
                # bugfix：增加空值判断
                # 顺带增加包含标签情况的判断，如果含标签符号(<)也不读取
                if (
                    entityNode.find("name").text
                    and "<" not in entityNode.find("name").text
                ):
                    entityGroup[entityNode.get("id")] = entityNode.find("name").text
                else:
                    entityGroup[entityNode.get("id")] = ""
            logger.debug("entity-group: {}".format(list(entityGroup.keys())))
            # 漏洞详情
            # issues = {issueType: [{'URL': xxx, 'PARAMETER': xxx, 'REQUEST': xxx, 'RESPONSE': xxx}, ..]}
            issues = {}
            # issue-group的每个item对应单个实体的单个漏洞
            # bugfix: 10.0.5以上的版本存在bug，可能存在空<item>标签
            for issueNode in srcXMLRoot.findall("./issue-group/item[@id]"):
                issueType = issueNode.find("./issue-type/ref").text
                if not issues.__contains__(issueType):
                    issues[issueType] = []
                # <test-http-traffic>下记录了测试的请求响应，去除appscan的标记符后，采用'HTTP/'作为标识分割请求和响应
                HTTPTrafficTexts = re.sub(
                    "--begin_mark_tag--|--end_mark_tag--|--begin_highlight_tag--|--end_highlight_tag--",
                    "",
                    issueNode.find("./variant-group/item/test-http-traffic").text,
                ).split("\nHTTP/", 1)
                # bugfix:非常规的HTTP请求响应，导致未分割时，手动增加一个空元素
                if len(HTTPTrafficTexts) == 1:
                    HTTPTrafficTexts.append("Unknown")
                else:
                    HTTPTrafficTexts[1] = "HTTP/" + HTTPTrafficTexts[1]
                issues[issueType].append(
                    {
                        "URL": urlGroup[issueNode.find("./url/ref").text]
                        + "->"
                        + entityGroup[issueNode.find("./entity/ref").text],
                        "PARAMETER": entityGroup[issueNode.find("./entity/ref").text],
                        "REQUEST": HTTPTrafficTexts[0],
                        "RESPONSE": HTTPTrafficTexts[1],
                    }
                )
            logger.debug("issue-group: {}".format(list(issues.keys())))

            # ====定位到issue-type-group，读取漏洞类别====
            # 并在此生成新Data
            logger.debug("-- Begin Issue Type --")
            # bugfix: 10.0.5以上的版本存在bug，可能存在空<item>标签
            for issueTypeNode in srcXMLRoot.findall("./issue-type-group/item[@id]"):
                vulRoot = ET.SubElement(newHostDataRoot, "VULNERABLITY")
                issueName = issueTypeNode.find("./name").text
                ET.SubElement(vulRoot, "NAME").text = issueName
                ET.SubElement(
                    vulRoot,
                    "NO",
                    {"CNVD": "NONE", "CVE": "NONE", "MS": "NONE", "OTHER": "NONE"},
                )
                ET.SubElement(vulRoot, "VULTYPE").text = threatClassGroup[
                    issueTypeNode.find("./threat-class/ref").text
                ]
                # 转换风险
                if issueTypeNode.get("maxIssueSeverity") == "0":
                    risk = "信息"
                if issueTypeNode.get("maxIssueSeverity") == "1":
                    risk = "低危"
                if issueTypeNode.get("maxIssueSeverity") == "2":
                    risk = "中危"
                if issueTypeNode.get("maxIssueSeverity") == "3":
                    risk = "高危"
                ET.SubElement(vulRoot, "RISK").text = risk
                # bugfix: 10.0.5以上的版本存在bug，部分新加入漏洞库的问题没有汉化，
                #         对应的security-risks和fix-recommendation可能为空，因此增加空值判断
                try:
                    key = issueTypeNode.find("./security-risks/ref").text
                    assert key
                    ET.SubElement(vulRoot, "SYNOPSIS").text = securityRiskGroup[key]
                    ET.SubElement(vulRoot, "DESCRIPTION").text = securityRiskGroup[key]
                except:
                    logger.warning('"{}" 未读取到 "./security-risks/ref"'.format(issueName))
                    ET.SubElement(vulRoot, "SYNOPSIS").text = "暂无"
                    ET.SubElement(vulRoot, "DESCRIPTION").text = "暂无"
                try:
                    key = issueTypeNode.find("./fix-recommendation/ref").text
                    assert key
                    ET.SubElement(vulRoot, "SOLUTION").text = fixRecommendationGroup[
                        key
                    ]
                except:
                    logger.warning(
                        '"{}" 未读取到 "./fix-recommendation/ref"'.format(issueName)
                    )
                    ET.SubElement(vulRoot, "SOLUTION").text = "暂无"
                ET.SubElement(vulRoot, "VALIDATE")
                ET.SubElement(vulRoot, "REFERENCE")
                # <DETAIL>中的四个元素，直接从issue字典中读取
                vulDetailsRoot = ET.SubElement(vulRoot, "DETAILS")
                # bugfix: 10.0.5以上的版本存在bug，部分新加入漏洞库的问题没有汉化，
                #         对应的issue可能不出现在漏洞字典，因此增加空值判断
                try:
                    assert issues[issueTypeNode.get("id")]
                    for issue in issues[issueTypeNode.get("id")]:
                        URLRoot = ET.SubElement(
                            vulDetailsRoot, "URL", {"URL": issue["URL"]}
                        )
                        ET.SubElement(URLRoot, "TYPE")
                        ET.SubElement(URLRoot, "PARAMETER").text = issue["PARAMETER"]
                        ET.SubElement(URLRoot, "REQUEST").text = issue["REQUEST"]
                        ET.SubElement(URLRoot, "RESPONSE").text = issue["RESPONSE"]
                    logger.debug(
                        "【{}】 has {} entities".format(
                            issueName, len(issues[issueTypeNode.get("id")])
                        )
                    )
                except:
                    logger.warning('issues 缺少 "{}"，忽略'.format(issueTypeNode.get("id")))
                    URLRoot = ET.SubElement(vulDetailsRoot, "URL")
            logger.debug("-- End Issue Type --")

            # ====写入文件====
            newTree = ET.ElementTree(newRoot)
            newTree.write(
                os.path.splitext(item)[0] + "_converted.xml", encoding="utf-8"
            )
            logger.info("处理完成: {}".format(os.path.splitext(item)[0] + "_converted.xml"))
        except Exception as err:
            logger.warning("处理失败: {}".format(err))

    logger.info("处理结束")
    os.system("pause")
