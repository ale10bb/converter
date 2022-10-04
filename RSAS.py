# -*- coding: UTF-8 -*-
import os
import logging
import argparse
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup

import utils

if __name__ == '__main__':
    logger = logging.getLogger('RSAS')
    # argparse：只需传入path，无其他开关
    parser = argparse.ArgumentParser(prog='AppScan', description='读取RSAS的HTML文件，转换成测评能手标准格式，转换结果分别保存至每个原始文件的同目录下。')
    parser.add_argument('path', nargs='+', help='file path or dir path')
    args = parser.parse_args()
    logger.info('共输入 {} 个文件/文件夹，处理中'.format(len(args.path)))
    target = utils.walk(args.path, ['.html', '.htm'])
    for item in target:
        try:
            logger.info('当前文件: "{}"'.format(item))
            srcHTMLRoot = BeautifulSoup(open(item, encoding='utf-8'), features='lxml')
            # html的每一个章节由标题div和内容div(后继)组成。标题div属性：
            # class="report_h report_h1"表示一级标题，id="title0"即1章节
            # class="report_h report_h2"表示二级标题，id="title01"即1.1章节
            # 注意，文件中均为id="title00"。实际html渲染后id会动态变化
            report_h2_headers = srcHTMLRoot.find_all('div', class_='report_h2')
            if not report_h2_headers:
                raise ValueError('Not a RSAS html.')

            # ====扫描基本信息缺省值====
            scan_info = {
                'FILE_ID': 'Converted', 
                'MAKERS': '绿盟科技', 
                'POLICY': 'empty', 
                'SCANTASK': 'empty', 
                'SCANTIME': '1970/1/1 00:00:00', 
                'TOOLNAME': '远程安全评估系统'
            }
            # ====构建字典====
            # 绿盟RSAS的index.html的格式为“漏洞名->受影响IP”，测评能手标准xml格式为“资产->漏洞清单”，因此需进行反转
            vulnDetails = [{}] # 漏洞信息为顺序读取插入，使用列表存储即可。第一个元素留空以匹配html中的序号
            hostVulns = {} # 'IP': [1, 2, 3, ...]

            for report_h2_header in report_h2_headers:
                header_text = report_h2_header.get_text()
                if '任务信息' in header_text:
                    # 1.1章节内容里
                    # 第一个table是网络风险（危险、安全）
                    # 第二个table嵌套两个50%宽度的table，每一行tr存放数据
                    for row in report_h2_header.find_next_sibling('div').find_all('tr', class_=['odd', 'even']):
                        if row.th.get_text() == '任务名称':
                            scan_info['SCANTASK'] = row.td.get_text(strip=True)
                            logger.info('found: 任务名称({})'.format(scan_info['SCANTASK']))
                        elif row.th.get_text() == '漏洞扫描模板':
                            scan_info['POLICY'] = row.td.get_text(strip=True)
                            logger.debug('found: 漏洞扫描模板')
                        elif row.th.get_text() == '系统版本信息':
                            scan_info['TOOLNAME'] += row.td.get_text(strip=True)
                            logger.debug('found: 系统版本信息')
                        elif row.th.get_text() == '时间统计':
                            scan_info['SCANTIME'] = row.td.get_text(strip=True)[3:22]
                            logger.debug('found: 时间统计')
                    logger.debug('scan_info: {}'.format(scan_info))
                elif '漏洞分布' in header_text:
                    # 漏洞信息两tr一组
                    # 第一个tr：class_="vuln_*"行记录漏洞名
                    # 第二个tr(后继)：class_="more hide"行记录漏洞详情
                    for row in report_h2_header.find_next_sibling('div').table.tbody('tr', class_=re.compile('vuln_')):
                        tds = row('td')
                        vulnIndex = int(tds[0].get_text())
                        vulnDetail = {
                            '漏洞名称': tds[1].span.get_text(strip=True),
                            '详细描述': '无',
                            '解决办法': '无',
                            '威胁分值': 0,
                            'CVE编号': '无',
                            'CNNVD编号': '无',
                        }
                        logger.debug('vuln: {}. {}'.format(vulnIndex, vulnDetail['漏洞名称']))
                        for row2 in row.find_next_sibling('tr').td.table('tr'):
                            row2_text = row2.th.get_text(strip=True)
                            if row2_text == '受影响主机':
                                for host in row2.td.get_text().split(';&nbsp'):
                                    stripped_host = host.strip()
                                    if not stripped_host or stripped_host == '点击查看详情':
                                        continue
                                    logger.debug('host: {}'.format(stripped_host))
                                    hostVulns.setdefault(stripped_host, [])
                                    hostVulns[stripped_host].append(vulnIndex)
                            elif row2_text == '详细描述':
                                vulnDetail['详细描述'] = row2.td.get_text()
                            elif row2_text == '解决办法':
                                vulnDetail['解决办法'] = row2.td.get_text()
                            elif row2_text == '威胁分值':
                                vulnDetail['威胁分值'] = float(row2.td.get_text())
                            elif row2_text == 'CVE编号':
                                vulnDetail['CVE编号'] = row2.td.get_text()
                            elif row2_text == 'CNNVD编号':
                                vulnDetail['CNNVD编号'] = row2.td.get_text()
                        logger.debug('vulnDetail: {}'.format(vulnDetail))
                        vulnDetails.append(vulnDetail)
            logger.info('vulns: {}'.format(len(vulnDetails)))

            # ====生成xml结构====
            newRoot = ET.Element('REPORT')
            ET.SubElement(newRoot, 'SCANINFO', scan_info)
            for host in hostVulns.keys():
                newDataRoot = ET.SubElement(newRoot, 'SCANDATA', {'TYPE': 'OS'})
                newHostRoot = ET.SubElement(newDataRoot, 'HOST', {'IP': host})
                newHostDataRoot = ET.SubElement(newHostRoot, 'DATA')
                for vulnIndex in hostVulns[host]:
                    vulRoot = ET.SubElement(newHostDataRoot, 'VULNERABLITY')
                    ET.SubElement(vulRoot, 'NAME').text = vulnDetails[vulnIndex]['漏洞名称']
                    ET.SubElement(vulRoot, 'NO', {
                        'CNVD': vulnDetails[vulnIndex]['CNNVD编号'],
                        'CVE': vulnDetails[vulnIndex]['CVE编号'],
                        'MS': '无', 
                        'OTHER': '无'
                    })
                    ET.SubElement(vulRoot, 'VULTYPE').text = '脆弱性问题'
                    #转换风险
                    if 0 < vulnDetails[vulnIndex]['威胁分值'] <= 1:
                        risk = '信息'
                    if 1 < vulnDetails[vulnIndex]['威胁分值'] <= 4:
                        risk = '低危'
                    if 4 < vulnDetails[vulnIndex]['威胁分值'] <= 7:
                        risk = '中危'
                    if 7 < vulnDetails[vulnIndex]['威胁分值'] <= 10:
                        risk = '高危'
                    ET.SubElement(vulRoot, 'RISK').text = risk
                    ET.SubElement(vulRoot, 'SYNOPSIS').text = vulnDetails[vulnIndex]['详细描述']
                    ET.SubElement(vulRoot, 'DESCRIPTION').text = vulnDetails[vulnIndex]['详细描述']
                    ET.SubElement(vulRoot, 'SOLUTION').text = vulnDetails[vulnIndex]['解决办法']
                    ET.SubElement(vulRoot, 'VALIDATE')
                    ET.SubElement(vulRoot, 'REFERENCE')
                    ET.SubElement(vulRoot, 'DETAILS')

            # ====写入文件====
            newTree = ET.ElementTree(newRoot)
            newTree.write(os.path.splitext(item)[0] + '_converted.xml', encoding='utf-8')
            logger.info('处理完成: {}'.format(os.path.splitext(item)[0] + '_converted.xml'))
        except Exception as err:
            logger.warning('处理失败: {}'.format(err), exc_info=True)

    logger.info('处理结束')
    os.system('pause')
