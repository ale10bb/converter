# -*- coding: UTF-8 -*-
import os
import sys
import logging
import argparse
import sqlite3
import csv
import requests
from bs4 import BeautifulSoup
import json
import mysql.connector

import utils

if __name__ == '__main__':
    logger = logging.getLogger('Nessus')
    # argparse：传入path
    parser = argparse.ArgumentParser(prog='Nessus', description='读取Nessus的CSV文件，将描述文字翻译成中文，转换结果分别保存至每个原始文件的同目录下。')
    parser.add_argument('path', nargs='+', help='file path or dir path')
    args = parser.parse_args()
    logger.info('共输入 {} 个文件/文件夹，处理中'.format(len(args.path)))
    target = utils.walk(args.path, ['.csv'])

    # ====检查数据库是否有效====
    db = os.path.join(os.path.dirname(sys.argv[0]), 'vulns.sqlite3')
    try:
        cnx = sqlite3.connect(db)
        cursor = cnx.cursor()
        cursor.execute('''
            SELECT plugin_id, source, script_name, synopsis, description, solution 
            FROM zhcn 
            LIMIT 1
        ''')
        logger.debug('fetch result: {}'.format(cursor.fetchone()))
        cnx.close()
    except Exception as err:
        logger.warning('fetch err: {}'.format(err))
        cnx.close()
        if os.path.exists(db):
            os.remove(db)
        cnx = sqlite3.connect(db)
        cursor = cnx.cursor()
        cursor.execute('''
            CREATE TABLE zhcn (
                plugin_id INTEGER PRIMARY KEY NOT NULL,
                source INTEGER NOT NULL,
                script_name TEXT,
                synopsis TEXT,
                description TEXT,
                solution TEXT
            )
        ''')
        cnx.commit()
        cnx.close()

    # ====准备连接并检测连通性====
    cnx = sqlite3.connect(db)
    cursor = cnx.cursor()
    try:
        session = requests.session()
        assert session.head('https://zh-cn.tenable.com/plugins').status_code == 200
        official_enabled = True
    except:
        official_enabled = False
    finally:
        logger.debug('official status: {}'.format(official_enabled))
    try:
        mysql_cnx = mysql.connector.connect(
            user='nessus', 
            password='rcE7tEIgY3xpgsAIwnIibDzjBIwvvkn4', 
            host='node-ali.chenqlz.top', 
            database='nessus'
        )
        mysql_cursor = mysql_cnx.cursor(buffered=True)
        mysql_enabled = True
    except:
        mysql_enabled = False
    finally:
        logger.debug('mysql status: {}'.format(mysql_enabled))
    for item in target:
        try:
            logger.info('当前文件: "{}"'.format(item))
            # 微软默认使用UTF-8-BOM的格式读写CSV
            with open(item, encoding='utf-8-sig') as src_file, open(os.path.splitext(item)[0] + '_converted.csv', 'w', encoding='utf-8-sig') as dst_file:
                reader = csv.DictReader(src_file, quoting=csv.QUOTE_ALL)
                writer = csv.DictWriter(dst_file, fieldnames=reader.fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                for row in reader:
                    try:
                        # 对于没有Plugin ID列，或Plugin ID不为数字的异常情况，直接跳过该行
                        plugin_id = int(row['Plugin ID'])
                        
                        # 首先从本地sqlite读取
                        cursor.execute('''
                            SELECT plugin_id, source, script_name, synopsis, description, solution 
                            FROM zhcn 
                            WHERE `plugin_id` = ?
                        ''', (plugin_id,))
                        sqlite_row = cursor.fetchone()
                        if sqlite_row:
                            logger.debug('{} hit in sqlite'.format(plugin_id))
                            row['Name'] = sqlite_row[2]
                            row['Synopsis'] = sqlite_row[3]
                            row['Description'] = sqlite_row[4]
                            row['Solution'] = sqlite_row[5]
                            continue

                        # 从官方中文站读取，读取到后插入数据库
                        if official_enabled:
                            r = session.get('https://zh-cn.tenable.com/plugins/nessus/{}'.format(plugin_id), allow_redirects=False)
                            if r.status_code == 200:
                                logger.debug('{} hit in official'.format(plugin_id))
                                data = BeautifulSoup(r.text, features='lxml').body.find('script', id='__NEXT_DATA__').string
                                prop_plugin = json.loads(data)['props']['pageProps']['plugin']
                                row['Name'] = prop_plugin.get('script_name', '')
                                row['Synopsis'] = prop_plugin.get('synopsis', '')
                                row['Description'] = prop_plugin.get('description', '')
                                row['Solution'] = prop_plugin.get('solution', '')
                                cursor.execute(
                                    "INSERT INTO zhcn VALUES (?, ?, ?, ?, ?, ?)", (
                                        plugin_id, 
                                        0, 
                                        prop_plugin.get('script_name', ''), 
                                        prop_plugin.get('synopsis', ''), 
                                        prop_plugin.get('description', ''), 
                                        prop_plugin.get('solution', '')
                                    )
                                )
                                cnx.commit()
                                logger.debug('{} inserted'.format(plugin_id))
                                continue
                        
                        # 从在线数据库尝试读取
                        if mysql_enabled:
                            mysql_cursor.execute('''
                                SELECT plugin_id, source, script_name, synopsis, description, solution 
                                FROM zhcn 
                                WHERE `plugin_id` = %s
                            ''', (plugin_id,))
                            mysql_cnx.commit()
                            mysql_row = mysql_cursor.fetchone()
                            if mysql_row:
                                logger.debug('{} hit in mysql'.format(plugin_id))
                                row['Name'] = mysql_row[2]
                                row['Synopsis'] = mysql_row[3]
                                row['Description'] = mysql_row[4]
                                row['Solution'] = mysql_row[5]
                                cursor.execute(
                                    "INSERT INTO zhcn VALUES (?, ?, ?, ?, ?, ?)", (
                                        plugin_id, 
                                        mysql_row[1], 
                                        mysql_row[2], 
                                        mysql_row[3], 
                                        mysql_row[4], 
                                        mysql_row[5]
                                    )
                                )
                                cnx.commit()
                                logger.debug('{} inserted'.format(plugin_id))
                                continue
                        raise ValueError('not hit')
                    except Exception as err:
                        logger.warning('plugin_id ({}) error: {}'.format(plugin_id, err))
                    finally:
                        writer.writerow(row)
            
            logger.info('处理完成: "{}"'.format(os.path.splitext(item)[0] + '_converted.csv'))
        except Exception as err:
            logger.warning('处理失败: "{}"'.format(err))

    mysql_cnx.close()
    logger.info('处理结束')
    os.system('pause')
