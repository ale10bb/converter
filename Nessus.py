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
from tqdm import tqdm

import utils

if __name__ == "__main__":
    logger = logging.getLogger("Nessus")
    # argparse：传入path
    parser = argparse.ArgumentParser(
        prog="Nessus", description="读取Nessus的CSV文件，将描述文字翻译成中文，转换结果分别保存至每个原始文件的同目录下。"
    )
    parser.add_argument("path", nargs="+", help="file path or dir path")
    args = parser.parse_args()
    logger.info("共输入 %s 个文件/文件夹，处理中", len(args.path))
    target = utils.walk(args.path, [".csv"])

    # ====检查数据库是否有效====
    db = os.path.join(os.path.dirname(sys.argv[0]), "vulns.sqlite3")
    cnx = None
    try:
        assert os.path.exists(db)
        cnx = sqlite3.connect(db)
        cursor = cnx.cursor()
        cursor.execute(
            """
            SELECT plugin_id, source, script_name, synopsis, description, solution 
            FROM zhcn 
            LIMIT 1
        """
        )
        cnx.close()
    except Exception as err:
        logger.info("initializing database")
        if cnx:
            cnx.close()
        if os.path.exists(db):
            os.remove(db)
        cnx = sqlite3.connect(db)
        cursor = cnx.cursor()
        cursor.execute(
            """
            CREATE TABLE zhcn (
                plugin_id INTEGER PRIMARY KEY NOT NULL,
                source INTEGER NOT NULL,
                script_name TEXT,
                synopsis TEXT,
                description TEXT,
                solution TEXT
            )
        """
        )
        cnx.commit()
        cnx.close()

    # ====处理文件====
    cnx = sqlite3.connect(db)
    cursor = cnx.cursor()
    session = requests.session()
    for item in target:
        converted_item = os.path.splitext(item)[0] + "_converted.csv"
        try:
            logger.info('当前文件: "%s', item)
            # 微软默认使用UTF-8-BOM的格式读写CSV
            with open(item, encoding="utf-8-sig") as src_file, open(
                converted_item, "w", encoding="utf-8-sig"
            ) as dst_file:
                reader = csv.DictReader(
                    src_file,
                    quoting=csv.QUOTE_ALL,
                )
                writer = csv.DictWriter(
                    dst_file,
                    fieldnames=reader.fieldnames,
                    quoting=csv.QUOTE_ALL,
                )
                writer.writeheader()
                for row in tqdm(reader, desc="row", unit=""):
                    try:
                        # 对于没有Plugin ID列，或Plugin ID不为数字的异常情况，直接跳过该行
                        plugin_id = int(row["Plugin ID"])

                        # 首先从本地sqlite读取
                        cursor.execute(
                            """
                            SELECT plugin_id, source, script_name, synopsis, description, solution 
                            FROM zhcn 
                            WHERE `plugin_id` = ?
                        """,
                            (plugin_id,),
                        )
                        sqlite_row = cursor.fetchone()
                        if sqlite_row:
                            row["Name"] = sqlite_row[2]
                            row["Synopsis"] = sqlite_row[3]
                            row["Description"] = sqlite_row[4]
                            row["Solution"] = sqlite_row[5]
                            continue

                        # 从官方中文站读取，读取到后插入数据库
                        logger.info("fetching %s from tenable", plugin_id)
                        url = f"https://zh-cn.tenable.com/plugins/nessus/{plugin_id}"
                        r = session.get(url, allow_redirects=False)
                        if not r.status_code == 200:
                            raise ValueError(f"No results for {plugin_id}")
                        data = (
                            BeautifulSoup(r.text, features="lxml")
                            .body.find("script", id="__NEXT_DATA__")
                            .string
                        )
                        prop_plugin = json.loads(data)["props"]["pageProps"]["plugin"]
                        row["Name"] = prop_plugin.get("script_name", "")
                        logger.info("name: %s", row["Name"])
                        row["Synopsis"] = prop_plugin.get("synopsis", "")
                        row["Description"] = prop_plugin.get("description", "")
                        row["Solution"] = prop_plugin.get("solution", "")
                        cursor.execute(
                            "INSERT INTO zhcn VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                plugin_id,
                                0,
                                prop_plugin.get("script_name", ""),
                                prop_plugin.get("synopsis", ""),
                                prop_plugin.get("description", ""),
                                prop_plugin.get("solution", ""),
                            ),
                        )
                        cnx.commit()
                        logger.debug("saved %s", plugin_id)
                    except Exception as err:
                        logger.warning("error: %s", err)
                    finally:
                        writer.writerow(row)

            logger.info('处理完成: "%s"', converted_item)
        except Exception as err:
            logger.warning('处理失败: "%s"', err)

    cnx.close()
    logger.info("处理结束")
    os.system("pause")
