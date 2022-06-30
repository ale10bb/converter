# -*- coding: UTF-8 -*-
import os.path
import logging
from walkdir import filtered_walk, file_paths 


def walk(paths:list, exts:list):
    ''' 在{paths}中搜索所有扩展名符合{exts}的文件，并转换成绝对路径。

    Args:
        paths: 文件或目录列表
        exts: 扩展名列表

    Returns:
        list: 文件绝对路径列表
    '''
    logger = logging.getLogger('utils.walk')
    logger.debug('path: {}, exts: {}'.format(paths, exts))
    if type(paths) != list:
        raise TypeError('Not a list: paths.')
    if type(exts) != list:
        raise TypeError('Not a list: exts.')

    target = set()
    for item in paths:
        if os.path.isfile(item) and os.path.splitext(item)[1].lower() in exts:
            target.add(item)
        if os.path.isdir(item):
            target.union(list(file_paths(filtered_walk(item, included_files=['*' + e for e in exts]))))
    logger.debug('target: {}'.format(target))
    return list(target)
