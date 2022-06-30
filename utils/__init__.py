# -*- coding: UTF-8 -*-
import logging
import os.path
import sys

from .utils import walk

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s -> %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=os.path.join(os.path.dirname(sys.argv[0]), 'Converter.log'), 
    encoding='utf-8'
)

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter(
    fmt='%(asctime)s - %(levelname)s - %(name)s -> %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
ch.setLevel(logging.INFO)
logging.getLogger('').addHandler(ch)
