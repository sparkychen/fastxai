# -*- coding: utf-8 -*-

import requests
from tqdm import tqdm

down_url = "https://gh-proxy.org/https://github.com/astral-sh/uv/releases/download/0.9.18/uv-x86_64-pc-windows-msvc.zip"
with requests.get(down_url, stream=True) as r:
    r.raise_for_status()
    total_size = int(r.headers.get('content-length', 0)) # 从响应头获取文件大小    
    # 使用 tqdm 创建进度条
    with open('./uv-x86_64-pc-windows-msvc.zip', 'wb') as f, tqdm(
        desc='uv-x86_64-pc-windows-msvc.zip',
        total=total_size,
        unit='B',
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        for chunk in r.iter_content(chunk_size=8192):
            size = f.write(chunk)
            bar.update(size) # 更新进度条