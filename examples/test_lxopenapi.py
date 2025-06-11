#!/usr/bin/env python
from pathlib import Path
base_dir = Path(__file__) / ".." / ".."
import sys
sys.path.insert(0, str(base_dir))

import anyio
from pprint import pprint
from lingxing.lxopenapi import get_public_ip, LXOpenAPI

async def main():
    print (await get_public_ip())

    api = LXOpenAPI(
        host="https://openapi.lingxing.com",
        app_id="ak_MJOgYw9POgBN8",
        app_secret="/FlD6FYxpwT7IKSu/yKFIg==",
        proxy="http://alfa:pswdalfa2016@data.alfa2019.com:3128",
    )

    tk = await api.access_token()
    print (tk)
    tk = await api.refresh_token(tk['refresh_token'])
    print (tk)

    resp = await api.request(
        "/erp/sc/data/seller/allMarketplace", "GET",
    )
    pprint (resp)

if __name__ == '__main__':
    anyio.run(main)

