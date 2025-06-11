#!/usr/bin/env python
import copy
import time
from typing import Optional, Union, Dict, Any
import base64
import hashlib
from json import dumps as json_dumps
import httpx
from Crypto.Cipher import AES

async def get_public_ip():
    async with httpx.AsyncClient() as client:
        response = await client.get("https://toolbox.lingxing.com/api/getIp")
        response.raise_for_status()
        data = response.json()

    ip = data.get("data", "unknown")
    if ':' in ip:
        ip = ip.split(':')[-1].strip()
    return ip

def format_params(request_params: Union[None, dict] = None) -> str:
    if not request_params or not isinstance(request_params, dict):
        raise ValueError(f"Invalid Input {request_params}")

    canonical_strs = []
    sort_keys = sorted(request_params.keys())
    for k in sort_keys:
        v = request_params[k]
        if v == "":
            continue
        elif isinstance(v, (dict, list)):
            # 如果直接使用 json, 则必须使用separators=(',',':'), 去除序列化后的空格, 否则 json中带空格就导致签名异常
            # 使用 option=orjson.OPT_SORT_KEYS 保证dict进行有序 序列化(因为最终要转换为 str进行签名计算, 需要保证有序)
            canonical_strs.append(f"{k}={json_dumps(v, sort_keys=True)}")
        else:
            canonical_strs.append(f"{k}={v}")
    return "&".join(canonical_strs)

def md5_encrypt(text: str):
    md = hashlib.md5()
    md.update(text.encode('utf-8'))
    return md.hexdigest()

BLOCK_SIZE = 16  # Bytes

def do_pad(text):
    return text + (BLOCK_SIZE - len(text) % BLOCK_SIZE) * \
        chr(BLOCK_SIZE - len(text) % BLOCK_SIZE)

def aes_encrypt(key, data):
    key = key.encode('utf-8')
    data = do_pad(data)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(data.encode())
    encode_str = base64.b64encode(result)
    enc_text = encode_str.decode('utf-8')
    return enc_text

def generate_sign(encrypt_key: str, params: dict) -> str:
    params_s = format_params(params)
    md5_str = md5_encrypt(params_s).upper()
    sign = aes_encrypt(encrypt_key, md5_str)
    return sign

async def request(method: str, req_url: str,
                    params: Optional[dict] = None,
                    json: Optional[dict] = None,
                    headers: Optional[dict] = None,
                    default_timeout=30, proxy=None, **kwargs) -> dict:
    timeout = kwargs.pop('timeout', default_timeout)
    json_str = json_dumps(json, sort_keys=True) if json else None
    async with httpx.AsyncClient(proxy=proxy) as client:
        response = await client.request(
            method=method,
            url=req_url,
            params=params,
            json=json_str,
            timeout=timeout,
            headers=headers,
            **kwargs
        )
        response.raise_for_status()
        return response.json()

class LXOpenAPI:

    def __init__(self, host: str, app_id: str, app_secret: str, **req_kws):
        self.host = host
        self.app_id = app_id
        self.app_secret = app_secret
        self.req_kws = req_kws
        self.token = None

    async def access_token(self) -> dict:
        path = '/api/auth-server/oauth/access-token'
        req_url = self.host + path
        req_params = {
            "appId": self.app_id,
            "appSecret": self.app_secret,
        }
        resp = await request("POST", req_url, params=req_params, **self.req_kws)
        if resp['code'] != '200':
            error_msg = f"generate_access_token failed, reason: {resp['msg']}"
            raise ValueError(error_msg)

        assert isinstance(resp['data'], dict)
        self.token = resp['data']
        return self.token

    async def refresh_token(self, refresh_token: str) -> dict:
        path = '/api/auth-server/oauth/refresh'
        req_url = self.host + path
        req_params = {
            "appId": self.app_id,
            "refreshToken": refresh_token,
        }
        resp = await request("POST", req_url, params=req_params, **self.req_kws)
        if resp['code'] != '200':
            error_msg = f"refresh_token failed, reason: {resp['msg']}"
            raise ValueError(error_msg)

        assert isinstance(resp['data'], dict)
        self.token = resp['data']
        return self.token

    async def request(self, route_name: str, method: str,
                      req_params: Optional[dict] = None,
                      req_body: Optional[dict] = None,
                      access_token: Optional[str] = None,
                      **kwargs) -> dict:
        """
        :param access_token:
        :param route_name: 请求路径
        :param method: GET/POST/PUT,etc
        :param req_params: query参数放这里, 没有则不传
        :param req_body: 请求体参数放这里, 没有则不传
        :param kwargs: timeout 等其他字段可以放这里
        :return:
        """
        if access_token is None:
            if self.token is None:
                self.token = await self.access_token()
            access_token = self.token['access_token']

        req_url = self.host + route_name
        headers = kwargs.pop('headers', {})

        req_params = req_params or {}

        gen_sign_params = copy.deepcopy(req_params)
        if req_body:
            gen_sign_params.update(req_body)

        timestamp=int(time.time())
        sign_params = {
            "app_key": self.app_id,
            "access_token": access_token,
            "timestamp": timestamp,
        }
        gen_sign_params.update(sign_params)
        sign_params['sign'] = generate_sign(self.app_id, gen_sign_params)

        req_params.update(sign_params)

        if req_body and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        return await request(
            method, req_url, params=req_params,
            headers=headers,
            json=req_body,
            **self.req_kws,
            **kwargs)