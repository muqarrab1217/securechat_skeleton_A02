"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import time

class Hello(BaseModel):
    type: str = "hello"
    certPem: str
    nonce: Optional[str] = None

class DHClient(BaseModel):
    type: str = "dh_client"
    A: str

class DHServer(BaseModel):
    type: str = "dh_server"
    B: str
    sig: str

class Login(BaseModel):
    type: str = "login"
    username: str
    password: str

class Register(BaseModel):
    type: str = "register"
    username: str
    email: str
    password: str

class ChatMsg(BaseModel):
    type: str = "msg"
    seq: int
    iv: str
    ct: str
    mac: str

def jsonEncode(obj):
    if hasattr(obj, "dict"):
        j = obj.dict()
    elif isinstance(obj, dict):
        j = obj
    else:
        raise TypeError("jsonEncode accepts pydantic models or dicts")
    return json.dumps(j).encode("utf-8")

def jsonDecode(bs: bytes):
    return json.loads(bs.decode("utf-8"))

def nowMS():
    return int(time.time() * 1000)
