import asyncio
import base64
import datetime
import hashlib
import json
import locale
import logging
import time
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional, Self, Unpack

import tzlocal
from aiohttp import ClientSession, ClientResponse, ClientTimeout
from aiohttp.client import _RequestOptions
from aiohttp.typedefs import StrOrURL

from yarl import URL

from .const import AVAILABLE_SERVERS, SERVER_CN
from .utils import generate_agent, generate_device_id, to_json, generate_nonce, generate_enc_params, decrypt_rc4
from ..utils.exceptions import (
    TwoFactorAuthRequiredException,
    InvalidCredentialsException,
    FailedLoginException,
    TooManyAttemptsException,
    FailedConnectionException,
    CaptchaRequiredException
)

_LOGGER = logging.getLogger(__name__)


@dataclass
class XiaomiCloudConnectorConfig:
    username: str
    password: str
    server: str
    user_id: str
    service_token: str
    expiration: datetime.datetime
    ssecurity: str
    device_id: str

    @classmethod
    def from_dict(cls, data: "dict[str,str] | XiaomiCloudConnectorConfig") -> "XiaomiCloudConnectorConfig":
        if isinstance(data, XiaomiCloudConnectorConfig):
            return data
        data = data.copy()
        data["expiration"] = datetime.datetime.fromisoformat(str(data["expiration"]))
        return cls(**data)


@dataclass
class XiaomiCloudHome:
    home_id: int
    owner: int


@dataclass
class XiaomiCloudDeviceInfo:
    device_id: str
    name: str
    model: str
    token: str
    spec_type: str
    local_ip: str | None
    mac: str | None
    server: str
    home_id: int
    user_id: int


@dataclass
class XiaomiCloudSessionData:
    session: ClientSession
    headers: dict[str, str]
    ssecurity: str | None = None
    userId: str | None = None
    serviceToken: str | None = None
    expiration: datetime.datetime | None = None

    def is_authenticated(self) -> bool:
        return self.serviceToken is not None and self.expiration > datetime.datetime.now() - datetime.timedelta(days=1)

    async def get(self: Self, url: StrOrURL, **kwargs: Unpack[_RequestOptions]):
        passed_headers = kwargs.pop("headers", {})
        return await self.session.get(url, headers={**passed_headers, **self.headers}, **kwargs)

    async def post(self: Self, url: StrOrURL, **kwargs: Unpack[_RequestOptions]) -> ClientResponse:
        passed_headers = kwargs.pop("headers", {})
        return await self.session.post(url, headers={**passed_headers, **self.headers}, **kwargs)

    def get_cookie(self: Self, key: str, default: None | str = None, domain: None | str = None) -> None | str:
        jar = self.session.cookie_jar

        return next((cookie.value for cookie in jar
                     if cookie.key == key and (not domain or domain in cookie.get("domain", ""))
                    ), default)


# noinspection PyBroadException
class XiaomiCloudConnector:
    _username: str
    _password: str
    _session_data: XiaomiCloudSessionData | None
    _locale: str
    _timezone: str
    server: str | None

    def __init__(self: Self, session_creator: Callable[[], ClientSession], username: str, password: str,
                 server: str | None = None):
        self._username = username
        self._password = password
        self._session_creator = session_creator
        self._locale = locale.getdefaultlocale()[0] or "en_GB"
        timezone = datetime.datetime.now(tzlocal.get_localzone()).strftime('%z')
        self._timezone = f"GMT{timezone[:-2]}:{timezone[-2:]}"
        self.server = server
        self._session_data = None
        self.device_id = generate_device_id()

    async def create_session(self: Self) -> None:
        if self._session_data is not None and self._session_data.session is not None:
            self._session_data.session.detach()
        agent = generate_agent(self.device_id)
        session = self._session_creator()
        cookies = {
            "sdkVerdion": "accountsdk-18.8.15",
            "deviceId": self.device_id
        }
        session.cookie_jar.update_cookies(cookies, response_url=URL("mi.com"))
        session.cookie_jar.update_cookies(cookies, response_url=URL("xiaomi.com"))
        headers = {"User-Agent": agent, "Content-Type": "application/x-www-form-urlencoded"}

        self._session_data = XiaomiCloudSessionData(session, headers)

    async def _login_step_1(self: Self) -> str:
        _LOGGER.debug("Xiaomi cloud login - step 1")
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        cookies = {
            "userId": self._username
        }

        try:
            response = await self._session_data.get(url, cookies=cookies)
            _LOGGER.debug("Xiaomi cloud login - step 1 status: %s", response.status)
            response_text = await response.text()
            _LOGGER.debug("Xiaomi cloud login - step 1 content: %s", response_text)
            response_json = to_json(response_text)
        except:
            raise FailedLoginException()

        if response.status == 200:
            if "_sign" in response_json:
                sign = response_json["_sign"]
                _LOGGER.debug("Xiaomi cloud login - step 1 sign: %s", sign)
                return sign
            elif "ssecurity" in response_json:
                self._session_data.ssecurity = response_json["ssecurity"]
                self._session_data.userId = response_json["userId"]
                max_age = int(response.cookies.get("userId").get("max-age"))
                self._session_data.expiration = datetime.datetime.now() + datetime.timedelta(seconds=max_age)

                return response_json["location"]

        _LOGGER.debug("Xiaomi cloud login - step 1 sign/ssecurity missing")
        return ""

    async def _login_step_2(self: Self, sign: str, captcha_code: str | None = None) -> str:
        _LOGGER.debug("Xiaomi cloud login - step 2")
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        params = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": sign,
            "_json": "true"
        }
        if captcha_code:
            params["captCode"] = captcha_code
        try:
            response = await self._session_data.post(url, params=params)
            _LOGGER.debug("Xiaomi cloud login - step 2 status: %s", response.status)
            response_text = await response.text()
            _LOGGER.debug("Xiaomi cloud login - step 2 content: %s", response_text)
            response_json = to_json(response_text)
        except:
            raise InvalidCredentialsException()
        if response.status == 200:
            if "ssecurity" in response_json:
                location = response_json["location"]
                self._session_data.ssecurity = response_json["ssecurity"]
                self._session_data.userId = response_json["userId"]
                max_age = int(response.cookies.get("userId").get("max-age"))
                self._session_data.expiration = datetime.datetime.now() + datetime.timedelta(seconds=max_age)
                self.two_factor_auth_url = None
                return location
            else:
                if "notificationUrl" in response_json:
                    await self.do_2fa_email_flow(response_json["notificationUrl"])
                elif "captchaUrl" in response_json and response_json["captchaUrl"] is not None:
                    captcha_url = response_json["captchaUrl"]
                    if captcha_url.startswith("/"):
                        captcha_url = "https://account.xiaomi.com" + response_json["captchaUrl"]

                    captcha_response = await self._session_data.get(captcha_url)
                    captcha_response_b64 = "data:image/jpeg;base64," + base64.b64encode(await captcha_response.read()).decode("utf-8")

                    raise CaptchaRequiredException(captcha_response_b64, sign)
        raise InvalidCredentialsException()

    async def do_2fa_email_flow(self: Self, notification_url: str) -> bool:
        """
        Handles the email-based 2FA flow and extracts ssecurity + serviceToken.
        Robust to cases where verifyEmail returns non-JSON/empty body.
        """
        # 1) Open notificationUrl (authStart)
        _LOGGER.debug("Opening notificationUrl (authStart): %s", notification_url)

        r = await self._session_data.get(notification_url)
        _LOGGER.debug("authStart final URL: %s status=%s", r.url, r.status)

        # 2) Fetch identity options (list)
        context = URL(notification_url).query["context"]
        list_params = {
            "sid": "xiaomiio",
            "context": context,
            "_locale": "en_US"
        }
        _LOGGER.debug("GET /identity/list params=%s", list_params)
        r = await self._session_data.get("https://account.xiaomi.com/identity/list", params=list_params)
        _LOGGER.debug("identity/list status=%s", r.status)

        # 3) Request email ticket
        send_params = {
            "_dc": str(int(time.time() * 1000)),
            "sid": "xiaomiio",
            "context": list_params["context"],
            "mask": "0",
            "_locale": "en_US"
        }
        send_data = {
            "retry": "0",
            "icode": "",
            "_json": "true",
            "ick": self._session_data.get_cookie("ick", "")
        }
        _LOGGER.debug("sendEmailTicket POST url=https://account.xiaomi.com/identity/auth/sendEmailTicket params=%s", send_params)
        _LOGGER.debug("sendEmailTicket data=%s", send_data)
        r = await self._session_data.post("https://account.xiaomi.com/identity/auth/sendEmailTicket",
                               params=send_params, data=send_data)
        try:
            jr = to_json(await r.text())
        except Exception:
            jr = {}
        _LOGGER.debug("sendEmailTicket response status=%s json=%s", r.status, jr)

        if (jr.get("code") == 70022):
            raise TooManyAttemptsException("Too many 2fa codes sent. Try again tomorrow.")

        # 4) Ask user for the email code and verify
        raise TwoFactorAuthRequiredException(context)


    async def continue_2fa_email_flow(self: Self, code: str, context: str) -> str:
        verify_params = {
            "_flag": "8",
            "_json": "true",
            "sid": "xiaomiio",
            "context": context,
            "mask": "0",
            "_locale": "en_US"
        }
        verify_data = {
            "_flag": "8",
            "ticket": code,
            "trust": "false",
            "_json": "true",
            "ick": self._session_data.get_cookie("ick", "")
        }
        r = await self._session_data.post("https://account.xiaomi.com/identity/auth/verifyEmail",
                               params=verify_params, data=verify_data)
        if r.status != 200:
            _LOGGER.error("verifyEmail failed: status=%s body=%s", r.status, (await r.text())[:500])
            raise FailedLoginException("2FA flow failed: verifyEmail failed with error status")

        finish_loc = None
        try:
            jr = await r.json()
            _LOGGER.debug("verifyEmail response status=%s json=%s", r.status, jr)
            finish_loc = jr.get("location")
        except Exception:
            # Non-JSON or empty; try to extract from headers or body
            _LOGGER.debug("verifyEmail returned non-JSON, attempting fallback extraction.")
            finish_loc = r.headers.get("Location")
            r_text = await r.text()
            if not finish_loc and r_text:
                m = re.search(r'https://account\.xiaomi\.com/identity/result/check\?[^"\']+', r_text)
                if m:
                    finish_loc = m.group(0)

        # Fallback: directly hit result/check using existing identity_session/context
        if not finish_loc:
            _LOGGER.debug("Using fallback call to /identity/result/check")
            r0 = await self._session_data.get(
                "https://account.xiaomi.com/identity/result/check",
                params={"sid": "xiaomiio", "context": context, "_locale": "en_US"},
                allow_redirects=False
            )
            _LOGGER.debug("result/check (fallback) status=%s hop-> %s", r0.status, r0.headers.get("Location"))
            if r0.status in (301, 302) and r0.headers.get("Location"):
                finish_loc = r0.url if "serviceLoginAuth2/end" in r0.url else r0.headers["Location"]

        if not finish_loc:
            _LOGGER.error("Unable to determine finish location after verifyEmail.")
            raise FailedLoginException("2FA flow failed: Unable to determine finish location after verifyEmail.")


        # First hop: GET identity/result/check (do NOT follow redirects to inspect Location)
        if "identity/result/check" in finish_loc:
            r = await self._session_data.get(finish_loc, allow_redirects=False)
            _LOGGER.debug("result/check status=%s hop-> %s", r.status, r.headers.get("Location"))
            end_url = r.headers.get("Location")
        else:
            end_url = finish_loc

        if not end_url:
            _LOGGER.error("Could not find Auth2/end URL in finish chain.")
            raise FailedLoginException("2FA flow failed: Could not find Auth2/end URL in finish chain.")

        # 6) Call Auth2/end WITHOUT redirects to capture 'extension-pragma' header containing ssecurity
        r = await self._session_data.get(end_url, allow_redirects=False)
        _LOGGER.debug("Auth2/end status=%s", r.status)
        r_text = await r.text()
        _LOGGER.debug("Auth2/end body(trunc)=%s", r_text[:200])
        # Some servers return 200 first (HTML 'Tips' page), then 302 on next call.
        if r.status == 200 and "Xiaomi Account - Tips" in r_text:
            r = await self._session_data.get(end_url, allow_redirects=False)
            _LOGGER.debug("Auth2/end(second) status=%s", r.status)

        ext_prag = r.headers.get("extension-pragma")
        if ext_prag:
            try:
                ep_json = json.loads(ext_prag)
                ssec = ep_json.get("ssecurity")
                psec = ep_json.get("psecurity")
                _LOGGER.debug("extension-pragma present. ssecurity=%s psecurity=%s", ssec, psec)
                if ssec:
                    self._session_data.ssecurity = ssec
            except Exception as e:
                _LOGGER.debug("Failed to parse extension-pragma: %s", e)

        if not self._session_data.ssecurity:
            _LOGGER.error("extension-pragma header missing ssecurity; cannot continue.")
            raise FailedLoginException("2FA flow failed: extension-pragma header missing ssecurity; cannot continue.")

        # 7) Find STS redirect and visit it (to set serviceToken cookie)
        sts_url = r.headers.get("Location")
        if not sts_url and r.text:
            idx = r.text.find("https://sts.api.io.mi.com/sts")
            if idx != -1:
                end = r.text.find('"', idx)
                if end == -1:
                    end = idx + 300
                sts_url = r.text[idx:end]
        if not sts_url:
            _LOGGER.error("Auth2/end did not provide STS redirect.")
            raise FailedLoginException("2FA flow failed: Auth2/end did not provide STS redirect.")

        r = await self._session_data.get(sts_url, allow_redirects=True)
        _LOGGER.debug("STS final URL: %s status=%s", r.url, r.status)
        if r.status != 200:
            _LOGGER.error("STS did not complete: status=%s body=%s", r.status, (await r.text())[:200])
            raise FailedLoginException("2FA flow failed: STS did not complete")

        # Extract serviceToken from cookie jar
        self._session_data.serviceToken = self._session_data.get_cookie("serviceToken", domain="sts.api.io.mi.com")
        found = bool(self._session_data.serviceToken)
        _LOGGER.debug("STS body (trunc)=%s", (await r.text())[:20])
        if not found:
            _LOGGER.error("Could not parse serviceToken; cannot complete login.")
            raise FailedLoginException("2FA flow failed: Could not parse serviceToken; cannot complete login.")
        _LOGGER.debug("STS did not return JSON; assuming 'ok' style response and relying on cookies.")
        _LOGGER.debug("extract_service_token: found=%s", found)

        # Mirror serviceToken to API domains expected by Mi Cloud
        for d in ["api.io.mi.com", "io.mi.com", "mi.com"]:
            cookies = {
                "serviceToken": self._session_data.serviceToken,
                "yetAnotherServiceToken": self._session_data.serviceToken
                }
            self._session_data.session.cookie_jar.update_cookies(cookies, URL(d))

        # Update ids from cookies if available
        self._session_data.userId = (self._session_data.get_cookie("userId", domain="account.xiaomi.com")
                                    or self._session_data.get_cookie("userId", domain="sts.api.io.mi.com")
                                    or self._session_data.userId)

        max_age = next((int(cookie.get("max-age", 0)) for cookie in self._session_data.session.cookie_jar
                        if cookie.key == "userId" and cookie.get("max-age") is not None), 0)

        self._session_data.expiration = datetime.datetime.now() + datetime.timedelta(seconds=max_age)

        return self._session_data.serviceToken

    async def _login_step_3(self: Self, location: str) -> None:
        _LOGGER.debug("Xiaomi cloud login - step 3 (location: %s)", location)
        try:
            response = await self._session_data.get(location)
            _LOGGER.debug("Xiaomi cloud login - step 3 status: %s", response.status)
            response_text = await response.text()
            _LOGGER.debug("Xiaomi cloud login - step 3 content: %s", response_text)
        except:
            raise InvalidCredentialsException()
        if response.status == 200 and "serviceToken" in response.cookies:
            self._session_data.serviceToken = response.cookies.get("serviceToken").value
        else:
            raise InvalidCredentialsException()

    async def login(self: Self) -> str | None:
        _LOGGER.debug("Logging in...")
        await self.create_session()
        sign = await self._login_step_1()
        if not sign.startswith('http'):
            location = await self._login_step_2(sign)
        else:
            location = sign
        await self._login_step_3(location)
        _LOGGER.debug("Logged in.")
        return self._session_data.serviceToken

    async def login_with_captcha(self: Self, sign: str, captcha_code: str) -> str | None:
        _LOGGER.debug("Continuing login with captcha entered.")

        location = await self._login_step_2(sign, captcha_code)
        await self._login_step_3(location)

        _LOGGER.debug("Logged in.")
        return self._session_data.serviceToken

    async def qr_login_step_1(self: Self):
        await self.create_session()
        # step 1
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        resp = await self._session_data.get(url)
        if resp.status != 200:
            _LOGGER.debug("Step 1 of QR login failed (code %s): %s", resp.status, await resp.text())
            raise FailedLoginException("Step 1 of QR login failed")

        # step 2
        json_resp = to_json(await resp.text())
        location = json_resp["location"]
        location_parsed = dict(URL(location).query)

        params = {
            '_qrsize': 240,
            'qs': json_resp['qs'],
            'bizDeviceType': '',
            'callback': json_resp['callback'],
            '_json': 'true',
            'theme': '',
            'sid': 'xiaomiio',
            'needTheme': 'false',
            'showActiveX': 'false',
            'serviceParam': location_parsed['serviceParam'],
            '_local': 'zh_CN',
            '_sign': json_resp['_sign'],
            '_dc': str(int(time.time() * 1000)),
        }

        url = URL('https://account.xiaomi.com/longPolling/loginUrl').with_query(params)
        resp = await self._session_data.get(url)

        if resp.status != 200:
            _LOGGER.debug("Xiaomi cloud qr login - Failed to obtain the QR code URL (code %s): %s", resp.status, await resp.text())
            raise FailedLoginException('Failed to obtain the QR code URL')

        json_resp = to_json(await resp.text())
        if json_resp['code'] != 0:
            _LOGGER.debug("Xiaomi cloud qr login - QR code unavailable (code %s): %s", json_resp['code'], json_resp['desc'])
            raise FailedLoginException("QR code unavailable")

        qr_response = await self._session_data.get(json_resp['qr'])
        qr_response_b64 = "data:image/png;base64," + base64.b64encode(await qr_response.read()).decode("utf-8")

        return {"qr_image": qr_response_b64, "link": json_resp['loginUrl'], "lp": json_resp['lp']}

    async def qr_login_step_2(self: Self, lp: str):
        try:
            resp = await self._session_data.get(lp, 
                                               timeout=ClientTimeout(total=60),
                                               headers={'Connection': 'keep-alive'})
        except asyncio.TimeoutError:
            _LOGGER.debug("Xiaomi cloud qr login - Timeout, please try again")
            raise FailedLoginException('Timeout, please try again')
        if resp.status != 200:
            _LOGGER.debug("Xiaomi cloud qr login - Long polling failed (code %s): %s", resp.status, await resp.text())
            raise FailedLoginException('Long polling failed, please try again')

        json_resp = to_json(await resp.text())
        max_age = int(resp.cookies.get("userId").get("max-age"))

        if json_resp['code'] != 0:
            _LOGGER.debug("Xiaomi cloud qr login - Long polling succeded, but returned error %s: %s", json_resp['code'], json_resp['desc'])
            raise FailedLoginException("Long polling succeded, but returned error")

        resp = await self._session_data.get(json_resp['location'])
        if resp.status != 200:
            _LOGGER.debug("Xiaomi cloud qr login - Failed to obtain last jump position %s: %s", resp.status, await resp.text())
            raise FailedLoginException("Failed to obtain last jump position")

        self._session_data.userId = json_resp["userId"]
        self._session_data.ssecurity = json_resp["ssecurity"]

        self._session_data.serviceToken = resp.cookies.get("serviceToken").value
        self._session_data.expiration = datetime.datetime.now() + datetime.timedelta(seconds=max_age)


    def is_authenticated(self: Self) -> bool:
        return self._session_data is not None and self._session_data.is_authenticated()

    async def get_raw_map_data(self: Self, map_url: str | None) -> bytes | None:
        if map_url is not None:
            try:
                _LOGGER.debug("Downloading raw map from \"%s\"...", map_url)
                response = await self._session_data.session.get(map_url)
            except:
                _LOGGER.debug("Downloading the map failed.")
                return None
            if response.status == 200:
                _LOGGER.debug("Downloaded raw map, status: (%d).", response.status)
                data = await response.content.read()
                _LOGGER.debug("Downloaded raw map (%d).", len(data))
                return data
            else:
                _LOGGER.debug("Downloading the map failed. Status: (%d).", response.status)
                _LOGGER.debug("Downloading the map failed. Text: (%s).", await response.text())

        return None

    async def _get_homes(self: Self, server: str) -> list[XiaomiCloudHome]:
        url = self.get_api_url(server) + "/v2/homeroom/gethome"
        params = {
            "data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'
        }

        homes = []

        homes_response = await self.execute_api_call_encrypted(url, params)
        if homes_response is None:
            return homes
        if homelist := homes_response["result"].get("homelist", None):
            homes.extend([XiaomiCloudHome(int(home["id"]), home["uid"]) for home in homelist])
        if homelist := homes_response["result"].get("share_home_list", None):
            homes.extend([XiaomiCloudHome(int(home["id"]), home["uid"]) for home in homelist])
        return homes

    async def _get_devices_from_home(self: Self, server: str, home_id: int, owner_id: int) -> list[
        XiaomiCloudDeviceInfo]:
        url = self.get_api_url(server) + "/v2/home/home_device_list"
        params = {
            "data": json.dumps(
                {
                    "home_id": home_id,
                    "home_owner": owner_id,
                    "limit": 200,
                    "get_split_device": True,
                    "support_smart_home": True,
                }
            )
        }
        if (response := await self.execute_api_call_encrypted(url, params)) is None:
            return []

        if (raw_devices := response["result"]["device_info"]) is None:
            return []
        return [
            XiaomiCloudDeviceInfo(
                device_id=device["did"],
                name=device["name"],
                model=device["model"],
                token=device.get("token", ""),
                spec_type=device.get("spec_type", ""),
                local_ip=device.get("localip", None),
                mac=device.get("mac", None),
                server=server,
                user_id=owner_id,
                home_id=home_id,
            )
            for device in raw_devices
        ]

    async def get_devices(self: Self, server: Optional[str] = None) -> list[XiaomiCloudDeviceInfo]:
        countries_to_check = AVAILABLE_SERVERS if server is None else [server]
        device_coro_list = [self._get_devices_from_server(server) for server in countries_to_check]
        device_lists = await asyncio.gather(*device_coro_list)
        return [device for device_list in device_lists for device in device_list]

    async def _get_devices_from_server(self: Self, server: str) -> list[XiaomiCloudDeviceInfo]:
        homes = await self._get_homes(server)
        device_coro_list = [self._get_devices_from_home(server, home.home_id, home.owner) for home in homes]
        device_lists = await asyncio.gather(*device_coro_list)
        return [device for device_list in device_lists for device in device_list]

    async def get_device_details(self: Self, token: str, server: Optional[str] = None) -> XiaomiCloudDeviceInfo | None:
        devices = await self.get_devices(server)
        matching_token = filter(lambda device: device.token == token, devices)
        return next(matching_token, None)

    async def get_other_info(self: Self, device_id: str, method: str, parameters: dict) -> any:
        url = self.get_api_url('sg') + "/v2/home/rpc/" + device_id
        params = {
            "data": json.dumps({"method": method, "params": parameters}, separators=(",", ":"))
        }
        return await self.execute_api_call_encrypted(url, params)

    async def execute_api_call_encrypted(self: Self, url: str, params: dict[str, str]) -> any:
        headers = {
            "Accept-Encoding": "identity",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self._session_data.userId),
            "yetAnotherServiceToken": str(self._session_data.serviceToken),
            "serviceToken": str(self._session_data.serviceToken),
            "locale": self._locale,
            "timezone": self._timezone,
            "is_daylight": str(time.daylight),
            "dst_offset": str(time.localtime().tm_isdst * 60 * 60 * 1000),
            "channel": "MI_APP_STORE"
        }
        millis = round(time.time() * 1000)
        nonce = generate_nonce(millis)
        signed_nonce = self._signed_nonce(nonce)
        fields = generate_enc_params(url, "POST", signed_nonce, nonce, params, self._session_data.ssecurity)

        try:
            response = await self._session_data.post(url, headers=headers, cookies=cookies, params=fields)
            response_text = await response.text()
        except Exception as e:
            raise FailedConnectionException(e)
        if response.status == 200:
            decoded = decrypt_rc4(self._signed_nonce(fields["_nonce"]), response_text)
            return json.loads(decoded)
        if response.status in [401, 403]:
            raise FailedLoginException()
        else:
            return None

    def get_api_url(self: Self, server: str | None = None) -> str:
        if server is None:
            server = self.server
        return "https://" + ("" if server == SERVER_CN else (server + ".")) + "api.io.mi.com/app"

    def _signed_nonce(self: Self, nonce: str) -> str:
        hash_object = hashlib.sha256(base64.b64decode(self._session_data.ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode()

    def to_config(self: Self) -> XiaomiCloudConnectorConfig:
        return XiaomiCloudConnectorConfig(
            self._username,
            self._password,
            self.server,
            self._session_data.userId,
            self._session_data.serviceToken,
            self._session_data.expiration,
            self._session_data.ssecurity,
            self.device_id
        )

    @staticmethod
    async def from_config(config: XiaomiCloudConnectorConfig, session_creator: Callable[[], ClientSession]):
        connector = XiaomiCloudConnector(session_creator,
                                         config.username,
                                         config.password,
                                         server=config.server)
        connector.device_id = config.device_id

        await connector.create_session()

        connector._session_data.userId = config.user_id
        connector._session_data.serviceToken = config.service_token
        connector._session_data.ssecurity = config.ssecurity
        connector._session_data.expiration = config.expiration

        return connector
