import copy
import requests
from bs4 import BeautifulSoup as BS
from HttpClient import HttpClientSingleton

class AuthController:
    _REQ_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
        "sec-ch-ua-mobile": "?0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "https://dhlottery.co.kr",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Referer": "https://dhlottery.co.kr/",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Language": "ko,en-US;q=0.9,en;q=0.8,ko-KR;q=0.7",
    }

    _AUTH_CRED = ""


    def __init__(self):
        self.http_client = HttpClientSingleton.get_instance()

    def login(self, user_id: str, password: str):
        assert type(user_id) == str
        assert type(password) == str

        # 1. Get a pre-login JSESSIONID
        pre_login_jsessionid = self._get_default_auth_cred()

        # 2. Try to login with the pre-login JSESSIONID
        headers = self._generate_req_headers(pre_login_jsessionid)
        data = self._generate_body(user_id, password)
        login_res = self._send_login_request(headers, data)

        # 3. Get the post-login JSESSIONID from the login response
        post_login_jsessionid = self._get_j_session_id_from_response(login_res)

        # 4. Verify login success with the post-login JSESSIONID
        if not self._verify_login_success(post_login_jsessionid):
            raise Exception("Login failed. Please check your username and password.")

        # 5. Set the auth credential
        self._set_auth_cred(post_login_jsessionid)


    def add_auth_cred_to_headers(self, headers: dict) -> str:
        assert type(headers) == dict

        copied_headers = copy.deepcopy(headers)
        copied_headers["Cookie"] = f"JSESSIONID={self._AUTH_CRED}"
        return copied_headers

    def _get_default_auth_cred(self):
        res = self.http_client.get(
            "https://dhlottery.co.kr/gameResult.do?method=byWin&wiselog=H_C_1_1"
        )

        return self._get_j_session_id_from_response(res)

    def _get_j_session_id_from_response(self, res: requests.Response):
        assert type(res) == requests.Response

        for cookie in res.cookies:
            if cookie.name == "JSESSIONID":
                return cookie.value

        raise KeyError("JSESSIONID cookie is not set in response")

    def _generate_req_headers(self, j_session_id: str):
        assert type(j_session_id) == str

        copied_headers = copy.deepcopy(self._REQ_HEADERS)
        copied_headers["Cookie"] = f"JSESSIONID={j_session_id}"
        return copied_headers

    def _generate_body(self, user_id: str, password: str):
        assert type(user_id) == str
        assert type(password) == str

        return {
            "returnUrl": "https://dhlottery.co.kr/common.do?method=main",
            "userId": user_id,
            "password": password,
            "checkSave": "on",
            "newsEventYn": "",
        }

    def _send_login_request(self, headers: dict, data: dict):
        assert type(headers) == dict
        assert type(data) == dict

        res = self.http_client.post(
            "https://www.dhlottery.co.kr/userSsl.do?method=login",
            headers=headers,
            data=data,
        )
        return res

    def _verify_login_success(self, j_session_id: str) -> bool:
        assert type(j_session_id) == str

        headers = self._generate_req_headers(j_session_id)
        res = self.http_client.post(
            url="https://dhlottery.co.kr/userSsl.do?method=myPage",
            headers=headers
        )

        html = res.text
        soup = BS(html, "html5lib")

        # Check for a specific element that only appears when logged in
        balance_element = soup.find("p", class_="total_new")
        return balance_element is not None

    def _set_auth_cred(self, j_session_id: str) -> None:
        assert type(j_session_id) == str
        self._AUTH_CRED = j_session_id
