import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
import base64


class Web():
    URL = "https://oauth.yiban.cn/code/html?client_id=b3a31fa8019cc40b&redirect_uri=http://f.yiban.cn/iapp76127"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; V1981A Build/SP1A.210812.003; wv) AppleWebKit/537.36 (KHTML, "
                      "like Gecko) Version/4.0 Chrome/94.0.4606.61 Mobile Safari/537.36;webank/h5face;webank/2.0 "
                      "yiban_android/5.0.18"}
    response = 0
    content = ""
    cookies = ""
    pubkey = ""
    passwd = ""
    username = ""
    crypt_passwd = ""
    response_logind = 0

    def request(self):
        self.response = requests.get(self.URL, headers=self.headers)
        self.content = self.response.content.decode('utf-8')
        self.cookies = self.response.cookies
        return self.response.status_code

    def get_pubkey(self):
        start = self.content.find("-----BEGIN PUBLIC KEY-----")
        end = self.content.find("-----END PUBLIC KEY-----") + 24
        self.pubkey = self.content[start:end]
        return self.pubkey

    def crypt(self):
        cipher = Cipher_pkcs1_v1_5.new(RSA.importKey(self.pubkey))
        cipher_text = base64.b64encode(cipher.encrypt(self.passwd.encode())).decode()
        self.crypt_passwd = cipher_text
        return cipher_text

    def login(self):
        URL = self.URL[self.URL.find("uri=") + 4:]
        client_id = self.URL[int(self.URL.find("client_id")) + 10:self.URL.find("redirect") - 1:]
        dic = {
            "oauth_uname": self.username,
            "oauth_upwd": self.crypt_passwd,
            "client_id": client_id,
            "redirect_uri": URL,
            "state": "",
            "scope": "1,2,3,4,",
            "display": "html"
        }

        self.response_logind = requests.post("https://oauth.yiban.cn/code/usersure", data=dic,cookies=self.cookies)
        print(dic)
        print(self.response_logind.content.decode('utf-8'))
        print(self.response_logind.status_code)


def main():
    print('run')
    test = Web()
    test.request()
    test.get_pubkey()
    test.crypt()
    #print(test.pubkey)
    # print(test.cookies)
    #print(test.crypt_passwd)
    test.login()
    #print(test.response_logind.content.decode('utf-8'))


main()
