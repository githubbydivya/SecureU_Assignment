import requests


class XxssProtection(object):

    def check_x_xss_protection(self, domain):
        url = f"https://{domain}/"
        # response = urllib3.connection_from_url(url)
        response = requests.get(url)
        x_xss_header_value = response.headers.get('X-XSS-Protection')
        print("[+] Header : ")
        if x_xss_header_value and (
                x_xss_header_value == '1; mode=block' or x_xss_header_value == '1;mode=block' or x_xss_header_value == '1'):
            print("X-XSS-Protection : Enabled")
        else:
            print("X-XSS-Protection : Disabled")

