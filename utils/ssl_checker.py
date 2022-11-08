import socket
import ssl
from datetime import datetime

import OpenSSL.crypto as crypto

ssl_enabled_disbaled_dict = {True: "Disbaled", False: "Enabled"}


class CheckSSLDetails(object):

    def check_ssl(self, domain):
        print("[+] SSL Details :")
        now = datetime.now()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert(True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
            commonName = x509.get_subject().CN
            notAfter = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            notBefore = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            expired = (notAfter < now) or (notBefore > now)
            print("- SSL : ", ssl_enabled_disbaled_dict.get(expired))
        print("- issued_to : ", domain)
