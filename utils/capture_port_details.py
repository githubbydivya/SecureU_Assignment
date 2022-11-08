import socket
import nmap


class PortDetails(object):

    def fetch_port_info(self, domain_name):
        print("[+] Ports")
        begin_port = 1
        end_port = 250
        scanner = nmap.PortScanner()
        if domain_name is not None:
            # translate hostname to IPv4
            ipv4_hostname = socket.gethostbyname(domain_name)
        else:
            print("Invalid domain_name -> ", domain_name)
        try:
            # Will scan ports between 1 and 250
            for i in range(begin_port, end_port + 1):
                # scan the ipv4_hostname and corresponding ports from 1 to 250
                res = scanner.scan(ipv4_hostname, str(i))
                # We will access the information about the port state
                res = res['scan'][ipv4_hostname]['tcp'][i]['state']
                # Below Capitalizing the first letter of the res i.e. the state for each of the tcp port.
                print(f'Port {i}  : {res.capitalize()}')
        except KeyboardInterrupt:
            print("\n KeyboardInterrupt, Exiting Program...")
        except Exception as ex:
            print(ex)

