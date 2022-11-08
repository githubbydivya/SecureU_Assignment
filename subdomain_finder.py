import requests
from threading import Thread, Lock
from queue import Queue
from utils.check_x_xss_protection import XxssProtection
from utils.ssl_checker import CheckSSLDetails
from utils.capture_port_details import PortDetails

queue_obj = Queue()
list_lock = Lock()
discovered_domains = []
subdomains_count = 0


def scan_subdomains(domain_name):
    global queue_obj
    global subdomains_count
    print("[+] URL :", domain_name)
    print("-" * 40)
    print("[+] Subdomains :")
    while True:
        # get the subdomain from the queue loaded with subdomains-9K.txt using argument parser.
        subdomain = queue_obj.get()
        # scanning the subdomain for the given domain.
        subdomain_url = f"http://{subdomain}.{domain_name}"
        try:
            response = requests.get(subdomain_url)
        except requests.ConnectionError:
            pass
        else:
            result = f"- [{response.status_code}] {subdomain}.{domain_name}"
            print(result)
            subdomains_count = subdomains_count + 1
        queue_obj.task_done()
        # we're done with scanning that subdomain


def extract_related_info(subdomains_count, domain_name):
    print("[+] Total Subdomains Found : ", subdomains_count)
    print("-" * 40)
    check_ssl_obj = CheckSSLDetails()
    check_ssl_obj.check_ssl(domain_name)
    print("-" * 40)
    # Making Call to fetch tcp Ports informations.
    port_obj = PortDetails()
    port_obj.fetch_port_info(domain_name)
    print("-" * 40)
    check_xxss_obj = XxssProtection()
    check_xxss_obj.check_x_xss_protection(domain_name)


def main(domain, n_threads, subdomains):
    global queue_obj

    # fill the queue with all the subdomains
    for subdomain in subdomains:
        queue_obj.put(subdomain)

    for t in range(n_threads):
        # start all threads
        worker = Thread(target=scan_subdomains, args=(domain,))
        # daemon thread means a thread that will end when the main thread ends
        worker.daemon = True
        worker.start()
        worker.join(timeout=60)
    extract_related_info(subdomains_count, domain)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Faster Subdomain Scanner using Threads")
    parser.add_argument("domain",
                        help="Domain to scan for subdomains without protocol (e.g without 'http://' or 'https://')")
    parser.add_argument("-l", "--wordlist",
                        help="File that contains all subdomains to scan, line by line. Default is subdomains.txt",
                        default="subdomains_files/subdomains.txt")
    parser.add_argument("-t", "--num-threads", help="Number of threads to use to scan the domain. Default is 10",
                        default=10, type=int)
    parser.add_argument("-o", "--output-file", help="Specify the output text file to write discovered subdomains",
                        default="discovered-subdomains.txt")

    args = parser.parse_args()
    domain = args.domain
    wordlist = args.wordlist
    num_threads = args.num_threads
    output_file = args.output_file

    main(domain=domain, n_threads=num_threads, subdomains=open(wordlist).read().splitlines())
    queue_obj.join()

    # save the file
    with open(output_file, "w") as f:
        for url in discovered_domains:
            print(url, file=f)
