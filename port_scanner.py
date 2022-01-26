import ipaddress
import queue
import re
import socket
import threading
import time

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class PortsScanner:
    host = ''
    mask = ''
    ports_to_scan = []
    __max_threads = 50
    __queue_output = queue.Queue()
    __lock = threading.Lock()

    def __init__(self):
        self.get_input_data()

    def get_input_data(self):
        self.get_ip()
        if len(self.host) > 0:
            if len(self.mask) > 0:
                self.get_ports()
                if len(self.host) > 0 and len(self.mask) > 0:
                    return
            else:
                print('No mask')
                return
        else:
            print('No Host')
            return
        print('Error')

    def get_ports(self):
        print('Please provide ports to scan. For example: 80, 443, 22, 21, 25')
        ports_input = input().replace(' ', '')
        if len(ports_input) > 0:
            self.ports_to_scan = [int(port) for port in re.findall('[0-9]+', ports_input)]
            if len(self.ports_to_scan) > 0:
                return self.ports_to_scan

        print('Error')

    def get_ip(self):
        print('Please provide ip and mask. For example: 192.168.1.0/24')
        ips_input = input().replace(' ', '')
        if len(ips_input) > 0:
            ip_tpl = re.findall(r"([0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}/[0-9]{,3})", ips_input)
            if len(ip_tpl) > 0:
                self.host = ip_tpl[0].split('/')[0]
                self.mask = ip_tpl[0].split('/')[1]
                return self.host, self.mask
        print('Error')

    def start_scan(self):
        print('Scan started...')
        network = ipaddress.ip_network(f'{self.host}/{self.mask}', strict=False)
        network_address = network.network_address
        if network_address is not None:
            self.scan_ports(ip=format(network_address), ports=self.ports_to_scan)

        broadcast_address = network.broadcast_address
        if broadcast_address is not None and broadcast_address != network_address:
            self.scan_ports(ip=format(broadcast_address), ports=self.ports_to_scan)

        for host in list(network.hosts()):
            while threading.active_count() > self.__max_threads:
                time.sleep(1)
            self.scan_ports(ip=format(host), ports=self.ports_to_scan)

    def scan_ports(self, ip, ports):
        for port in ports:
            threading.Thread(target=self.__check_port, args=[ip, port]).start()

    def __check_port(self, ip, port):
        # check tcp
        result = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = self.__check_connection(sock=sock, ip=ip, port=port) == 0
        except Exception:
            pass
        # check udp
        if not result:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.__check_connection(sock=sock, ip=ip, port=port)
            except Exception:
                pass

    def __check_connection(self, sock, ip, port):
        socket.setdefaulttimeout(2.0)  # seconds
        result = sock.connect_ex((ip, port))
        if result == 0:
            if port == 80 or port == 443:
                msg = self.get_service_name(host=ip, port=port)
                self.__lock.acquire()
                print(f'{ip} {port} OPEN{msg}', end='\n')
            else:
                self.__lock.acquire()
                print(f'{ip} {port} OPEN', end='\n')
            self.__lock.release()
        sock.close()
        return result

    @staticmethod
    def get_service_name(host, port, protocol='http'):
        if port == 80:
            protocol = 'http'
        elif port == 443:
            protocol = 'https'
        response = requests.get(f'{protocol}://{host}:{port}', verify=False)
        header = response.headers
        if 'server' in header.keys():
            service_name = response.headers.get('server')
            return f' {service_name}'

        return ''
