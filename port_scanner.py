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
    __max_threads = 100
    __queue_output = queue.Queue()
    __lock = threading.Lock()

    def __init__(self):
        self.get_input_data()

    def get_input_data(self):
        self.get_ip()
        if len(self.host) > 0:
            if len(self.mask) > 0:
                self.get_ports()
                if len(self.host) > 0 and len(self.mask) > 0 and len(self.ports_to_scan) > 0:
                    return
                else:
                    print('No ports')
                    return
            else:
                print('No mask')
                return
        else:
            print('No Host')
            return

    def get_ports(self):
        ports_input = input('Please provide ports to scan. For example: 80, 443, 442, 8443, 5555, 22, 21, 23\n').replace(' ', '')
        if len(ports_input) > 0:
            self.ports_to_scan = list(set([int(port) for port in re.findall('[0-9]+', ports_input)]))
            if len(self.ports_to_scan) > 0:
                return self.ports_to_scan
        print('Error ', end='')

    def get_ip(self):
        ips_input = input('Please provide ip and mask. For example: 192.168.1.0/24\n').replace(' ', '')
        if len(ips_input) > 0:
            ip_tpl = re.findall(r"([0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}/[0-9]{,3})", ips_input)
            if len(ip_tpl) > 0:
                self.host = ip_tpl[0].split('/')[0]
                self.mask = ip_tpl[0].split('/')[1]
                return self.host, self.mask
        print('Error ', end='')

    def start_scan(self):
        if len(self.host) > 0 and len(self.ports_to_scan) > 0 and len(self.mask) > 0:
            print('Scan started...')
            network = ipaddress.ip_network(f'{self.host}/{self.mask}', strict=False)
            network_address = network.network_address
            if network_address is not None:
                self.scan_ports(ip=format(network_address), ports=self.ports_to_scan)

            broadcast_address = network.broadcast_address
            if broadcast_address is not None and broadcast_address != network_address:
                self.scan_ports(ip=format(broadcast_address), ports=self.ports_to_scan)

            for host in list(network.hosts()):
                if str(format(host)) != str(network_address) and str(format(host)) != str(broadcast_address):
                    while threading.active_count() > self.__max_threads:
                        time.sleep(1)
                    self.scan_ports(ip=format(host), ports=self.ports_to_scan)

    def scan_ports(self, ip, ports):
        for port in ports:
            t = threading.Thread(target=self.__check_connection, args=[ip, port])
            t.start()

    def __check_connection(self, ip, port):
        sock_ = socket.socket()
        try:
            sock_.settimeout(5.0)  # seconds
            sock_.connect((ip, port))
        except Exception:
            pass
        else:
            with self.__lock:
                if port == 80 or port == 443:
                    msg = self.get_service_name(host=ip, port=port)
                    print(f'{ip} {port} OPEN{msg}')
                else:
                    print(f'{ip} {port} OPEN')
        finally:
            sock_.close()

    @staticmethod
    def get_service_name(host, port, protocol='http'):
        if port == 80:
            protocol = 'http'
        elif port == 443:
            protocol = 'https'
        try:
            response = requests.get(f'{protocol}://{host}:{port}', verify=False)
            header = response.headers
            if 'server' in header.keys():
                service_name = response.headers.get('server')
                return f' {service_name}'
        except Exception:
            pass

        return ''
