import ipaddress
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
    __lock = threading.Lock()

    def run(self):
        self._get_input_data()
        self._start_scan()

    def _get_input_data(self):
        self._get_ip()
        if self.host:
            if self.mask:
                self._get_ports()
                if not self.ports_to_scan:
                    print('No ports')
            else:
                print('No mask')
        else:
            print('No Host')

    def _get_ports(self):
        ports_input = \
            input('Please provide ports to scan. For example: 80, 443, 442, 8443, 5555, 22, 21, 23\n').replace(' ', '')
        if len(re.findall(r'[\d,]', ports_input)) > 0:
            self.ports_to_scan = list(set([int(port) for port in re.findall(r'\d+', ports_input)]))
            if len(self.ports_to_scan) > 0:
                return self.ports_to_scan
        print('Error ', end='')

    def _get_ip(self):
        ips_input = input('Please provide ip and mask. For example: 192.168.1.0/24\n').replace(' ', '')
        if len(re.findall(r'[a-zа-я\d\-]', ips_input)) > 0:
            ip_tpl = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3})", ips_input)
            if len(ip_tpl) > 0:
                self.host = ip_tpl[0][0]
                self.mask = ip_tpl[0][1]
                return self.host, self.mask
        print('Error ', end='')

    def _start_scan(self):
        if len(self.host) > 0 and len(self.ports_to_scan) > 0 and len(self.mask) > 0:
            print('Scan started...')
            network = ipaddress.ip_network(f'{self.host}/{self.mask}', strict=False)

            network_address = network.network_address
            if network_address is not None:
                self._scan_ports(ip=format(network_address), ports=self.ports_to_scan)

            broadcast_address = network.broadcast_address
            if broadcast_address is not None and broadcast_address != network_address:
                self._scan_ports(ip=format(broadcast_address), ports=self.ports_to_scan)

            for host in list(network.hosts()):
                if str(format(host)) != str(network_address) and str(format(host)) != str(broadcast_address):
                    while threading.active_count() > self.__max_threads:
                        time.sleep(1)
                    self._scan_ports(ip=format(host), ports=self.ports_to_scan)

    def _scan_ports(self, ip, ports):
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
                    msg = self._get_service_name(host=ip, port=port)
                    print(f'{ip} {port} OPEN{msg}')
                else:
                    print(f'{ip} {port} OPEN')
        finally:
            sock_.close()

    @staticmethod
    def _get_service_name(host, port, protocol='http'):
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
