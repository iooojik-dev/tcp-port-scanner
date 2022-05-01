import asyncio
import ipaddress
import re
import socket
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class PortsScanner:
    host = None
    mask = None
    ports_to_scan = []

    async def run(self):
        await self._get_input_data()
        await self._start_scan()

    async def _get_input_data(self):
        await self._get_ip()
        if self.host:
            if self.mask:
                await self.get_ports()
                if not self.ports_to_scan:
                    print('No ports')
            else:
                print('No mask')
                return
        else:
            print('No Host')

    async def get_ports(self):
        ports_input = input('Please provide ports to scan. For example: 80, 443, 442, 8443, 5555, 22, 21, 23\n')
        if len(re.findall(r'\d+', ports_input)) > 0:
            self.ports_to_scan = list(set([int(port) for port in re.findall('[0-9]+', ports_input)]))
        else:
            print('Error ', end='')

    async def _get_ip(self):
        ips_input = input('Please provide ip and mask. For example: 192.168.1.0/24\n')
        # ips_input = '192.168.1.0/24'
        if len(re.findall(r'\d+\.', ips_input)) > 0:
            ip_tpl = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3})", ips_input)
            if ip_tpl:
                self.host = ip_tpl[0][0]
                self.mask = ip_tpl[0][1]
        else:
            print('Error ', end='')

    async def _start_scan(self):
        print('Scan started...')
        tasks = []
        network = ipaddress.ip_network(f'{self.host}/{self.mask}', strict=False)
        network_address = network.network_address
        if network_address:
            tasks.append(asyncio.ensure_future(self.scan_ports(ip=format(network_address), ports=self.ports_to_scan)))
        broadcast_address = network.broadcast_address
        if broadcast_address and broadcast_address != network_address:
            tasks.append(asyncio.ensure_future(self.scan_ports(ip=format(broadcast_address), ports=self.ports_to_scan)))
        for host in list(network.hosts()):
            if format(host) != format(network_address) and format(host) != format(broadcast_address):
                tasks.append(asyncio.ensure_future(self.scan_ports(ip=format(host), ports=self.ports_to_scan)))
        await asyncio.wait(tasks)

    async def scan_ports(self, ip, ports):
        for port in ports:
            await self._check_connection(ip=ip, port=port)

    async def _check_connection(self, ip, port):
        sock_ = socket.socket()
        try:
            sock_.settimeout(5.0)
            sock_.connect((ip, port))
        except Exception:
            pass
        else:
            if port == 80 or port == 443:
                msg = self.get_service_name(host=ip, port=port)
                print(f'{ip} {port} OPEN{msg}')
            else:
                print(f'{ip} {port} OPEN')
        finally:
            sock_.close()

    @staticmethod
    def get_service_name(host, port,):
        protocol = 'https' if port == 443 else 'http'
        try:
            response = requests.get(f'{protocol}://{host}:{port}', verify=False, timeout=10,)
            header = response.headers
            if 'server' in header.keys():
                service_name = response.headers.get('server')
                return f' {service_name}'
        except Exception:
            pass
        return ''
