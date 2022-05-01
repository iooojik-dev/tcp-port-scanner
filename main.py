import asyncio

from port_scanner import PortsScanner

if __name__ == '__main__':
    try:
        port_scanner = PortsScanner()
        asyncio.get_event_loop().run_until_complete(port_scanner.run())
    except KeyboardInterrupt:
        pass
