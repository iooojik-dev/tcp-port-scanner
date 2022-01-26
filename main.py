from port_scanner import PortsScanner

try:
    port_scanner = PortsScanner()
    port_scanner.start_scan()
except KeyboardInterrupt:
    pass
