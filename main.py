from port_scanner import PortsScanner

if __name__ == '__main__':
    try:
        port_scanner = PortsScanner()
        port_scanner.run()
    except KeyboardInterrupt:
        pass
