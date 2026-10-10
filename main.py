import time
from analyzer import Analyzer
from registry import registryMonitor

def main():
    print("=== Netowrk Monitor Daemon ===\n")

    registry = registryMonitor()
    analyzer = Analyzer(registry.queue)
    analyzer.start()
    registry.add_interface("en0", out_file="test_daemon.pcap")
    registry.start_all()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstop...")
        registry.stop_all()
        analyzer.stop()


if __name__ == "__main__":
    main()
