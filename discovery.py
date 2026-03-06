from scapy.all import ARP, Ether, srp


def scan_network(network: str) -> list[dict]:
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered = srp(packet, timeout=2, verbose=False)[0]
    devices = []

    for _, received in answered:
        devices.append(
            {
                "ip": received.psrc,
                "mac": received.hwsrc,
            }
        )

    return devices


def print_results(devices: list[dict]) -> None:
    print("\nDiscovered Devices:\n")
    print(f"{'IP Address':<18}{'MAC Address'}")
    print("-" * 35)

    for device in sorted(devices, key=lambda x: tuple(map(int, x["ip"].split(".")))):
        print(f"{device['ip']:<18}{device['mac']}")


def main() -> None:
    print("Network Discovery Tool")
    network = input("Enter network range (example 10.0.0.0/24): ").strip()

    if not network:
        print("Error: network range cannot be empty.")
        return

    devices = scan_network(network)

    if devices:
        print_results(devices)
    else:
        print("No devices found.")


if __name__ == "__main__":
    main()
