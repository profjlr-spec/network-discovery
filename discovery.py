from scapy.all import ARP, Ether, srp


def get_vendor(mac: str) -> str:
    oui = mac.upper()[0:8]

    vendor_map = {
        "F8:79:0A": "Arris",
        "BC:09:1B": "Apple / Device Vendor",
        "18:B4:30": "Google / Nest / Device Vendor",
        "7C:27:BC": "Samsung / Device Vendor",
    }

    return vendor_map.get(oui, "Unknown")


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
                "vendor": get_vendor(received.hwsrc),
            }
        )

    return devices


def print_results(devices: list[dict]) -> None:
    print("\nDiscovered Devices:\n")
    print(f"{'IP Address':<18}{'MAC Address':<20}{'Vendor'}")
    print("-" * 60)

    for device in sorted(devices, key=lambda x: tuple(map(int, x["ip"].split(".")))):
        print(f"{device['ip']:<18}{device['mac']:<20}{device['vendor']}")


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
