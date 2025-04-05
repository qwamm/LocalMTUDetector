from winpcapy import WinPcapUtils, WinPcapDevices
import time
import threading

src_mac = ""
dst_mac = ""

def watching_timer(state):
    time.sleep(2)
    if not state['completed']:
        print("TIMEOUT")

def send_packet_with_reply_time_constraint(pattern, byte_num, callback, limit=1):
        frame_hex_template = "%(dst_mac)s%(src_mac)s" + byte_num * "dd"
        packet = frame_hex_template % {
            "src_mac": src_mac,
            "dst_mac": dst_mac
        }
        packet_buffer = bytes.fromhex(packet)
        state = {'completed': False}
        watchdog = threading.Thread(target=watching_timer, args=(state,))
        watchdog.daemon = True
        watchdog.start()
        start = time.time()
        WinPcapUtils.send_packet(pattern, packet_buffer, callback=callback, limit=limit)
        end = time.time()
        print(end - start)
        if end - start > 2:
            return 0
        state['completed'] = True
        return 1

def capture_packets_and_return(win_pcap, param, header, pkt_data):
    if pkt_data.hex()[24] == "d" and pkt_data.hex()[12:24] != src_mac:
        print(pkt_data.hex())
        frame_hex_template = "%(dst_mac)s%(src_mac)s" + "d" * (len(pkt_data.hex()) - 24)
        if len(pkt_data.hex()) - 24 < 1500:
            # 00 - ordinary frame flag
            frame_hex_template += "00"
        else:
            # 01 - jumbo frame flag
            frame_hex_template += "01"
        packet = frame_hex_template % {
            "dst_mac": pkt_data.hex()[12:24],
            "src_mac": pkt_data.hex()[:12]
        }
        packet_buffer = bytes.fromhex(packet)
        time.sleep(0.1)
        print(packet)
        win_pcap.send(packet_buffer)

def default_callback(win_pcap, param, header, pkt_data):
    print(pkt_data.hex())

def find_mtu_size_mode(device_name_pattern):
    num = int(input("Enter start size of frame:"))

    while num < 46:
        print("Too small size of frame. Please, enter bigger size:")
        num = int(input("Enter start size of frame:"))

    right = num
    left = 0

    max_sent = 0

    while True:
        if left == right:
            print(f"Max size of jumbo frame is {max_sent} bytes")
            break
        print(left, right, num, sep=" ")
        res = send_packet_with_reply_time_constraint(device_name_pattern, num, default_callback, 2)
        if res:
            if right == num and left == 0:
                print(f"Not a jumbo frame")
                break
            elif right - left == 1 and num == left:
                print(f"Max size of jumbo frame is {max_sent} bytes")
                break
            max_sent = max(max_sent, num)
            left = num
            num = (right + left) // 2
        else:
            print(f"Got exception with {num}")
            right = num
            num = (right + left) // 2

def capture_mode(device_name_pattern):
    WinPcapUtils.capture_on(device_name_pattern, capture_packets_and_return)

if __name__ == "__main__":
    print("Available devices:")
    print(WinPcapDevices.list_devices())
    print("Enter network adapter name (e.g. Ethernet, Realtek, Intel(R)..)")
    device = "*" + input() + "*"

    print("Enter source MAC address without \'-\' symbols:")
    src_mac = input()
    print("Enter destination MAC address without \'-\' symbols:")
    dst_mac = input()
    print("Choose mode (0 - Caprture packets and return them with a reply flag,"
          " 1 - Send requests in order to determine a MTU size that network supports)")
    mode = -1
    while True:
        try:
            mode = int(input())
            assert mode in [0, 1]
            break
        except ValueError:
            print("Invalid mode. Please, enter a relevant value.")
    if mode:
        find_mtu_size_mode(device)
    else:
        capture_mode(device)
