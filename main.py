import _thread
from winpcapy import WinPcapUtils
import time, timeit
import threading


def watching_timer(state):
    time.sleep(2)
    if not state['completed']:
        print("TIMEOUT")

def send_packet_with_reply_time_constraint(pattern, byte_num, callback, limit=1):
        arp_request_hex_template = "%(dst_mac)s%(src_mac)s" + byte_num * "dd"
        packet = arp_request_hex_template % {
            "dst_mac": "a8a1592880c4",
            "src_mac": "d843aedc8285"
        }
        packet_buffer = bytes.fromhex(packet)
        while True:
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

# Example Callback function to parse IP packets
def packet_callback(win_pcap, param, header, pkt_data):
   print(pkt_data)

#if __name__ == "__main__":
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
        print(left, right, num, sep = " ")
        res = send_packet_with_reply_time_constraint("*Realtek*", num, packet_callback, 1)
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
            print (f"Got exception with {num}")
            right = num
            num = (right + left) // 2