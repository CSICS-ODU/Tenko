#Check if cython code has been compiled
import os
import subprocess
import time

use_extrapolation=False #experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"): #has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd,shell=True)
#Import dependencies
import netStat as ns
import csv
import numpy as np
print("Importing Scapy Library")
from scapy.all import *
import os.path
import platform
import subprocess
import pdb

# dpkt: fast C-extension packet parser (preferred for pcap path)
try:
    import dpkt as _dpkt
    import socket as _socket
    _HAS_DPKT = True
except ImportError:
    _HAS_DPKT = False

PCAP_FILE = "dataset/Mirai/Mirai_pcap.pcap"


def _parse_dpkt(ts, buf):
    """Parse a raw pcap frame with dpkt.  Returns same tuple as Scapy path."""
    try:
        eth = _dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    framelen = len(buf)
    timestamp = ts
    try:
        srcMAC = ':'.join('%02x' % b for b in eth.src)
        dstMAC = ':'.join('%02x' % b for b in eth.dst)
    except Exception:
        srcMAC = dstMAC = ''

    srcIP = dstIP = srcproto = dstproto = ''
    IPtype = np.nan

    ip_layer = eth.data
    if isinstance(ip_layer, _dpkt.ip.IP):
        IPtype = 0
        try:
            srcIP = _socket.inet_ntoa(ip_layer.src)
            dstIP = _socket.inet_ntoa(ip_layer.dst)
        except Exception:
            pass
        transport = ip_layer.data
        if isinstance(transport, _dpkt.tcp.TCP):
            srcproto = str(transport.sport)
            dstproto = str(transport.dport)
        elif isinstance(transport, _dpkt.udp.UDP):
            srcproto = str(transport.sport)
            dstproto = str(transport.dport)
        elif isinstance(transport, _dpkt.icmp.ICMP):
            srcproto = dstproto = 'icmp'
    elif isinstance(ip_layer, _dpkt.ip6.IP6):
        IPtype = 1
        try:
            srcIP = _socket.inet_ntop(_socket.AF_INET6, ip_layer.src)
            dstIP = _socket.inet_ntop(_socket.AF_INET6, ip_layer.dst)
        except Exception:
            pass
        transport = ip_layer.data
        if isinstance(transport, _dpkt.tcp.TCP):
            srcproto = str(transport.sport)
            dstproto = str(transport.dport)
        elif isinstance(transport, _dpkt.udp.UDP):
            srcproto = str(transport.sport)
            dstproto = str(transport.dport)
    elif isinstance(ip_layer, _dpkt.arp.ARP):
        IPtype = 0
        srcproto = dstproto = 'arp'
        try:
            srcIP = _socket.inet_ntoa(ip_layer.spa)
            dstIP = _socket.inet_ntoa(ip_layer.tpa)
        except Exception:
            pass

    if srcproto == '' and srcIP == '':
        srcIP = srcMAC
        dstIP = dstMAC

    return timestamp, framelen, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, IPtype


#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
# If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time
class FE:
    def __init__(self,file_path,limit=np.inf):
        self.path = file_path
        self.limit = limit
        self.parse_type = None #unknown
        self.curPacketIndx = 0
        self.tsvin = None #used for parsing TSV file
        self.scapyin = None #used for parsing pcap with scapy
        self._dpkt_f = None   # file handle for dpkt streaming reader
        self._dpkt_reader = None
        
        ### Prep pcap ##
        self.__prep__()
        
        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def _get_tshark_path(self):
        if platform.system() == 'Windows':
            return 'C:\\Users\\s1banerj\\Downloads\\WiresharkPortable\\App\\Wireshark\\tshark.exe'
            #'C:\\Program Files\\Wireshark\\tshark.exe'
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''

    def __prep__(self):
        ### Find file: ###
        if not os.path.isfile(self.path):  # file does not exist
            print("File: " + self.path + " does not exist")
            raise Exception()

        ### check file type ###
        type = self.path.split('.')[-1]

        self._tshark = self._get_tshark_path()
        ##If file is TSV (pre-parsed by wireshark script)
        if type == "tsv":
            self.parse_type = "tsv"

        ##If file is pcap
        elif type == "pcap" or type == 'pcapng':
            # Prefer dpkt for per-packet streaming (fast and no pre-loading)
            if _HAS_DPKT and not os.environ.get("FE_FORCE_SCAPY"):
                print("Using dpkt for pcap parsing (fast path)...")
                self.parse_type = "dpkt"
            # Try parsing via tshark dll of wireshark (still fast if available)
            elif os.path.isfile(self._tshark):
                self.pcap2tsv_with_tshark()  # creates local tsv file
                self.path += ".tsv"
                self.parse_type = "tsv"
            else: # Fall back to Scapy (slower)
                print("tshark not found. Trying scapy...")
                self.parse_type = "scapy"
        else:
            print("File: " + self.path + " is not a tsv or pcap file")
            raise Exception()

        ### open readers ##
        if self.parse_type == "tsv":
            maxInt = sys.maxsize
            decrement = True
            while decrement:
                # decrease the maxInt value by factor 10
                # as long as the OverflowError occurs.
                decrement = False
                try:
                    csv.field_size_limit(maxInt)
                except OverflowError:
                    maxInt = int(maxInt / 10)
                    decrement = True

            print("counting lines in file...")
            num_lines = sum(1 for line in open(self.path))
            print("There are " + str(num_lines) + " Packets.")
            self.limit = min(self.limit, num_lines-1)
            self.tsvinf = open(self.path, 'rt', encoding="utf8")
            self.tsvin = csv.reader(self.tsvinf, delimiter='\t')
            row = self.tsvin.__next__() #move iterator past header

        elif self.parse_type == "dpkt":
            # Detect pcap vs pcapng by magic bytes
            with open(self.path, 'rb') as _mf:
                _magic = _mf.read(4)
            self._is_pcapng = (_magic == b'\x0a\x0d\x0d\x0a')

            def _make_reader(fh):
                if self._is_pcapng:
                    return _dpkt.pcapng.Reader(fh)
                return _dpkt.pcap.Reader(fh)

            print("Counting packets in pcap/pcapng (dpkt)...")
            n_pkts = sum(1 for _ in _make_reader(open(self.path, 'rb')))
            print(f"There are {n_pkts} Packets.")
            self.limit = min(self.limit, n_pkts)
            self._dpkt_f = open(self.path, 'rb')
            self._dpkt_reader = iter(_make_reader(self._dpkt_f))
            self._dpkt_make_reader = _make_reader

        else: # scapy
            print("Reading PCAP file via Scapy...")
            self.scapyin = rdpcap(self.path)
            self.limit = len(self.scapyin)
            print("Loaded " + str(len(self.scapyin)) + " Packets.")

    def get_next_vector(self, timings=None):
        """
        timings: optional dict with keys 'parse' and 'afterimage' — lists that
                 receive per-packet latency in milliseconds when provided.
        """
        if self.curPacketIndx == self.limit:
            if self.parse_type == 'tsv':
                self.tsvinf.close()
            elif self.parse_type == 'dpkt' and self._dpkt_f:
                self._dpkt_f.close()
            return []

        ### Parse next packet ###
        if self.parse_type == "tsv":
            t0 = time.perf_counter()
            row = self.tsvin.__next__()
            IPtype = np.nan
            timestamp = row[0]
            framelen = row[1]
            srcIP = ''
            dstIP = ''
            if row[4] != '':  # IPv4
                srcIP = row[4]
                dstIP = row[5]
                IPtype = 0
            elif row[17] != '':  # ipv6
                srcIP = row[17]
                dstIP = row[18]
                IPtype = 1
            srcproto = row[6] + row[8]  # UDP or TCP port
            dstproto = row[7] + row[9]  # UDP or TCP port
            srcMAC = row[2]
            dstMAC = row[3]
            if srcproto == '':  # it's a L2/L1 level protocol
                if row[12] != '':  # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = row[14]  # src IP (ARP)
                    dstIP = row[16]  # dst IP (ARP)
                    IPtype = 0
                elif row[10] != '':  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = row[2]  # src MAC
                    dstIP = row[3]  # dst MAC
            t1 = time.perf_counter()

        elif self.parse_type == "dpkt":
            t0 = time.perf_counter()
            try:
                ts, buf = next(self._dpkt_reader)
            except StopIteration:
                return []
            parsed = _parse_dpkt(ts, buf)
            t1 = time.perf_counter()
            if parsed is None:
                self.curPacketIndx += 1
                if timings is not None:
                    timings['parse'].append((t1 - t0) * 1000.0)
                    timings['afterimage'].append(0.0)
                return []
            timestamp, framelen, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, IPtype = parsed

        elif self.parse_type == "scapy":
            t0 = time.perf_counter()
            packet = self.scapyin[self.curPacketIndx]
            IPtype = np.nan
            timestamp = packet.time
            framelen = len(packet)
            if packet.haslayer(IP):  # IPv4
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
                IPtype = 0
            elif packet.haslayer(IPv6):  # ipv6
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
                IPtype = 1
            else:
                srcIP = ''
                dstIP = ''

            if packet.haslayer(TCP):
                srcproto = str(packet[TCP].sport)
                dstproto = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                srcproto = str(packet[UDP].sport)
                dstproto = str(packet[UDP].dport)
            else:
                srcproto = ''
                dstproto = ''

            srcMAC = packet.src
            dstMAC = packet.dst
            if srcproto == '':  # it's a L2/L1 level protocol
                if packet.haslayer(ARP):  # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = packet[ARP].psrc  # src IP (ARP)
                    dstIP = packet[ARP].pdst  # dst IP (ARP)
                    IPtype = 0
                elif packet.haslayer(ICMP):  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = packet.src  # src MAC
                    dstIP = packet.dst  # dst MAC
            t1 = time.perf_counter()
        else:
            return []

        self.curPacketIndx = self.curPacketIndx + 1

        if timings is not None:
            timings['parse'].append((t1 - t0) * 1000.0)

        ### Extract Features (AfterImage)
        try:
            t_ai0 = time.perf_counter()
            feat = self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp))
            t_ai1 = time.perf_counter()
            if timings is not None:
                timings['afterimage'].append((t_ai1 - t_ai0) * 1000.0)
            return [feat, srcIP]
        except Exception as e:
            print(e)
            if timings is not None:
                timings['afterimage'].append(0.0)
            return []


    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
        cmd =  '"' + self._tshark + '" -r '+ self.path +' -T fields '+ fields +' -E header=y -E occurrence=f > '+self.path+".tsv"
        subprocess.call(cmd,shell=True)
        print("tshark parsing complete. File saved as: "+self.path +".tsv")

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
