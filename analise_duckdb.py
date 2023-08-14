import duckdb
import pyshark

"""
cursor = duckdb.read_csv('output.csv')

print(duckdb.sql("SELECT ip_proto,ip_src,ip_dst,tcp_srcport,tcp_dstport FROM cursor WHERE tcp_srcport = '6060' or tcp_dstport = '6060' "))
"""


capture = pyshark.LiveCapture(interface='eno1', bpf_filter='tcp port 6060')
capture.sniff(timeout=10)

for packet in capture:
    print(packet)
