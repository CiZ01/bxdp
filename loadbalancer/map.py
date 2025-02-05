#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2018 Netronome Systems, Inc.

import csv
import sys


tmpfile = 'tmp_bpftool.txt' # batch map updates into a file for bpftool
stats_zero = '00 00 00 00 00 00 00 00' # initialize stats to (u64) zero

max_dest = 512
inputsaddr = "10.10.10.1"
try:
    dest_file = open("512dest.csv", 'r')
    dest_hosts = list(csv.reader(dest_file))
    dest_count = len(dest_hosts)
except:
    print("Error reading file")
    sys.exit(1)

if dest_count > max_dest:
    print("Warning: only the first %d destinations will be used" % max_dest)
else:
    print("Loading file with %d destinations" % dest_count)

batchfile = open(tmpfile, 'w')

# iterate through data in input file, if it contains less values than max_dest
# map will be filled as round robin
for key in range (0, max_dest):
    target_id = key % dest_count

    # bpftool requires data as individual bytes
    keyval1 = str(key & 0xFF)
    keyval2 = str(key >> 8)

    saddr = inputsaddr.split('.') # source IP for egress packets
    daddr = dest_hosts[target_id][0].split('.') # IP of the target server

    dmac_hex = dest_hosts[target_id][1].split(':') # MAC of the target server
    dmac = [str(int(byte, 16)) for byte in dmac_hex] # convert hex to integers

    # Fill in map using struct iptnl_info arrangement as specified in l4lb_xdp.c
    COMMAND = (['map update id', "0",
                'key', keyval1, keyval2, '00 00',
                'value', saddr[0], saddr[1], saddr[2], saddr[3],
                         daddr[0], daddr[1], daddr[2], daddr[3],
                         stats_zero, stats_zero,
                         dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
                         '00 00 \n'])
    COMMAND = ' '.join(COMMAND)
    batchfile.write(COMMAND)

batchfile.close()
# subprocess.check_output('bpftool batch file %s' % tmpfile, shell=True)