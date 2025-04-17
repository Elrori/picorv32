#!/usr/bin/env python3
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.

from sys import argv

binfile = argv[1]
nwords = int(argv[2])
format = argv[3]

with open(binfile, "rb") as f:
    bindata = f.read()

assert len(bindata) < 4*nwords
assert len(bindata) % 4 == 0
if format == 'hex' or format == 'txt':
    for i in range(nwords):
        if i < len(bindata) // 4:
            w = bindata[4*i : 4*i+4]
            print("%02x%02x%02x%02x" % (w[3], w[2], w[1], w[0]))
        else:
            print("00000000")
elif format == 'mif':
    print("DEPTH=%d;" % nwords, end='\r\n')
    print("WIDTH=32;", end='\r\n')
    print("ADDRESS_RADIX=UNS;", end='\r\n')
    print("DATA_RADIX=HEX;", end='\r\n')
    print("CONTENT 	 BEGIN", end='\r\n')
    for i in range(nwords):
        if i < len(bindata) // 4:
            w = bindata[4*i : 4*i+4]
            print("%d:%02x%02x%02x%02x;" % (i, w[3], w[2], w[1], w[0]), end='\r\n')
        else:
            print("%d:00000000;" % i, end='\r\n')
    print("END;", end='')
else:
    exit()
