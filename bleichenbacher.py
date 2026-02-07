#!/usr/bin/env python3
# Run me like this:
# $ python3 bleichenbacher.py "eecs388+uniqname+100.00"
# or select "Bleichenbacher" from the VS Code debugger
from roots import *
import hashlib
import sys
def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]
    prefix = b'\x00\x01\xff\x00'
    asn1 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    # idea: generate prefix+asn1+hash, then do 256 - (prefix+asn1+hash) to find the number of garbage bytes we need
    forged = prefix + asn1 + hashlib.sha256(message.encode()).digest()
    # idea: instead of appending 0x00 as our YY garbage bytes,
    # we can append 0xFF because integer_nthroot returns the floor of the cube root,
    # so there's a possibility we can be slightly less when we go to cube it,
    # which ultimately changes our valid block (before the garbage bytes).
    # using 0xFF as padding bytes mitigates this so that we don't need to worry
    # about the difference between the valid and generated spilling into
    # our valid block
    # (comment serves to explain to partner incase I forget why I did this when I wake up) #
    forged += b'\xff' * (256 - len(forged))
    # now just convert it to an integer and take the cube root (e = 3)
    forged_signature, whole = integer_nthroot(bytes_to_integer(forged), 3)
    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))
if __name__ == '__main__':
    main()
