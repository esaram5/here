"""Generate synthetic USBPcap data only. No real device protocol is implied."""
import argparse
from pathlib import Path
import struct


def usb(payload, ep, irp, done):
    return struct.pack('<HQIHBHHBBI',27,irp,0,9,int(done),1,5,ep,3,len(payload))+payload


def main():
    p=argparse.ArgumentParser();p.add_argument('output');args=p.parse_args()
    # Status OUT, status IN, then a synthetic data block OUT and completion.
    packets=[usb(b'\x10',1,1,False),usb(b'',1,1,True),usb(b'',129,2,False),
             usb(b'\x90\x01',129,2,True),usb(b'DEMO_DATA_ONLY',1,3,False),usb(b'',1,3,True)]
    raw=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,249)
    for i,packet in enumerate(packets):raw+=struct.pack('<IIII',100,i*1000,len(packet),len(packet))+packet
    with Path(args.output).open('xb') as f:f.write(raw)
    print('Synthetic example written:',args.output)

if __name__=='__main__':main()
