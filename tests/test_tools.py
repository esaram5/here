import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
from usb_recovery.capture import FormatError, read_packets, decode_usb
from usb_recovery.analyze import analyze, collect, streams_from, compare_streams, load_source
from usb_recovery.simulate import Simulator, simulate


def usb(payload=b'', ep=1, complete=False, irp=1, status=0, transfer=3, stage=0, device=5):
    n = 28 if transfer == 2 else 27
    return struct.pack('<HQIHBHHBBI', n, irp, status, 9, int(complete), 1, device, ep, transfer, len(payload)) + (bytes([stage]) if transfer == 2 else b'') + payload


def pcap(packets, endian='<', nano=False, link=249):
    magic = b'\x4d\x3c\xb2\xa1' if nano else b'\xd4\xc3\xb2\xa1'
    if endian == '>': magic = magic[::-1]
    return magic + struct.pack(endian+'HHIIII',2,4,0,0,65535,link) + b''.join(struct.pack(endian+'IIII',100,i*100,len(p),len(p))+p for i,p in enumerate(packets))


def block(kind, body, e='<'):
    body += b'\0' * (-len(body)%4); n=len(body)+12
    return struct.pack(e+'II',kind,n)+body+struct.pack(e+'I',n)


def ng(packets,e='<',options=b'',simple=False):
    result=block(0x0a0d0d0a,struct.pack(e+'IHHq',0x1a2b3c4d,1,0,-1),e)
    result+=block(1,struct.pack(e+'HHI',249,0,65535)+options,e)
    for i,p in enumerate(packets):
        result+=block(3,struct.pack(e+'I',len(p))+p,e) if simple else block(6,struct.pack(e+'IIIII',0,0,1000+i,len(p),len(p))+p,e)
    return result

class CaptureTests(unittest.TestCase):
    def test_pcap_endian_nano(self):
        for e in ('<','>'):
            for nano in (False,True):
                p=list(read_packets(pcap([usb(b'A'),usb(b'B')],e,nano)))
                self.assertEqual(decode_usb(p[0]).payload,b'A')
                self.assertAlmostEqual(p[1].timestamp,100+100*(1e-9 if nano else 1e-6))
    def test_ng_endian_multisection(self):
        p=list(read_packets(ng([usb(b'A')])+ng([usb(b'B')],'>')))
        self.assertEqual([x.section for x in p],[0,1])
        self.assertEqual(decode_usb(p[1]).payload,b'B')
    def test_options(self):
        opts=struct.pack('<HH',9,1)+b'\x8a\0\0\0'+struct.pack('<HHq',14,8,-2)
        self.assertAlmostEqual(list(read_packets(ng([usb()],options=opts)))[0].timestamp,1000/1024-2)
    def test_simple(self):
        p=list(read_packets(ng([usb(b'A')],simple=True)))[0]
        self.assertIsNone(p.timestamp); self.assertEqual(decode_usb(p).payload,b'A')
    def test_malformed(self):
        good=ng([usb(b'A')])
        for bad in (good[:-1],good[:-4]+b'\0'*4,pcap([usb()])[:-1],b'bad'):
            with self.assertRaises(FormatError):list(read_packets(bad))
    def test_undefined_interface(self):
        with self.assertRaises(FormatError):list(read_packets(ng([])+block(6,struct.pack('<IIIII',3,0,1,0,0))))
    def test_phase_dedup(self):
        rows,_=collect(pcap([usb(b'ABC'),usb(b'ABC',complete=True),usb(ep=129,irp=2),usb(b'OK',ep=129,irp=2,complete=True)]))
        self.assertEqual(sorted(streams_from(rows)[0].values()),[b'ABC',b'OK'])
        self.assertEqual(rows[0]['paired_frame'],2);self.assertEqual(rows[3]['paired_frame'],3)
    def test_repeat_preserved(self):
        rows,_=collect(pcap([usb(b'A'),usb(complete=True),usb(b'A',irp=2),usb(complete=True,irp=2)]))
        self.assertEqual(list(streams_from(rows)[0].values()),[b'AA'])
    def test_failed_excluded(self):
        rows,_=collect(pcap([usb(b'A'),usb(complete=True,status=1),usb(b'B',ep=129,complete=True,irp=2,status=1)]))
        self.assertEqual(streams_from(rows)[0],{})
    def test_control_new(self):
        setup=bytes.fromhex('c001000000000200')
        rows,_=collect(pcap([usb(setup,transfer=2),usb(b'OK',ep=128,transfer=2,stage=3,complete=True)]))
        self.assertEqual(rows[0]['payload_hex'],'');self.assertEqual(rows[0]['direction'],'IN')
        self.assertEqual(rows[1]['setup_hex'],setup.hex());self.assertEqual(rows[1]['paired_frame'],1)
        self.assertEqual(streams_from(rows)[0],{})
    def test_control_old(self):
        rows,_=collect(pcap([usb(bytes.fromhex('4001000000000200'),transfer=2),usb(b'AB',transfer=2,stage=1),usb(transfer=2,stage=2,complete=True)]))
        self.assertEqual(rows[2]['paired_frame'],1);self.assertEqual(rows[1]['payload_hex'],'4142')
    def test_truncated(self):
        rows,_=collect(pcap([usb(b'ABC')[:-1]]));self.assertTrue(rows[0]['truncated']);self.assertFalse(rows[0]['selected'])
    def test_filter_and_nonusb(self):
        rows,_=collect(pcap([usb(b'A'),usb(b'B',device=6)]),bus=1,device=6);self.assertEqual(len(rows),1)
        rows,w=collect(pcap([b'network'],link=1));self.assertEqual(rows,[]);self.assertTrue(any('non-USBPcap' in x for x in w))
    def test_irp_reuse(self):
        rows,_=collect(pcap([usb(b'A'),usb(complete=True),usb(b'B'),usb(complete=True)]));self.assertEqual(rows[3]['paired_frame'],3)

class AnalysisTests(unittest.TestCase):
    def test_compare(self):
        r=compare_streams({'a':b'ABC','b':b'X'},{'a':b'AXC','c':b'Y'})
        self.assertEqual(r[0]['first_128_different_offsets'],[1]);self.assertEqual(r[1]['state'],'only_first')
    def test_zip_report(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);source=p/'r.zip'
            with zipfile.ZipFile(source,'w') as z:
                z.writestr('results/capture.pcapng',ng([usb(b'ABC'),usb(complete=True)]))
                z.writestr('results/observations.json','\ufeff'+json.dumps({'message':'이미 쓰여 있음'}))
                z.writestr('../../escape.txt','ignored')
            r=analyze(source,p/'out');self.assertEqual(r['usb_frames'],2)
            self.assertEqual(next((p/'out'/'streams').glob('*.bin')).read_bytes(),b'ABC')
            self.assertFalse((p/'escape.txt').exists())
            with self.assertRaises(FileExistsError):analyze(source,p/'out')
    def test_duplicate_capture(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'r.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('a.pcap',pcap([]));z.writestr('b.pcap',pcap([]))
            with self.assertRaises(FormatError):load_source(p)
    def test_metadata_only(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'in').mkdir();r=analyze(p/'in',p/'out')
            self.assertEqual(r['usb_frames'],0);self.assertIn('metadata-only',r['warnings'][0])
    def test_marker(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'c.pcap').write_bytes(pcap([usb(b'A'),usb(b'B',irp=2)]))
            r=analyze(p/'c.pcap',p/'out',marker=0);self.assertEqual(r['candidate_tail_frames'],[1])

class SimulatorTests(unittest.TestCase):
    def setUp(self):self.rules=json.loads((Path(__file__).resolve().parents[1]/'examples/toy_rules.json').read_text())
    def test_echo_save(self):
        m=Simulator(self.rules);self.assertEqual(m.step(b'\x10')['response_hex'],'9000')
        self.assertEqual(m.step(bytes.fromhex('200248454c4c'))['response_hex'],'9102')
        m.step(b'\x30');self.assertEqual(m.saved,b'HELL');self.assertEqual(m.state,'done')
    def test_wrong_order(self):
        m=Simulator(self.rules)
        with self.assertRaises(ValueError):m.step(b'\x30')
        self.assertEqual(m.state,'idle')
    def test_ambiguous(self):
        self.rules['rules'].append(self.rules['rules'][0].copy())
        with self.assertRaises(ValueError):Simulator(self.rules).step(b'\x10')
    def test_bad_mask(self):
        self.rules['rules'][0]['mask_hex']='ffff'
        with self.assertRaises(ValueError):Simulator(self.rules)
    def test_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):simulate(self.rules,['10'],Path(d)/'out')

if __name__=='__main__':unittest.main()
