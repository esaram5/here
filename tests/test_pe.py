from pathlib import Path
import struct
import tempfile
import unittest
from usb_recovery.pe import PE,inspect_pe
from usb_recovery.capture import FormatError


def make_pe(bits=32,managed=False):
    data=bytearray(0x800);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0';size=240 if bits==64 else 224
    struct.pack_into('<HHIIIHH',data,0x84,0x8664 if bits==64 else 0x14c,1,0,0,0,size,0x102)
    opt=0x98;struct.pack_into('<H',data,opt,0x20b if bits==64 else 0x10b)
    struct.pack_into('<I',data,opt+16,0x1000)
    struct.pack_into('<Q' if bits==64 else '<I',data,opt+(24 if bits==64 else 28),0x140000000 if bits==64 else 0x400000)
    struct.pack_into('<II',data,opt+32,0x1000,0x200)
    struct.pack_into('<II',data,opt+56,0x2000,0x200)
    directory=opt+(112 if bits==64 else 96)
    struct.pack_into('<I',data,directory-4,16)
    struct.pack_into('<II',data,directory+8,0x1100,40)
    if managed:struct.pack_into('<II',data,directory+14*8,0x1500,72)
    sec=opt+size;data[sec:sec+8]=b'.rdata\0\0'
    struct.pack_into('<IIII',data,sec+8,0x600,0x1000,0x600,0x200)
    struct.pack_into('<I',data,sec+36,0x40000040)
    struct.pack_into('<IIIII',data,0x300,0x1200,0,0,0x1180,0x1240)
    data[0x380:0x380+11]=b'winusb.dll\0'
    fmt='<Q' if bits==64 else '<I'
    struct.pack_into(fmt,data,0x400,0x1280);struct.pack_into(fmt,data,0x440,0x1280)
    data[0x480:0x480+19]=b'\0\0WinUsb_WritePipe\0'
    msg='이미 쓰여 있음'.encode('utf-16le');data[0x600:0x600+len(msg)]=msg
    return bytes(data)


class PETests(unittest.TestCase):
    def test_pe32_pe64(self):
        for bits in (32,64):
            pe=PE(make_pe(bits));self.assertEqual(pe.bits,bits)
            imp=pe.imports();self.assertEqual(imp[0]['dll'],'winusb.dll')
            self.assertEqual(imp[0]['name'],'WinUsb_WritePipe');self.assertEqual(imp[0]['iat_rva'],0x1240)
    def test_ordinal(self):
        data=bytearray(make_pe());struct.pack_into('<I',data,0x400,0x80000012)
        self.assertEqual(PE(data).imports()[0]['name'],'#18')
    def test_iat_fallback(self):
        data=bytearray(make_pe());struct.pack_into('<I',data,0x300,0)
        self.assertEqual(PE(data).imports()[0]['name'],'WinUsb_WritePipe')
    def test_unmapped_rva(self):
        with self.assertRaises(FormatError):PE(make_pe()).rva_offset(0x9000)
    def test_malformed_headers(self):
        for raw in (b'MZ',make_pe()[:0x100],b'bad'):
            with self.assertRaises(FormatError):PE(raw)
    def test_report_managed_keyword(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'a.exe').write_bytes(make_pe(managed=True))
            r=inspect_pe(p/'a.exe',p/'out',['이미 쓰여 있음'])
            self.assertTrue(r['clr_directory_present']);self.assertIn('ILSpy',r['suggested_route'])
            self.assertEqual(r['api_groups']['winusb'],['WinUsb_WritePipe'])
            self.assertTrue(any(x['file_offset']==0x600 and x['rva']==0x1400 for x in r['string_hits']))
    def test_bad_import_report_warning(self):
        data=bytearray(make_pe());struct.pack_into('<I',data,0x300,0x9000)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'a.exe').write_bytes(data)
            r=inspect_pe(p/'a.exe',p/'out');self.assertEqual(r['imports'],[]);self.assertTrue(r['warnings'])
    def test_delay_import_warning(self):
        data=bytearray(make_pe());struct.pack_into('<II',data,0x98+96+13*8,0x1500,32)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'a.exe').write_bytes(data)
            self.assertTrue(any('Delay imports' in x for x in inspect_pe(p/'a.exe',p/'out')['warnings']))

if __name__=='__main__':unittest.main()
