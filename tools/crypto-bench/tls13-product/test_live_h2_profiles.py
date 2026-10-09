#!/usr/bin/env python3
"""Current h2 hello recognition must not widen either cryptographic profile."""
import importlib.util
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m)
    return m

F=load('h2_floor_wire',HERE.parent/'tls13-poc/live_k15_pcap.py')
C=load('h2_conforming_wire',HERE/'live_286_pcap.py')

class Profiles(unittest.TestCase):
    def test_8088_fresh_and_resumed(self):
        for resumed in (False,True):
            hello=F._fixture_client_hello(bytes(range(32)),resumed=resumed,alpn_h2=True)
            parsed=F.parse_client_hello(hello)
            self.assertEqual(parsed['alpn'],'h2')
            self.assertIsNone(parsed['record_size_limit'])
            self.assertFalse(parsed['early_data'])
            self.assertEqual(parsed['profile'],'resumed' if resumed else 'fresh')
            with self.assertRaises(ValueError):F.parse_client_hello(hello.replace(b'\x02h2',b'\x02h3'))
            with self.assertRaises(ValueError):C.parse_client_hello(hello)
    def test_286_fresh_and_resumed(self):
        order=(0,43,10,13,51,16,21,45)
        for resumed in (False,True):
            hello=C.fixture_client_hello(13,resumed=resumed,extension_order=order+((41,) if resumed else ()))
            parsed=C.parse_client_hello(hello)
            self.assertEqual(parsed['alpn'],'h2')
            self.assertIsNone(parsed['record_size_limit'])
            self.assertFalse(parsed['early_data_offered'])
            self.assertEqual(parsed['hello_profile'],'resumption' if resumed else 'acquisition')
            with self.assertRaises(ValueError):C.parse_client_hello(hello.replace(b'\x02h2',b'\x02h3'))
            with self.assertRaises(ValueError):F.parse_client_hello(hello)
    def test_286_maximum_ticket_is_discovered(self):
        order=(0,43,10,13,51,16,21,45,41)
        hello=C.fixture_client_hello(13,resumed=True,extension_order=order,
                                     ticket_identity=b't'*C.MAX_TICKET_IDENTITY_BYTES)
        self.assertTrue(C.is_286_candidate(hello))
        self.assertEqual(C.parse_client_hello(hello)['alpn'],'h2')

if __name__=='__main__':unittest.main()
