import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fi_country_transaction import switch, OLD, NEW
class Fake:
    def __init__(self,failure=None,restore_failure=False):
        self.live={OLD};self.boot={OLD};self.marker=False
        self.failure=failure;self.restore_failure=restore_failure;self.fired=False
    def step(self,name):
        if name==self.failure and not self.fired:
            self.fired=True;raise RuntimeError(name)
    def preflight(self): self.step('preflight')
    def mark(self): self.marker=True;self.step('mark')
    def unmark(self): self.marker=False
    def stop(self,u): self.live.discard(u);self.step('stop:'+u)
    def start(self,u):
        if u==OLD and self.restore_failure:raise RuntimeError('restore')
        self.live.add(u);self.step('start:'+u)
    def enable(self,u): self.boot.add(u);self.step('enable:'+u)
    def disable(self,u): self.boot.discard(u);self.step('disable:'+u)
    def verify_candidate(self):
        assert self.live=={NEW} and self.boot=={OLD} and self.marker
        self.step('verify_candidate')
    def verify_commit(self):
        assert self.live==self.boot=={NEW} and self.marker
        self.step('verify_commit')
    def verify_restore(self):
        assert self.live==self.boot=={OLD} and not self.marker
class Transition(unittest.TestCase):
    def test_success(self):
        x=Fake();switch(x);self.assertEqual(x.live,{NEW});self.assertEqual(x.boot,{NEW});self.assertTrue(x.marker)
    def test_preflight(self):
        x=Fake('preflight')
        with self.assertRaises(RuntimeError):switch(x)
        self.assertEqual(x.live,{OLD});self.assertEqual(x.boot,{OLD});self.assertFalse(x.marker)
    def test_each_failure(self):
        for failure in ('mark','stop:'+OLD,'start:'+NEW,'verify_candidate','enable:'+NEW,'disable:'+OLD,'verify_commit'):
            with self.subTest(failure=failure):
                x=Fake(failure)
                with self.assertRaises(RuntimeError):switch(x)
                self.assertEqual(x.live,{OLD});self.assertEqual(x.boot,{OLD});self.assertFalse(x.marker)
    def test_restore_failure(self):
        with self.assertRaisesRegex(RuntimeError,'FI_COUNTRY_ROLLBACK_UNCONFIRMED'):switch(Fake('verify_candidate',True))
    def test_interrupt(self):
        x=Fake()
        def interrupted():raise KeyboardInterrupt()
        x.verify_candidate=interrupted
        with self.assertRaises(KeyboardInterrupt):switch(x)
        self.assertEqual(x.live,{OLD});self.assertEqual(x.boot,{OLD});self.assertFalse(x.marker)
if __name__=='__main__':unittest.main()
