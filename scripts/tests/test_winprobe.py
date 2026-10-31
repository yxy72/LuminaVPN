"""Opt-in native watchdog tests. No adapter, route, DNS or WFP mutations."""
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import unittest


@unittest.skipUnless(os.name == 'nt' and os.environ.get('NETLAUNCH_TEST_WINPROBE'),
                     'requires built Windows winprobe and elevated token')
class IndependentRecoveryTests(unittest.TestCase):
    def start_probe(self, *args):
        process = subprocess.Popen([os.environ['NETLAUNCH_TEST_WINPROBE'], 'idle',
                                    '--timeout', '4s', *args],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        self.addCleanup(self.stop_probe, process)
        lines = queue.Queue()
        threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        line = lines.get(timeout=12).strip()
        self.assertTrue(line, 'probe did not publish readiness')
        directory = Path(line)
        self.assertTrue((directory / 'probe-ready.json').exists())
        self.assertTrue((directory / 'recover.cmd').exists())
        return process, directory

    @staticmethod
    def stop_probe(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=12)

    def result(self, directory):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                result = json.loads((directory / 'probe-result.json').read_text())
                self.assertTrue(result['recovered'])
                journal = json.loads((directory / 'network.json').read_text())
                self.assertTrue(journal['stopping'])
                for key in ('routes', 'dns', 'addresses', 'mtu', 'guards', 'pairs'):
                    self.assertFalse(journal.get(key), 'idle probe changed network state')
                return result
            except FileNotFoundError:
                time.sleep(.05)
        self.fail('independent recovery did not publish success')

    def test_hard_deadline_terminates_stalled_owner(self):
        started = time.monotonic()
        process, directory = self.start_probe()
        process.wait(timeout=12)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.result(directory)['reason'], 'deadline')
        self.assertLess(time.monotonic() - started, 12)

    def test_owner_exit_recovers_without_parent(self):
        process, directory = self.start_probe('--exit-owner')
        self.assertEqual(process.wait(timeout=12), 0)
        self.assertEqual(self.result(directory)['reason'], 'owner_exited')

    def test_manual_recovery_then_repeat_without_session(self):
        process, directory = self.start_probe()
        command = [str(directory / 'winprobe.exe'), 'recover', '--run', directory.name]
        first = subprocess.run(command, capture_output=True, timeout=15)
        self.assertEqual(first.returncode, 0, first.stderr.decode(errors='replace'))
        process.wait(timeout=12)
        original = self.result(directory)
        self.assertTrue(original['recovered'])
        second = subprocess.run(['cmd.exe', '/d', '/c', str(directory / 'recover.cmd'), '/nopause'],
                                capture_output=True, timeout=15)
        self.assertEqual(second.returncode, 0, second.stderr.decode(errors='replace'))
        self.assertEqual(self.result(directory), original)


if __name__ == '__main__':
    unittest.main()
