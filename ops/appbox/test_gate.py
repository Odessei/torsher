import subprocess
import unittest
from unittest.mock import patch

from gate import activity


class ActivityProbeTest(unittest.TestCase):
    @patch("gate.subprocess.run")
    def test_default_probe_uses_container_access_without_a_supplied_session(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, b'{"openStreams":0,"recentDevices":0}', b''),
            subprocess.CompletedProcess([], 0, b'{"event":"playback.playing"}\n', b''),
        ]
        self.assertEqual(activity(target="viewer"), {
            "openStreams": 0, "recentDevices": 0, "recentPlayback": True,
        })
        probe = run.call_args_list[0]
        self.assertEqual(probe.args[0][:8], (
            "docker", "exec", "-i", "--workdir", "/app", "viewer", "node", "--input-type=module",
        ))
        self.assertEqual(probe.kwargs["input"], b"")

    @patch("gate.subprocess.run")
    def test_explicit_session_remains_supported(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, b'{"openStreams":1,"recentDevices":2}', b''),
            subprocess.CompletedProcess([], 0, b'', b''),
        ]
        self.assertEqual(activity(b"fixture=session")["openStreams"], 1)
        self.assertEqual(run.call_args_list[0].kwargs["input"], b"fixture=session")

    @patch("gate.subprocess.run")
    def test_missing_activity_fails_closed(self, run):
        run.side_effect = subprocess.CalledProcessError(2, ["docker", "exec"])
        with self.assertRaises(subprocess.CalledProcessError):
            activity()
        self.assertEqual(run.call_count, 1)
