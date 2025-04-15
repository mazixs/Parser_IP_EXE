"""
Юнит-тесты для модуля config.py.
"""
import unittest
import os
from modules.config import read_config, ConfigError

class TestConfig(unittest.TestCase):
    def setUp(self):
        self.valid_config = """
[Processes]
exe_list = ["test1.exe", "test2.exe"]
[Output]
ip_file = "ip.txt"
keenetic_file = "keenetic.bat"
ping_file = "ping.log"
domain_file = "domain.txt"
[Ping]
enable_ping = 1
[Threading]
max_ping_threads = 2
max_active_tasks = 4
ping_delay = 0.5
ping_interval = 600
[Domain]
enable_domain_tracking = 1
[Subnet]
mask = "32"
"""
        self.config_path = "test_config.toml"
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(self.valid_config)

    def tearDown(self):
        if os.path.exists(self.config_path):
            os.remove(self.config_path)

    def test_read_valid_config(self):
        result = read_config(self.config_path)
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[0], ["test1.exe", "test2.exe"])
        self.assertEqual(result[5], "32")
        self.assertEqual(result[6], 1)

    def test_missing_config_file(self):
        with self.assertRaises(ConfigError):
            read_config("nonexistent.toml")

if __name__ == "__main__":
    unittest.main()