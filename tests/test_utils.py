"""
Юнит-тесты для утилитарных функций.
"""
import unittest
from modules.utils import group_ips_into_subnets, parse_average_ping_time
import platform
from unittest.mock import patch

class TestUtils(unittest.TestCase):
    def test_group_ips_into_subnets_ipv4(self):
        ips = {"192.168.1.1", "192.168.1.2", "10.0.0.1"}
        subnets = group_ips_into_subnets(ips, "24")
        self.assertIn("192.168.1.0/24", subnets)
        self.assertIn("10.0.0.0/24", subnets)

    def test_group_ips_into_subnets_ipv6(self):
        ips = {"2001:db8::1"}
        subnets = group_ips_into_subnets(ips, "32")
        self.assertIn("2001:db8::1/128", subnets)

    def test_parse_average_ping_time_windows(self):
        output = "Minimum = 1ms, Maximum = 2ms, Average = 1ms"
        avg = parse_average_ping_time(output)
        self.assertEqual(avg, "1")

    def test_parse_average_ping_time_linux(self):
        linux_output = "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
        with patch('platform.system', return_value='Linux'):
            avg = parse_average_ping_time(linux_output)
        self.assertEqual(avg, "0.456")

if __name__ == "__main__":
    unittest.main()