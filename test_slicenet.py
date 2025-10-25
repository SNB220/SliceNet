#!/usr/bin/env python3
"""
Test suite for SliceNet - IP Subnet Calculator
Run with: python test_slicenet.py
"""

import unittest
import sys
from slicenet import SubnetCalculator, IPv6Calculator


class TestSubnetCalculator(unittest.TestCase):
    """Test cases for SubnetCalculator class."""
    
    def test_basic_cidr_notation(self):
        """Test basic calculation with CIDR notation."""
        calc = SubnetCalculator('145.71.55.1', '/18')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '145.71.0.0')
        self.assertEqual(results['subnet_mask'], '255.255.192.0 (/18)')
        self.assertEqual(results['first_host'], '145.71.0.1')
        self.assertEqual(results['last_host'], '145.71.63.254')
        self.assertEqual(results['broadcast'], '145.71.63.255')
        self.assertEqual(results['total_hosts'], 16384)
        self.assertEqual(results['usable_hosts'], 16382)
    
    def test_decimal_subnet_mask(self):
        """Test calculation with decimal subnet mask."""
        calc = SubnetCalculator('145.71.64.0', '255.255.255.128')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '145.71.64.0')
        self.assertEqual(results['subnet_mask'], '255.255.255.128 (/25)')
        self.assertEqual(results['first_host'], '145.71.64.1')
        self.assertEqual(results['last_host'], '145.71.64.126')
        self.assertEqual(results['broadcast'], '145.71.64.127')
        self.assertEqual(results['total_hosts'], 128)
        self.assertEqual(results['usable_hosts'], 126)
    
    def test_class_c_network(self):
        """Test standard Class C network (/24)."""
        calc = SubnetCalculator('192.168.1.100', '24')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '192.168.1.0')
        self.assertEqual(results['subnet_mask'], '255.255.255.0 (/24)')
        self.assertEqual(results['first_host'], '192.168.1.1')
        self.assertEqual(results['last_host'], '192.168.1.254')
        self.assertEqual(results['broadcast'], '192.168.1.255')
        self.assertEqual(results['usable_hosts'], 254)
    
    def test_class_b_network(self):
        """Test standard Class B network (/16)."""
        calc = SubnetCalculator('172.16.100.50', '/16')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '172.16.0.0')
        self.assertEqual(results['subnet_mask'], '255.255.0.0 (/16)')
        self.assertEqual(results['first_host'], '172.16.0.1')
        self.assertEqual(results['last_host'], '172.16.255.254')
        self.assertEqual(results['broadcast'], '172.16.255.255')
        self.assertEqual(results['total_hosts'], 65536)
        self.assertEqual(results['usable_hosts'], 65534)
    
    def test_class_a_network(self):
        """Test standard Class A network (/8)."""
        calc = SubnetCalculator('10.5.10.20', '255.0.0.0')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '10.0.0.0')
        self.assertEqual(results['subnet_mask'], '255.0.0.0 (/8)')
        self.assertEqual(results['first_host'], '10.0.0.1')
        self.assertEqual(results['last_host'], '10.255.255.254')
        self.assertEqual(results['broadcast'], '10.255.255.255')
    
    def test_host_address_32(self):
        """Test /32 network (single host)."""
        calc = SubnetCalculator('192.168.1.1', '/32')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '192.168.1.1')
        self.assertEqual(results['first_host'], '192.168.1.1')
        self.assertEqual(results['last_host'], '192.168.1.1')
        self.assertEqual(results['broadcast'], '192.168.1.1')
        self.assertEqual(results['total_hosts'], 1)
        self.assertEqual(results['usable_hosts'], 1)
    
    def test_point_to_point_31(self):
        """Test /31 network (point-to-point link)."""
        calc = SubnetCalculator('10.0.0.0', '/31')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '10.0.0.0')
        self.assertEqual(results['first_host'], '10.0.0.0')
        self.assertEqual(results['last_host'], '10.0.0.1')
        self.assertEqual(results['broadcast'], '10.0.0.1')
        self.assertEqual(results['total_hosts'], 2)
        self.assertEqual(results['usable_hosts'], 2)
    
    def test_small_subnet_30(self):
        """Test /30 network (4 addresses, 2 usable)."""
        calc = SubnetCalculator('192.168.1.4', '/30')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '192.168.1.4')
        self.assertEqual(results['first_host'], '192.168.1.5')
        self.assertEqual(results['last_host'], '192.168.1.6')
        self.assertEqual(results['broadcast'], '192.168.1.7')
        self.assertEqual(results['usable_hosts'], 2)
    
    def test_large_subnet_12(self):
        """Test /12 network (large subnet)."""
        calc = SubnetCalculator('172.16.0.1', '/12')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '172.16.0.0')
        self.assertEqual(results['subnet_mask'], '255.240.0.0 (/12)')
        self.assertEqual(results['first_host'], '172.16.0.1')
        self.assertEqual(results['last_host'], '172.31.255.254')
        self.assertEqual(results['broadcast'], '172.31.255.255')
        self.assertEqual(results['total_hosts'], 1048576)
    
    def test_binary_output(self):
        """Test binary representation output."""
        calc = SubnetCalculator('192.168.1.100', '/24', show_binary=True)
        results = calc.calculate()
        
        self.assertIn('binary', results)
        self.assertEqual(
            results['binary']['ip_address'],
            '11000000.10101000.00000001.01100100'
        )
        self.assertEqual(
            results['binary']['subnet_mask'],
            '11111111.11111111.11111111.00000000'
        )
        self.assertEqual(
            results['binary']['network_address'],
            '11000000.10101000.00000001.00000000'
        )
    
    def test_invalid_ip_format(self):
        """Test invalid IP address format."""
        with self.assertRaises(ValueError):
            SubnetCalculator('256.1.1.1', '/24')
        
        with self.assertRaises(ValueError):
            SubnetCalculator('192.168.1', '/24')
        
        with self.assertRaises(ValueError):
            SubnetCalculator('abc.def.ghi.jkl', '/24')
    
    def test_invalid_cidr(self):
        """Test invalid CIDR notation."""
        with self.assertRaises(ValueError):
            SubnetCalculator('192.168.1.1', '/33')
        
        with self.assertRaises(ValueError):
            SubnetCalculator('192.168.1.1', '/-1')
    
    def test_invalid_subnet_mask(self):
        """Test invalid subnet mask."""
        with self.assertRaises(ValueError):
            SubnetCalculator('192.168.1.1', '255.255.255.256')
        
        # Non-contiguous mask
        with self.assertRaises(ValueError):
            SubnetCalculator('192.168.1.1', '255.255.0.255')
    
    def test_edge_case_zero_cidr(self):
        """Test /0 network (entire internet)."""
        calc = SubnetCalculator('0.0.0.0', '/0')
        results = calc.calculate()
        
        self.assertEqual(results['network_address'], '0.0.0.0')
        self.assertEqual(results['broadcast'], '255.255.255.255')
        self.assertEqual(results['total_hosts'], 4294967296)
    
    def test_cidr_without_slash(self):
        """Test CIDR notation without leading slash."""
        calc = SubnetCalculator('192.168.1.1', '24')
        results = calc.calculate()
        
        self.assertEqual(results['subnet_mask'], '255.255.255.0 (/24)')
    
    def test_various_subnet_boundaries(self):
        """Test IP addresses at various subnet boundaries."""
        # IP at network address
        calc = SubnetCalculator('192.168.1.0', '/24')
        self.assertEqual(calc.calculate()['network_address'], '192.168.1.0')
        
        # IP at broadcast address
        calc = SubnetCalculator('192.168.1.255', '/24')
        self.assertEqual(calc.calculate()['network_address'], '192.168.1.0')
        
        # IP in middle of subnet
        calc = SubnetCalculator('192.168.1.128', '/24')
        self.assertEqual(calc.calculate()['network_address'], '192.168.1.0')
    
    def test_next_network(self):
        """Test next network calculation."""
        # /24 network
        calc = SubnetCalculator('192.168.1.0', '/24')
        results = calc.calculate()
        self.assertEqual(results['next_network'], '192.168.2.0')
        
        # /25 network
        calc = SubnetCalculator('192.168.1.0', '/25')
        results = calc.calculate()
        self.assertEqual(results['next_network'], '192.168.1.128')
        
        # /26 network
        calc = SubnetCalculator('10.0.0.0', '/26')
        results = calc.calculate()
        self.assertEqual(results['next_network'], '10.0.0.64')
        
        # /30 network
        calc = SubnetCalculator('172.16.0.0', '/30')
        results = calc.calculate()
        self.assertEqual(results['next_network'], '172.16.0.4')
        
        # Last possible /24 network (should not overflow)
        calc = SubnetCalculator('255.255.255.0', '/24')
        results = calc.calculate()
        self.assertEqual(results['next_network'], 'N/A')
    
    def test_next_network_sequential_subnets(self):
        """Test sequential subnet planning."""
        # Divide 192.168.1.0/24 into /26 subnets
        calc1 = SubnetCalculator('192.168.1.0', '/26')
        self.assertEqual(calc1.calculate()['next_network'], '192.168.1.64')
        
        calc2 = SubnetCalculator('192.168.1.64', '/26')
        self.assertEqual(calc2.calculate()['next_network'], '192.168.1.128')
        
        calc3 = SubnetCalculator('192.168.1.128', '/26')
        self.assertEqual(calc3.calculate()['next_network'], '192.168.1.192')
        
        calc4 = SubnetCalculator('192.168.1.192', '/26')
        self.assertEqual(calc4.calculate()['next_network'], '192.168.2.0')
    
    def test_wildcard_mask(self):
        """Test wildcard mask calculation."""
        # /24 network
        calc = SubnetCalculator('192.168.1.0', '/24')
        results = calc.calculate()
        self.assertEqual(results['wildcard_mask'], '0.0.0.255')
        
        # /16 network
        calc = SubnetCalculator('172.16.0.0', '/16')
        results = calc.calculate()
        self.assertEqual(results['wildcard_mask'], '0.0.255.255')
        
        # /30 network
        calc = SubnetCalculator('10.0.0.0', '/30')
        results = calc.calculate()
        self.assertEqual(results['wildcard_mask'], '0.0.0.3')
        
        # /25 network
        calc = SubnetCalculator('192.168.1.0', '/25')
        results = calc.calculate()
        self.assertEqual(results['wildcard_mask'], '0.0.0.127')
    
    def test_ip_class_detection(self):
        """Test IP address class detection."""
        # Class A
        calc = SubnetCalculator('10.0.0.1', '/8')
        self.assertEqual(calc.get_ip_class(), 'A')
        
        # Class B
        calc = SubnetCalculator('172.16.0.1', '/16')
        self.assertEqual(calc.get_ip_class(), 'B')
        
        # Class C
        calc = SubnetCalculator('192.168.1.1', '/24')
        self.assertEqual(calc.get_ip_class(), 'C')
        
        # Class D (Multicast)
        calc = SubnetCalculator('224.0.0.1', '/24')
        self.assertEqual(calc.get_ip_class(), 'D (Multicast)')
        
        # Class E (Reserved)
        calc = SubnetCalculator('240.0.0.1', '/24')
        self.assertEqual(calc.get_ip_class(), 'E (Reserved)')
    
    def test_ip_type_detection(self):
        """Test IP address type detection."""
        # Private RFC 1918 - 10.0.0.0/8
        calc = SubnetCalculator('10.5.5.5', '/24')
        self.assertIn('Private', calc.get_ip_type())
        self.assertIn('10.0.0.0/8', calc.get_ip_type())
        
        # Private RFC 1918 - 172.16.0.0/12
        calc = SubnetCalculator('172.20.0.1', '/24')
        self.assertIn('Private', calc.get_ip_type())
        self.assertIn('172.16.0.0/12', calc.get_ip_type())
        
        # Private RFC 1918 - 192.168.0.0/16
        calc = SubnetCalculator('192.168.100.1', '/24')
        self.assertIn('Private', calc.get_ip_type())
        self.assertIn('192.168.0.0/16', calc.get_ip_type())
        
        # Loopback
        calc = SubnetCalculator('127.0.0.1', '/8')
        self.assertIn('Loopback', calc.get_ip_type())
        
        # Public
        calc = SubnetCalculator('8.8.8.8', '/24')
        self.assertEqual(calc.get_ip_type(), 'Public')
        
        # Link-Local
        calc = SubnetCalculator('169.254.1.1', '/16')
        self.assertIn('Link-Local', calc.get_ip_type())
    
    def test_subnet_table_generation(self):
        """Test subnet table generation."""
        # Divide /24 into /26 subnets (4 subnets)
        calc = SubnetCalculator('192.168.1.0', '/24')
        subnets = calc.generate_subnet_table(26)
        
        self.assertEqual(len(subnets), 4)
        self.assertEqual(subnets[0]['network'], '192.168.1.0')
        self.assertEqual(subnets[1]['network'], '192.168.1.64')
        self.assertEqual(subnets[2]['network'], '192.168.1.128')
        self.assertEqual(subnets[3]['network'], '192.168.1.192')
        
        # Check first subnet details
        self.assertEqual(subnets[0]['first_host'], '192.168.1.1')
        self.assertEqual(subnets[0]['last_host'], '192.168.1.62')
        self.assertEqual(subnets[0]['broadcast'], '192.168.1.63')
        self.assertEqual(subnets[0]['usable_hosts'], 62)
    
    def test_subnet_table_invalid_cidr(self):
        """Test subnet table with invalid CIDR."""
        calc = SubnetCalculator('192.168.1.0', '/24')
        
        # Target CIDR must be larger than current
        with self.assertRaises(ValueError):
            calc.generate_subnet_table(23)
        
        with self.assertRaises(ValueError):
            calc.generate_subnet_table(24)


class TestIPConversion(unittest.TestCase):
    """Test IP address conversion functions."""
    
    def test_ip_to_int_conversion(self):
        """Test IP string to integer conversion."""
        calc = SubnetCalculator('192.168.1.1', '/24')
        
        self.assertEqual(calc._ip_to_int('0.0.0.0'), 0)
        self.assertEqual(calc._ip_to_int('255.255.255.255'), 0xFFFFFFFF)
        self.assertEqual(calc._ip_to_int('192.168.1.1'), 3232235777)
        self.assertEqual(calc._ip_to_int('10.0.0.1'), 167772161)
    
    def test_int_to_ip_conversion(self):
        """Test integer to IP string conversion."""
        calc = SubnetCalculator('192.168.1.1', '/24')
        
        self.assertEqual(calc._int_to_ip(0), '0.0.0.0')
        self.assertEqual(calc._int_to_ip(0xFFFFFFFF), '255.255.255.255')
        self.assertEqual(calc._int_to_ip(3232235777), '192.168.1.1')
        self.assertEqual(calc._int_to_ip(167772161), '10.0.0.1')
    
    def test_decimal_to_cidr_conversion(self):
        """Test decimal subnet mask to CIDR conversion."""
        calc = SubnetCalculator('192.168.1.1', '/24')
        
        self.assertEqual(calc._decimal_to_cidr('255.255.255.0'), 24)
        self.assertEqual(calc._decimal_to_cidr('255.255.0.0'), 16)
        self.assertEqual(calc._decimal_to_cidr('255.0.0.0'), 8)
        self.assertEqual(calc._decimal_to_cidr('255.255.255.128'), 25)
        self.assertEqual(calc._decimal_to_cidr('255.255.255.252'), 30)


class TestIPv6Calculator(unittest.TestCase):
    """Test cases for IPv6Calculator class."""
    
    def test_basic_ipv6_compressed(self):
        """Test basic IPv6 calculation with compressed notation."""
        calc = IPv6Calculator('2001:db8::1', 64)
        results = calc.calculate()
        
        self.assertEqual(results['address_compressed'], '2001:db8::1')
        self.assertEqual(results['address_full'], '2001:0db8:0000:0000:0000:0000:0000:0001')
        self.assertEqual(results['network_compressed'], '2001:db8::')
        self.assertEqual(results['prefix'], '/64')
    
    def test_ipv6_loopback(self):
        """Test IPv6 loopback address."""
        calc = IPv6Calculator('::1', 128)
        results = calc.calculate()
        
        self.assertEqual(results['address_compressed'], '::1')
        self.assertEqual(results['ipv6_type'], 'Loopback (::1)')
        self.assertEqual(results['total_addresses'], 1)
    
    def test_ipv6_link_local(self):
        """Test IPv6 link-local address."""
        calc = IPv6Calculator('fe80::1', 10)
        results = calc.calculate()
        
        self.assertEqual(results['ipv6_type'], 'Link-Local (fe80::/10)')
        self.assertEqual(results['network_compressed'], 'fe80::')
    
    def test_ipv6_unique_local(self):
        """Test IPv6 unique local address."""
        calc = IPv6Calculator('fc00::1', 7)
        results = calc.calculate()
        
        self.assertEqual(results['ipv6_type'], 'Unique Local Address (fc00::/7)')
    
    def test_ipv6_multicast(self):
        """Test IPv6 multicast address."""
        calc = IPv6Calculator('ff02::1', 128)
        results = calc.calculate()
        
        self.assertEqual(results['ipv6_type'], 'Multicast (ff00::/8)')
        self.assertEqual(results['address_compressed'], 'ff02::1')
    
    def test_ipv6_global_unicast(self):
        """Test IPv6 global unicast address."""
        calc = IPv6Calculator('2001:db8:85a3::8a2e:370:7334', 48)
        results = calc.calculate()
        
        self.assertEqual(results['ipv6_type'], 'Global Unicast (2000::/3)')
        self.assertEqual(results['network_compressed'], '2001:db8:85a3::')
    
    def test_ipv6_prefix_64(self):
        """Test standard /64 IPv6 prefix."""
        calc = IPv6Calculator('2001:db8::', 64)
        results = calc.calculate()
        
        self.assertEqual(results['prefix'], '/64')
        self.assertEqual(results['first_address'], '2001:db8::')
        self.assertEqual(results['last_address'], '2001:db8::ffff:ffff:ffff:ffff')
    
    def test_ipv6_binary_output(self):
        """Test IPv6 binary representation."""
        calc = IPv6Calculator('2001:db8::1', 64, show_binary=True)
        results = calc.calculate()
        
        self.assertIn('binary', results)
        self.assertIn('address', results['binary'])
        self.assertIn('mask', results['binary'])
    
    def test_ipv6_invalid_address(self):
        """Test invalid IPv6 addresses."""
        with self.assertRaises(ValueError):
            IPv6Calculator('gggg::1', 64)
        
        with self.assertRaises(ValueError):
            IPv6Calculator('2001:db8::1::2', 64)
    
    def test_ipv6_invalid_prefix(self):
        """Test invalid IPv6 prefix lengths."""
        with self.assertRaises(ValueError):
            IPv6Calculator('2001:db8::1', 129)


def run_tests():
    """Run all test suites."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSubnetCalculator))
    suite.addTests(loader.loadTestsFromTestCase(TestIPConversion))
    suite.addTests(loader.loadTestsFromTestCase(TestIPv6Calculator))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
