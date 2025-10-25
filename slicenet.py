#!/usr/bin/env python3
"""
SliceNet - IP Subnet Calculator
A powerful tool for IPv4 and IPv6 subnet calculations with 12 advanced features.

Author: SNB
GitHub: https://github.com/SNB220
Version: 1.0.0
License: MIT

Features:
- IPv4 & IPv6 subnet calculation
- Binary representation and analysis
- IP classification and type detection
- Subnet table generation
- IP range to CIDR conversion
- Supernet/CIDR aggregation
- Export to TXT/CSV/JSON
- Batch processing from files
- And more...
"""

import sys
import re
import json
import csv
import os
from datetime import datetime
from typing import Tuple, Optional, Union, Dict, List, Any


class IPv6Calculator:
    """Handles IPv6 subnet calculations and format conversions."""
    
    def __init__(self, ipv6: str, prefix: int, show_binary: bool = False, show_subnets: Optional[int] = None):
        """
        Initialize IPv6 calculator.
        
        Args:
            ipv6: IPv6 address string
            prefix: Prefix length (0-128)
            show_binary: Whether to show binary representations
            show_subnets: If provided, show all subnets of this prefix size
        """
        self.show_binary = show_binary
        self.show_subnets = show_subnets
        self.prefix = prefix
        self.original_input = ipv6
        
        # Parse and validate IPv6 address
        self.ipv6_int = self._parse_ipv6(ipv6)
        self._validate()
        
        # Calculate mask
        self.mask_int = self._prefix_to_mask(prefix)
    
    def _validate(self):
        """Validate IPv6 address and prefix."""
        if not (0 <= self.ipv6_int <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
            raise ValueError("Invalid IPv6 address")
        if not (0 <= self.prefix <= 128):
            raise ValueError(f"Invalid prefix length: /{self.prefix}. Must be between /0 and /128")
    
    def _parse_ipv6(self, ipv6: str) -> int:
        """Parse IPv6 address to 128-bit integer."""
        ipv6 = ipv6.strip()
        
        # Handle :: compression
        if '::' in ipv6:
            if ipv6.count('::') > 1:
                raise ValueError("Invalid IPv6: multiple '::' found")
            
            # Split on ::
            parts = ipv6.split('::')
            left = parts[0].split(':') if parts[0] else []
            right = parts[1].split(':') if parts[1] else []
            
            # Remove empty strings
            left = [p for p in left if p]
            right = [p for p in right if p]
            
            # Calculate missing zeros
            total_parts = len(left) + len(right)
            missing = 8 - total_parts
            
            # Reconstruct full address
            groups = left + (['0000'] * missing) + right
        else:
            groups = ipv6.split(':')
        
        if len(groups) != 8:
            raise ValueError(f"Invalid IPv6 address: expected 8 groups, got {len(groups)}")
        
        # Convert to integer
        result = 0
        for group in groups:
            if len(group) > 4:
                raise ValueError(f"Invalid IPv6 group: {group}")
            try:
                value = int(group, 16)
                if value > 0xFFFF:
                    raise ValueError
                result = (result << 16) | value
            except ValueError:
                raise ValueError(f"Invalid IPv6 group: {group}")
        
        return result
    
    def _int_to_ipv6_full(self, ip_int: int) -> str:
        """Convert 128-bit integer to full IPv6 string (uncompressed)."""
        groups = []
        for i in range(8):
            shift = (7 - i) * 16
            group = (ip_int >> shift) & 0xFFFF
            groups.append(f"{group:04x}")
        return ':'.join(groups)
    
    def _int_to_ipv6_compressed(self, ip_int: int) -> str:
        """Convert 128-bit integer to compressed IPv6 string."""
        full = self._int_to_ipv6_full(ip_int)
        groups = full.split(':')
        
        # Find longest run of zeros
        max_zero_start = -1
        max_zero_len = 0
        current_zero_start = -1
        current_zero_len = 0
        
        for i, group in enumerate(groups):
            if group == '0000':
                if current_zero_start == -1:
                    current_zero_start = i
                    current_zero_len = 1
                else:
                    current_zero_len += 1
            else:
                if current_zero_len > max_zero_len:
                    max_zero_start = current_zero_start
                    max_zero_len = current_zero_len
                current_zero_start = -1
                current_zero_len = 0
        
        # Check last run
        if current_zero_len > max_zero_len:
            max_zero_start = current_zero_start
            max_zero_len = current_zero_len
        
        # Compress if we found zeros
        if max_zero_len > 1:
            # Remove leading zeros and compress
            compressed_groups = [g.lstrip('0') or '0' for g in groups]
            
            # Replace longest zero run with ::
            before = compressed_groups[:max_zero_start]
            after = compressed_groups[max_zero_start + max_zero_len:]
            
            if not before and not after:
                return '::'
            elif not before:
                return '::' + ':'.join(after)
            elif not after:
                return ':'.join(before) + '::'
            else:
                return ':'.join(before) + '::' + ':'.join(after)
        else:
            # Just remove leading zeros
            return ':'.join([g.lstrip('0') or '0' for g in groups])
    
    def _prefix_to_mask(self, prefix: int) -> int:
        """Convert prefix length to 128-bit mask."""
        if prefix == 0:
            return 0
        return (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - prefix)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    
    def _int_to_binary(self, ip_int: int) -> str:
        """Convert 128-bit integer to binary representation."""
        binary = bin(ip_int)[2:].zfill(128)
        # Split into groups of 16 bits
        return ':'.join([binary[i:i+16] for i in range(0, 128, 16)])
    
    def get_network_address(self) -> int:
        """Calculate IPv6 network address."""
        return self.ipv6_int & self.mask_int
    
    def get_first_address(self) -> int:
        """Get first address in subnet (usually same as network for IPv6)."""
        return self.get_network_address()
    
    def get_last_address(self) -> int:
        """Get last address in subnet."""
        network = self.get_network_address()
        host_bits = 128 - self.prefix
        return network | ((1 << host_bits) - 1)
    
    def get_total_addresses(self) -> int:
        """Get total number of addresses in subnet."""
        return 2 ** (128 - self.prefix)
    
    def get_previous_network(self) -> Optional[int]:
        """Get the network address of the previous IPv6 subnet."""
        network = self.get_network_address()
        # Calculate subnet size
        subnet_size = 2 ** (128 - self.prefix)
        previous_network = network - subnet_size
        # Check if previous network is valid (doesn't go negative)
        if previous_network < 0:
            return None
        return previous_network
    
    def get_next_network(self) -> Optional[int]:
        """Get the network address of the next IPv6 subnet."""
        last_addr = self.get_last_address()
        next_network = last_addr + 1
        # Check if next network is valid (doesn't overflow 128-bit)
        if next_network > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
            return None
        return next_network
    
    def generate_subnet_table(self, target_prefix: int) -> list:
        """
        Generate all subnets of a given prefix size within the current network.
        
        Args:
            target_prefix: Target prefix length for subnets (must be larger than current)
        
        Returns:
            List of subnet dictionaries
        """
        if target_prefix <= self.prefix:
            raise ValueError(f"Target prefix /{target_prefix} must be larger than current /{self.prefix}")
        if target_prefix > 128:
            raise ValueError(f"Target prefix /{target_prefix} is invalid (max is /128)")
        
        network = self.get_network_address()
        last_addr = self.get_last_address()
        
        # Calculate subnet size
        subnet_size = 2 ** (128 - target_prefix)
        num_subnets = 2 ** (target_prefix - self.prefix)
        
        # Limit output for very large ranges
        max_subnets = 1024
        if num_subnets > max_subnets:
            raise ValueError(f"Too many subnets ({num_subnets}). Maximum is {max_subnets}. Try a smaller prefix difference.")
        
        subnets = []
        current_network = network
        
        for i in range(num_subnets):
            subnet_last = current_network + subnet_size - 1
            
            # Ensure we don't exceed the parent network
            if subnet_last > last_addr:
                break
            
            subnet_info = {
                'subnet': f"{self._int_to_ipv6_compressed(current_network)}/{target_prefix}",
                'network': self._int_to_ipv6_compressed(current_network),
                'first': self._int_to_ipv6_compressed(current_network),
                'last': self._int_to_ipv6_compressed(subnet_last),
                'total_addresses': subnet_size
            }
            subnets.append(subnet_info)
            
            current_network += subnet_size
        
        return subnets
    
    def get_ipv6_type(self) -> str:
        """Determine IPv6 address type."""
        # Get first 16 bits
        first_group = (self.ipv6_int >> 112) & 0xFFFF
        
        # Loopback (::1)
        if self.ipv6_int == 1:
            return 'Loopback (::1)'
        
        # Unspecified (::)
        if self.ipv6_int == 0:
            return 'Unspecified (::)'
        
        # Link-local (fe80::/10)
        if (first_group & 0xFFC0) == 0xFE80:
            return 'Link-Local (fe80::/10)'
        
        # Multicast (ff00::/8)
        if (first_group & 0xFF00) == 0xFF00:
            return 'Multicast (ff00::/8)'
        
        # Unique Local (fc00::/7)
        if (first_group & 0xFE00) == 0xFC00:
            return 'Unique Local Address (fc00::/7)'
        
        # Global Unicast (2000::/3)
        if (first_group & 0xE000) == 0x2000:
            return 'Global Unicast (2000::/3)'
        
        # IPv4-mapped (::ffff:0:0/96)
        if (self.ipv6_int >> 32) == 0xFFFF:
            return 'IPv4-Mapped (::ffff:0:0/96)'
        
        # IPv4-compatible (deprecated)
        if self.ipv6_int < 0x100000000 and self.ipv6_int != 0:
            return 'IPv4-Compatible (deprecated)'
        
        return 'Reserved/Other'
    
    def calculate(self) -> dict:
        """Perform all IPv6 calculations."""
        network = self.get_network_address()
        first_addr = self.get_first_address()
        last_addr = self.get_last_address()
        
        results = {
            'address_full': self._int_to_ipv6_full(self.ipv6_int),
            'address_compressed': self._int_to_ipv6_compressed(self.ipv6_int),
            'prefix': f'/{self.prefix}',
            'ipv6_type': self.get_ipv6_type(),
            'network_full': self._int_to_ipv6_full(network),
            'network_compressed': self._int_to_ipv6_compressed(network),
            'first_address': self._int_to_ipv6_compressed(first_addr),
            'last_address': self._int_to_ipv6_compressed(last_addr),
            'total_addresses': self.get_total_addresses(),
            'previous_network': self.get_previous_network(),
            'next_network': self.get_next_network()
        }
        
        if self.show_binary:
            results['binary'] = {
                'address': self._int_to_binary(self.ipv6_int),
                'mask': self._int_to_binary(self.mask_int),
                'network': self._int_to_binary(network)
            }
        
        return results
    
    def format_output(self) -> str:
        """Format IPv6 calculation results."""
        results = self.calculate()
        
        output = []
        output.append("\n" + "="*70)
        output.append("SliceNet - IPv6 SUBNET CALCULATOR")
        output.append("="*70)
        output.append(f"IPv6 Address (Full):       {results['address_full']}")
        output.append(f"IPv6 Address (Compressed): {results['address_compressed']}")
        output.append(f"Prefix Length:             {results['prefix']}")
        output.append(f"Address Type:              {results['ipv6_type']}")
        output.append("")
        output.append(f"Network (Full):            {results['network_full']}")
        output.append(f"Network (Compressed):      {results['network_compressed']}")
        output.append(f"First Address:             {results['first_address']}")
        output.append(f"Last Address:              {results['last_address']}")
        
        # Format total addresses
        total = results['total_addresses']
        if total > 10**15:
            output.append(f"Total Addresses:           {total:.2e}")
        else:
            output.append(f"Total Addresses:           {total:,}")
        
        # Previous Network
        prev_net = self.get_previous_network()
        if prev_net is not None:
            output.append(f"\nPrevious Network:          {self._int_to_ipv6_compressed(prev_net)}/{self.prefix}")
        else:
            output.append(f"\nPrevious Network:          None (start of IPv6 address space)")
        
        # Next Network
        next_net = self.get_next_network()
        if next_net is not None:
            output.append(f"Next Network:              {self._int_to_ipv6_compressed(next_net)}/{self.prefix}")
        else:
            output.append(f"Next Network:              None (end of IPv6 address space)")
        
        if self.show_binary:
            output.append("\n" + "-"*70)
            output.append("BINARY REPRESENTATION (128-bit)")
            output.append("-"*70)
            output.append(f"Address: {results['binary']['address']}")
            output.append(f"Mask:    {results['binary']['mask']}")
            output.append(f"         " + "AND operation".center(62))
            output.append(f"Network: {results['binary']['network']}")
        
        # Subnet Table
        if self.show_subnets:
            output.append("\n" + "-"*70)
            output.append(f"SUBNET TABLE (/{self.prefix} divided into /{self.show_subnets} subnets)")
            output.append("-"*70)
            try:
                subnets = self.generate_subnet_table(self.show_subnets)
                output.append(f"Total Subnets: {len(subnets)}\n")
                
                # Determine if we should show detailed or compact view
                if len(subnets) <= 64:
                    # Detailed view for smaller ranges
                    output.append(f"{'#':<6} {'Network':<45} {'Total Addresses':<20}")
                    output.append("-"*70)
                    for i, subnet in enumerate(subnets, 1):
                        total_fmt = f"{subnet['total_addresses']:.2e}" if subnet['total_addresses'] > 10**15 else f"{subnet['total_addresses']:,}"
                        output.append(f"{i:<6} {subnet['subnet']:<45} {total_fmt:<20}")
                else:
                    # Compact view for larger ranges
                    output.append(f"{'#':<6} {'Network':<50}")
                    output.append("-"*70)
                    for i, subnet in enumerate(subnets, 1):
                        output.append(f"{i:<6} {subnet['subnet']}")
                
            except ValueError as e:
                output.append(f"Error: {str(e)}")
        
        output.append("="*70)
        output.append("")
        output.append("SliceNet 🌐 — Cut through networks with precision.")
        output.append("Made with ❤️ by SNB | https://github.com/SNB220")
        output.append("")
        
        return '\n'.join(output)


class SubnetCalculator:
    """Handles IP subnet calculations and conversions."""
    
    def __init__(self, ip: str, mask: str, show_binary: bool = False, show_subnets: Optional[int] = None):
        """
        Initialize the calculator with an IP address and subnet mask.
        
        Args:
            ip: IP address string (e.g., '192.168.1.1')
            mask: Subnet mask in CIDR (e.g., '24' or '/24') or decimal (e.g., '255.255.255.0')
            show_binary: Whether to show binary representations
            show_subnets: If provided, show all subnets of this CIDR size
        """
        self.show_binary = show_binary
        self.show_subnets = show_subnets
        self.ip_int = self._ip_to_int(ip)
        self.ip_str = ip
        
        # Parse mask - could be CIDR or decimal
        if mask.startswith('/'):
            self.cidr = int(mask[1:])
        elif mask.isdigit():
            self.cidr = int(mask)
        else:
            # Assume it's a decimal mask
            self.cidr = self._decimal_to_cidr(mask)
        
        self._validate()
        self.mask_int = self._cidr_to_mask_int(self.cidr)
        self.mask_decimal = self._int_to_ip(self.mask_int)
        
    def _validate(self):
        """Validate IP address and CIDR notation."""
        if not (0 <= self.ip_int <= 0xFFFFFFFF):
            raise ValueError("Invalid IP address")
        if not (0 <= self.cidr <= 32):
            raise ValueError(f"Invalid CIDR notation: /{self.cidr}. Must be between /0 and /32")
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address string to integer."""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                raise ValueError
            
            result = 0
            for octet in octets:
                octet_int = int(octet)
                if not (0 <= octet_int <= 255):
                    raise ValueError
                result = (result << 8) | octet_int
            return result
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid IP address format: {ip}")
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer to IP address string."""
        return '.'.join([
            str((ip_int >> 24) & 0xFF),
            str((ip_int >> 16) & 0xFF),
            str((ip_int >> 8) & 0xFF),
            str(ip_int & 0xFF)
        ])
    
    def _int_to_binary(self, ip_int: int) -> str:
        """Convert integer to binary IP representation."""
        binary = bin(ip_int)[2:].zfill(32)
        # Split into octets for readability
        return '.'.join([binary[i:i+8] for i in range(0, 32, 8)])
    
    def _cidr_to_mask_int(self, cidr: int) -> int:
        """Convert CIDR notation to subnet mask integer."""
        return (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    
    def _decimal_to_cidr(self, decimal_mask: str) -> int:
        """Convert decimal subnet mask to CIDR notation."""
        try:
            mask_int = self._ip_to_int(decimal_mask)
            # Count consecutive 1 bits from the left
            binary = bin(mask_int)[2:].zfill(32)
            
            # Validate it's a proper subnet mask (all 1s followed by all 0s)
            if not re.match(r'^1*0*$', binary):
                raise ValueError("Invalid subnet mask: bits must be contiguous")
            
            return binary.count('1')
        except ValueError as e:
            raise ValueError(f"Invalid subnet mask: {decimal_mask}. {str(e)}")
    
    def get_network_address(self) -> int:
        """Calculate network address using bitwise AND."""
        return self.ip_int & self.mask_int
    
    def get_broadcast_address(self) -> int:
        """Calculate broadcast address."""
        network = self.get_network_address()
        wildcard = ~self.mask_int & 0xFFFFFFFF
        return network | wildcard
    
    def get_first_host(self) -> Optional[int]:
        """Get first usable host IP address."""
        network = self.get_network_address()
        if self.cidr == 32:
            return network  # /32 is a host address
        if self.cidr == 31:
            return network  # /31 is point-to-point, no +1 needed
        return network + 1
    
    def get_last_host(self) -> Optional[int]:
        """Get last usable host IP address."""
        broadcast = self.get_broadcast_address()
        if self.cidr == 32:
            return broadcast  # /32 is a host address
        if self.cidr == 31:
            return broadcast  # /31 is point-to-point, no -1 needed
        return broadcast - 1
    
    def get_total_hosts(self) -> int:
        """Get total number of addresses in subnet."""
        return 2 ** (32 - self.cidr)
    
    def get_usable_hosts(self) -> int:
        """Get number of usable host addresses."""
        total = self.get_total_hosts()
        if self.cidr == 32:
            return 1  # Single host
        if self.cidr == 31:
            return 2  # Point-to-point link (RFC 3021)
        return total - 2  # Subtract network and broadcast addresses
    
    def get_previous_network(self) -> Optional[int]:
        """Get the network address of the previous subnet."""
        network = self.get_network_address()
        # Calculate subnet size
        subnet_size = 2 ** (32 - self.cidr)
        previous_network = network - subnet_size
        # Check if previous network is valid (doesn't go negative)
        if previous_network < 0:
            return None
        return previous_network
    
    def get_next_network(self) -> Optional[int]:
        """Get the network address of the next subnet."""
        broadcast = self.get_broadcast_address()
        next_network = broadcast + 1
        # Check if next network is valid (doesn't overflow)
        if next_network > 0xFFFFFFFF:
            return None
        return next_network
    
    def get_wildcard_mask(self) -> int:
        """Calculate wildcard mask (inverse of subnet mask)."""
        return ~self.mask_int & 0xFFFFFFFF
    
    def get_ip_class(self) -> str:
        """Determine the IP address class (A, B, C, D, E)."""
        first_octet = (self.ip_int >> 24) & 0xFF
        
        if first_octet < 128:
            return 'A'
        elif first_octet < 192:
            return 'B'
        elif first_octet < 224:
            return 'C'
        elif first_octet < 240:
            return 'D (Multicast)'
        else:
            return 'E (Reserved)'
    
    def get_ip_type(self) -> str:
        """Determine if IP is private, public, or special purpose."""
        first_octet = (self.ip_int >> 24) & 0xFF
        second_octet = (self.ip_int >> 16) & 0xFF
        
        # Loopback (127.0.0.0/8)
        if first_octet == 127:
            return 'Loopback (127.0.0.0/8)'
        
        # Private ranges (RFC 1918)
        if first_octet == 10:
            return 'Private (RFC 1918: 10.0.0.0/8)'
        if first_octet == 172 and 16 <= second_octet <= 31:
            return 'Private (RFC 1918: 172.16.0.0/12)'
        if first_octet == 192 and second_octet == 168:
            return 'Private (RFC 1918: 192.168.0.0/16)'
        
        # Link-local (169.254.0.0/16)
        if first_octet == 169 and second_octet == 254:
            return 'Link-Local (APIPA: 169.254.0.0/16)'
        
        # Multicast (224.0.0.0/4)
        if first_octet >= 224 and first_octet < 240:
            return 'Multicast (224.0.0.0/4)'
        
        # Reserved (240.0.0.0/4)
        if first_octet >= 240:
            return 'Reserved (240.0.0.0/4)'
        
        # CGNAT / Shared Address Space (100.64.0.0/10)
        if first_octet == 100 and 64 <= second_octet < 128:
            return 'Shared Address Space (RFC 6598: 100.64.0.0/10)'
        
        return 'Public'
    
    def generate_subnet_table(self, target_cidr: int) -> list:
        """
        Generate all subnets of a given CIDR size within the current network.
        
        Args:
            target_cidr: Target CIDR notation for subnets (must be larger than current)
        
        Returns:
            List of subnet dictionaries
        """
        if target_cidr <= self.cidr:
            raise ValueError(f"Target CIDR /{target_cidr} must be larger than current /{self.cidr}")
        if target_cidr > 32:
            raise ValueError(f"Target CIDR /{target_cidr} is invalid (max is /32)")
        
        network = self.get_network_address()
        broadcast = self.get_broadcast_address()
        
        # Calculate subnet size
        subnet_size = 2 ** (32 - target_cidr)
        num_subnets = 2 ** (target_cidr - self.cidr)
        
        subnets = []
        current_network = network
        
        for i in range(num_subnets):
            subnet_broadcast = current_network + subnet_size - 1
            
            # Ensure we don't exceed the parent network
            if subnet_broadcast > broadcast:
                break
            
            if target_cidr == 32:
                first_host = current_network
                last_host = current_network
            elif target_cidr == 31:
                first_host = current_network
                last_host = subnet_broadcast
            else:
                first_host = current_network + 1
                last_host = subnet_broadcast - 1
            
            subnets.append({
                'number': i + 1,
                'network': self._int_to_ip(current_network),
                'first_host': self._int_to_ip(first_host),
                'last_host': self._int_to_ip(last_host),
                'broadcast': self._int_to_ip(subnet_broadcast),
                'usable_hosts': subnet_size - 2 if target_cidr < 31 else (1 if target_cidr == 32 else 2)
            })
            
            current_network += subnet_size
        
        return subnets
    
    def calculate(self) -> dict:
        """
        Perform all calculations and return results as a dictionary.
        
        Returns:
            Dictionary containing all network details
        """
        network = self.get_network_address()
        broadcast = self.get_broadcast_address()
        first_host = self.get_first_host()
        last_host = self.get_last_host()
        previous_network = self.get_previous_network()
        next_network = self.get_next_network()
        wildcard = self.get_wildcard_mask()
        
        results = {
            'network_address': self._int_to_ip(network),
            'subnet_mask': f"{self.mask_decimal} (/{self.cidr})",
            'wildcard_mask': self._int_to_ip(wildcard),
            'ip_class': self.get_ip_class(),
            'ip_type': self.get_ip_type(),
            'first_host': self._int_to_ip(first_host) if first_host is not None else 'N/A',
            'last_host': self._int_to_ip(last_host) if last_host is not None else 'N/A',
            'broadcast': self._int_to_ip(broadcast),
            'total_hosts': self.get_total_hosts(),
            'usable_hosts': self.get_usable_hosts(),
            'previous_network': self._int_to_ip(previous_network) if previous_network is not None else 'N/A',
            'next_network': self._int_to_ip(next_network) if next_network is not None else 'N/A'
        }
        
        if self.show_binary:
            results['binary'] = {
                'ip_address': self._int_to_binary(self.ip_int),
                'subnet_mask': self._int_to_binary(self.mask_int),
                'network_address': self._int_to_binary(network),
                'broadcast': self._int_to_binary(broadcast)
            }
        
        return results
    
    def format_output(self) -> str:
        """Format the calculation results for display."""
        results = self.calculate()
        
        output = []
        output.append("\n" + "="*50)
        output.append("SliceNet - IPv4 SUBNET CALCULATOR")
        output.append("="*50)
        output.append(f"IP Address: {self.ip_str}")
        output.append(f"IP Class: {results['ip_class']}")
        output.append(f"IP Type: {results['ip_type']}")
        output.append(f"Network Address: {results['network_address']}")
        output.append(f"Subnet Mask: {results['subnet_mask']}")
        output.append(f"Wildcard Mask: {results['wildcard_mask']}")
        output.append(f"First Host IP: {results['first_host']}")
        output.append(f"Last Host IP: {results['last_host']}")
        output.append(f"Broadcast IP: {results['broadcast']}")
        output.append(f"Total Hosts: {results['total_hosts']:,}")
        output.append(f"Usable Hosts: {results['usable_hosts']:,}")
        output.append(f"Previous Network: {results['previous_network']}")
        output.append(f"Next Network: {results['next_network']}")
        
        if self.show_binary:
            output.append("\n" + "-"*50)
            output.append("BINARY REPRESENTATION")
            output.append("-"*50)
            output.append(f"IP Address:      {results['binary']['ip_address']}")
            output.append(f"Subnet Mask:     {results['binary']['subnet_mask']}")
            output.append(f"                 " + "AND operation".center(35))
            output.append(f"Network Address: {results['binary']['network_address']}")
            output.append(f"Broadcast:       {results['binary']['broadcast']}")
        
        if self.show_subnets:
            output.append("\n" + "="*50)
            output.append(f"SUBNET TABLE (/{self.show_subnets} subnets)")
            output.append("="*50)
            try:
                subnets = self.generate_subnet_table(self.show_subnets)
                
                # Table header
                output.append(f"{'#':<4} {'Network':<16} {'First Host':<16} {'Last Host':<16} {'Broadcast':<16} {'Hosts':<8}")
                output.append("-" * 50)
                
                # Table rows
                for subnet in subnets:
                    output.append(
                        f"{subnet['number']:<4} "
                        f"{subnet['network']:<16} "
                        f"{subnet['first_host']:<16} "
                        f"{subnet['last_host']:<16} "
                        f"{subnet['broadcast']:<16} "
                        f"{subnet['usable_hosts']:<8}"
                    )
                
                output.append("-" * 50)
                output.append(f"Total Subnets: {len(subnets)}")
            except ValueError as e:
                output.append(f"Error: {e}")
        
        output.append("="*50)
        output.append("")
        output.append("SliceNet 🌐 — Cut through networks with precision.")
        output.append("Made with ❤️ by SNB | https://github.com/SNB220")
        output.append("")
        
        return '\n'.join(output)


class IPRangeToCIDR:
    """Convert IP address ranges to CIDR notation."""
    
    def __init__(self, start_ip: str, end_ip: str):
        """
        Initialize with start and end IP addresses.
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
        """
        self.is_ipv6 = ':' in start_ip or ':' in end_ip
        
        if self.is_ipv6:
            # IPv6 range
            self.start_int = self._parse_ipv6(start_ip)
            self.end_int = self._parse_ipv6(end_ip)
            self.max_prefix = 128
            self.max_int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        else:
            # IPv4 range
            self.start_int = self._ip_to_int(start_ip)
            self.end_int = self._ip_to_int(end_ip)
            self.max_prefix = 32
            self.max_int = 0xFFFFFFFF
        
        if self.start_int > self.end_int:
            raise ValueError(f"Start IP ({start_ip}) must be less than or equal to End IP ({end_ip})")
    
    def _ip_to_int(self, ip: str) -> int:
        """Convert IPv4 address to integer."""
        octets = ip.split('.')
        if len(octets) != 4:
            raise ValueError(f"Invalid IPv4 address: {ip}")
        
        result = 0
        for octet in octets:
            if not octet.isdigit():
                raise ValueError(f"Invalid IPv4 address: {ip}")
            num = int(octet)
            if num > 255:
                raise ValueError(f"Invalid IPv4 octet: {num}")
            result = (result << 8) | num
        return result
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer to IPv4 address."""
        octets = []
        for i in range(4):
            octets.append(str((ip_int >> (24 - i * 8)) & 0xFF))
        return '.'.join(octets)
    
    def _parse_ipv6(self, ipv6: str) -> int:
        """Parse IPv6 address to 128-bit integer."""
        ipv6 = ipv6.strip()
        
        if '::' in ipv6:
            if ipv6.count('::') > 1:
                raise ValueError("Invalid IPv6: multiple '::' found")
            
            parts = ipv6.split('::')
            left = parts[0].split(':') if parts[0] else []
            right = parts[1].split(':') if parts[1] else []
            
            left = [p for p in left if p]
            right = [p for p in right if p]
            
            total_parts = len(left) + len(right)
            missing = 8 - total_parts
            
            groups = left + (['0000'] * missing) + right
        else:
            groups = ipv6.split(':')
        
        if len(groups) != 8:
            raise ValueError(f"Invalid IPv6 address: expected 8 groups, got {len(groups)}")
        
        result = 0
        for group in groups:
            if len(group) > 4:
                raise ValueError(f"Invalid IPv6 group: {group}")
            try:
                value = int(group, 16)
                if value > 0xFFFF:
                    raise ValueError
                result = (result << 16) | value
            except ValueError:
                raise ValueError(f"Invalid IPv6 group: {group}")
        
        return result
    
    def _int_to_ipv6_compressed(self, ip_int: int) -> str:
        """Convert 128-bit integer to compressed IPv6 string."""
        groups = []
        for i in range(8):
            shift = (7 - i) * 16
            group = (ip_int >> shift) & 0xFFFF
            groups.append(f"{group:04x}")
        
        full = ':'.join(groups)
        
        # Find longest run of zeros
        max_zero_start = -1
        max_zero_len = 0
        current_zero_start = -1
        current_zero_len = 0
        
        for i, group in enumerate(groups):
            if group == '0000':
                if current_zero_start == -1:
                    current_zero_start = i
                    current_zero_len = 1
                else:
                    current_zero_len += 1
            else:
                if current_zero_len > max_zero_len:
                    max_zero_start = current_zero_start
                    max_zero_len = current_zero_len
                current_zero_start = -1
                current_zero_len = 0
        
        if current_zero_len > max_zero_len:
            max_zero_start = current_zero_start
            max_zero_len = current_zero_len
        
        if max_zero_len > 1:
            before = groups[:max_zero_start]
            after = groups[max_zero_start + max_zero_len:]
            
            before_str = ':'.join(g.lstrip('0') or '0' for g in before)
            after_str = ':'.join(g.lstrip('0') or '0' for g in after)
            
            if before_str and after_str:
                return f"{before_str}::{after_str}"
            elif before_str:
                return f"{before_str}::"
            elif after_str:
                return f"::{after_str}"
            else:
                return "::"
        else:
            return ':'.join(g.lstrip('0') or '0' for g in groups)
    
    def range_to_cidr(self) -> list:
        """
        Convert IP range to minimal set of CIDR blocks.
        
        Returns:
            List of CIDR strings that cover the range
        """
        cidrs = []
        current = self.start_int
        
        while current <= self.end_int:
            # Find the largest CIDR block that fits
            max_size = self.max_prefix
            
            # Find the largest block size where current is aligned
            for prefix in range(self.max_prefix + 1):
                block_size = 2 ** (self.max_prefix - prefix)
                if current % block_size == 0:
                    max_size = prefix
                    break
            
            # Find the largest block that doesn't exceed end_ip
            for prefix in range(max_size, self.max_prefix + 1):
                block_size = 2 ** (self.max_prefix - prefix)
                block_end = current + block_size - 1
                
                if block_end <= self.end_int:
                    # This block fits
                    if self.is_ipv6:
                        cidr_str = f"{self._int_to_ipv6_compressed(current)}/{prefix}"
                    else:
                        cidr_str = f"{self._int_to_ip(current)}/{prefix}"
                    
                    cidrs.append({
                        'cidr': cidr_str,
                        'start': current,
                        'end': block_end,
                        'prefix': prefix,
                        'count': block_size
                    })
                    
                    current = block_end + 1
                    break
            else:
                # Should not happen, but safety check
                break
        
        return cidrs
    
    def format_output(self) -> str:
        """Format the CIDR conversion results."""
        cidrs = self.range_to_cidr()
        
        output = []
        output.append("\n" + "="*70)
        output.append("SliceNet - IP RANGE TO CIDR CONVERTER")
        output.append("="*70)
        
        if self.is_ipv6:
            output.append(f"Start IP:  {self._int_to_ipv6_compressed(self.start_int)}")
            output.append(f"End IP:    {self._int_to_ipv6_compressed(self.end_int)}")
        else:
            output.append(f"Start IP:  {self._int_to_ip(self.start_int)}")
            output.append(f"End IP:    {self._int_to_ip(self.end_int)}")
        
        total_ips = self.end_int - self.start_int + 1
        if total_ips > 10**15:
            output.append(f"Total IPs: {total_ips:.2e}")
        else:
            output.append(f"Total IPs: {total_ips:,}")
        
        output.append(f"\nCIDR Blocks: {len(cidrs)}")
        output.append("")
        
        if len(cidrs) <= 50:
            # Detailed view
            output.append(f"{'#':<4} {'CIDR Block':<45} {'IP Count':<15} {'Range'}")
            output.append("-"*70)
            
            for i, cidr in enumerate(cidrs, 1):
                count_str = f"{cidr['count']:.2e}" if cidr['count'] > 10**9 else f"{cidr['count']:,}"
                
                if self.is_ipv6:
                    start_str = self._int_to_ipv6_compressed(cidr['start'])
                    end_str = self._int_to_ipv6_compressed(cidr['end'])
                    if len(cidr['cidr']) > 40:
                        output.append(f"{i:<4} {cidr['cidr']}")
                        output.append(f"     Count: {count_str}")
                        output.append(f"     Range: {start_str} - {end_str}")
                        output.append("")
                    else:
                        output.append(f"{i:<4} {cidr['cidr']:<45} {count_str:<15}")
                else:
                    start_str = self._int_to_ip(cidr['start'])
                    end_str = self._int_to_ip(cidr['end'])
                    output.append(f"{i:<4} {cidr['cidr']:<45} {count_str:<15} {start_str} - {end_str}")
        else:
            # Compact view
            output.append("CIDR Blocks (compact view):")
            output.append("")
            for i, cidr in enumerate(cidrs, 1):
                output.append(f"{i}. {cidr['cidr']}")
        
        output.append("="*70)
        output.append("")
        output.append("SliceNet 🌐 — Cut through networks with precision.")
        output.append("Made with ❤️ by SNB | https://github.com/SNB220")
        output.append("")
        
        return '\n'.join(output)


class SupernetCalculator:
    """Calculate supernet/CIDR aggregation for multiple networks."""
    
    def __init__(self, networks: list):
        """
        Initialize with list of network strings in CIDR notation.
        
        Args:
            networks: List of networks in CIDR notation (e.g., ['192.168.0.0/24', '192.168.1.0/24'])
        """
        self.networks = networks
        self.is_ipv6 = ':' in networks[0] if networks else False
        self.parsed_networks = []
        
        # Parse and validate all networks
        for net in networks:
            if '/' not in net:
                raise ValueError(f"Network must be in CIDR notation: {net}")
            
            ip_part, prefix_part = net.split('/')
            prefix = int(prefix_part)
            
            if self.is_ipv6:
                # Parse IPv6
                ip_int = self._parse_ipv6(ip_part)
                if prefix < 0 or prefix > 128:
                    raise ValueError(f"Invalid IPv6 prefix: /{prefix}")
                mask = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - prefix)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                network_int = ip_int & mask
            else:
                # Parse IPv4
                ip_int = self._ip_to_int(ip_part)
                if prefix < 0 or prefix > 32:
                    raise ValueError(f"Invalid IPv4 prefix: /{prefix}")
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                network_int = ip_int & mask
            
            self.parsed_networks.append({
                'network': network_int,
                'prefix': prefix,
                'original': net
            })
    
    def _ip_to_int(self, ip_str: str) -> int:
        """Convert IPv4 string to integer."""
        parts = ip_str.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address: {ip_str}")
        result = 0
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                raise ValueError(f"Invalid IPv4 octet: {num}")
            result = (result << 8) | num
        return result
    
    def _int_to_ip(self, num: int) -> str:
        """Convert integer to IPv4 string."""
        return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"
    
    def _parse_ipv6(self, ip_str: str) -> int:
        """Convert IPv6 string to integer."""
        # Expand :: notation
        if '::' in ip_str:
            parts = ip_str.split('::')
            if len(parts) != 2:
                raise ValueError(f"Invalid IPv6 address: {ip_str}")
            left = parts[0].split(':') if parts[0] else []
            right = parts[1].split(':') if parts[1] else []
            missing = 8 - len(left) - len(right)
            middle = ['0'] * missing
            groups = left + middle + right
        else:
            groups = ip_str.split(':')
        
        if len(groups) != 8:
            raise ValueError(f"Invalid IPv6 address: {ip_str}")
        
        result = 0
        for group in groups:
            if not group:
                group = '0'
            result = (result << 16) | int(group, 16)
        return result
    
    def _int_to_ipv6_compressed(self, num: int) -> str:
        """Convert integer to compressed IPv6 string."""
        # Convert to 8 groups of 4 hex digits
        groups = []
        for i in range(8):
            groups.append(f"{(num >> (112 - i * 16)) & 0xFFFF:x}")
        
        # Find longest sequence of zeros
        ipv6_str = ':'.join(groups)
        
        # Replace longest run of :0:0: with ::
        best_start = -1
        best_len = 0
        current_start = -1
        current_len = 0
        
        for i, group in enumerate(groups):
            if group == '0':
                if current_start == -1:
                    current_start = i
                    current_len = 1
                else:
                    current_len += 1
            else:
                if current_len > best_len:
                    best_start = current_start
                    best_len = current_len
                current_start = -1
                current_len = 0
        
        if current_len > best_len:
            best_start = current_start
            best_len = current_len
        
        if best_len > 1:
            groups_before = groups[:best_start]
            groups_after = groups[best_start + best_len:]
            if not groups_before and not groups_after:
                return '::'
            elif not groups_before:
                return '::' + ':'.join(groups_after)
            elif not groups_after:
                return ':'.join(groups_before) + '::'
            else:
                return ':'.join(groups_before) + '::' + ':'.join(groups_after)
        
        return ':'.join(groups)
    
    def calculate_supernet(self) -> dict:
        """
        Calculate the supernet that encompasses all given networks.
        
        Returns:
            Dictionary with supernet information
        """
        if not self.parsed_networks:
            raise ValueError("No networks provided")
        
        if len(self.parsed_networks) == 1:
            # Only one network, return it as-is
            net = self.parsed_networks[0]
            if self.is_ipv6:
                network_str = self._int_to_ipv6_compressed(net['network'])
            else:
                network_str = self._int_to_ip(net['network'])
            
            return {
                'supernet': f"{network_str}/{net['prefix']}",
                'network': net['network'],
                'prefix': net['prefix'],
                'input_networks': [n['original'] for n in self.parsed_networks],
                'count': 1,
                'is_contiguous': True
            }
        
        # Find min and max addresses
        max_bits = 128 if self.is_ipv6 else 32
        min_addr = min(n['network'] for n in self.parsed_networks)
        
        # Find the actual max address (end of the last network)
        max_addr_end = 0
        for net in self.parsed_networks:
            size = 2 ** (max_bits - net['prefix'])
            end = net['network'] + size - 1
            if end > max_addr_end:
                max_addr_end = end
        
        # Find the smallest prefix that contains both min and max
        for prefix in range(max_bits, -1, -1):  # Start from most specific
            mask = (2 ** max_bits - 1) << (max_bits - prefix) if prefix > 0 else 0
            supernet = min_addr & mask
            supernet_size = 2 ** (max_bits - prefix)
            supernet_end = supernet + supernet_size - 1
            
            if supernet <= min_addr and supernet_end >= max_addr_end:
                # Check if networks are contiguous
                is_contiguous = self._check_contiguous(supernet, prefix)
                
                if self.is_ipv6:
                    network_str = self._int_to_ipv6_compressed(supernet)
                else:
                    network_str = self._int_to_ip(supernet)
                
                return {
                    'supernet': f"{network_str}/{prefix}",
                    'network': supernet,
                    'prefix': prefix,
                    'input_networks': [n['original'] for n in self.parsed_networks],
                    'count': len(self.parsed_networks),
                    'is_contiguous': is_contiguous
                }
        
        raise ValueError("Could not calculate supernet")
    
    def _check_contiguous(self, supernet: int, prefix: int) -> bool:
        """Check if input networks are contiguous within the supernet."""
        max_bits = 128 if self.is_ipv6 else 32
        
        # Sort networks by their network address
        sorted_nets = sorted(self.parsed_networks, key=lambda x: x['network'])
        
        # Check if networks touch each other (no gaps)
        for i in range(len(sorted_nets) - 1):
            current_net = sorted_nets[i]
            next_net = sorted_nets[i + 1]
            
            # Calculate where current network ends
            current_size = 2 ** (max_bits - current_net['prefix'])
            current_end = current_net['network'] + current_size
            
            # If there's a gap between current end and next start, not contiguous
            if current_end != next_net['network']:
                return False
        
        # Check if the networks exactly fill the supernet (no extra space)
        supernet_size = 2 ** (max_bits - prefix)
        total_covered = sum(2 ** (max_bits - net['prefix']) for net in self.parsed_networks)
        
        # If first network starts at supernet and total size matches, it's contiguous
        first_starts_at_supernet = sorted_nets[0]['network'] == supernet
        
        return first_starts_at_supernet and total_covered == supernet_size
    
    def format_output(self) -> str:
        """Format the supernet calculation results."""
        result = self.calculate_supernet()
        
        output = []
        output.append("\n" + "="*70)
        output.append("SliceNet - SUPERNET/CIDR AGGREGATION")
        output.append("="*70)
        
        output.append(f"Input Networks: {result['count']}")
        output.append("")
        for i, net in enumerate(result['input_networks'], 1):
            output.append(f"  {i}. {net}")
        
        output.append(f"\nSupernet: {result['supernet']}")
        output.append(f"Contiguous: {'Yes' if result['is_contiguous'] else 'No (contains gaps)'}")
        
        if not result['is_contiguous']:
            output.append("\nWarning: Input networks are not contiguous.")
            output.append("The supernet includes additional address space between networks.")
        
        output.append("="*70)
        output.append("")
        output.append("SliceNet 🌐 — Cut through networks with precision.")
        output.append("Made with ❤️ by SNB | https://github.com/SNB220")
        output.append("")
        
        return '\n'.join(output)


class ExportManager:
    """Handles exporting calculation results to various formats."""
    
    EXPORT_FOLDER = "exports"
    
    @staticmethod
    def _ensure_export_folder() -> None:
        """Create exports folder if it doesn't exist."""
        if not os.path.exists(ExportManager.EXPORT_FOLDER):
            os.makedirs(ExportManager.EXPORT_FOLDER)
            print(f"📁 Created '{ExportManager.EXPORT_FOLDER}/' folder for saved files")
    
    @staticmethod
    def prompt_save(result_text: str, calculation_type: str = "subnet") -> None:
        """
        Prompt user to save results with Y/N confirmation.
        
        Args:
            result_text: The formatted output text to save
            calculation_type: Type of calculation (subnet, range, supernet, etc.)
        """
        try:
            response = input("\n💾 Would you like to save these results? (Y/N): ").strip().upper()
            
            if response != 'Y':
                print("Results not saved.")
                return
            
            # Ask for format
            print("\nChoose export format:")
            print("  1. TXT  - Plain text file")
            print("  2. CSV  - Comma-separated values")
            print("  3. JSON - Structured data")
            
            format_choice = input("Enter choice (1/2/3): ").strip()
            
            if format_choice == '1':
                ExportManager._save_txt(result_text, calculation_type)
            elif format_choice == '2':
                ExportManager._save_csv(result_text, calculation_type)
            elif format_choice == '3':
                ExportManager._save_json(result_text, calculation_type)
            else:
                print("Invalid choice. Results not saved.")
        
        except (KeyboardInterrupt, EOFError):
            print("\n\nSave cancelled.")
    
    @staticmethod
    def _generate_filename(extension: str, calculation_type: str) -> str:
        """Generate timestamped filename in exports folder."""
        ExportManager._ensure_export_folder()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"slicenet_{calculation_type}_{timestamp}.{extension}"
        return os.path.join(ExportManager.EXPORT_FOLDER, filename)
    
    @staticmethod
    def _save_txt(result_text: str, calculation_type: str) -> None:
        """Save results as plain text file."""
        filename = ExportManager._generate_filename("txt", calculation_type)
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(result_text)
            print(f"\n✓ Results saved to: {filename}")
        except Exception as e:
            print(f"\n✗ Error saving file: {e}")
    
    @staticmethod
    def _save_csv(result_text: str, calculation_type: str) -> None:
        """Save results as CSV file."""
        filename = ExportManager._generate_filename("csv", calculation_type)
        
        try:
            # Parse the text output into key-value pairs
            data = ExportManager._parse_output_to_dict(result_text)
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Field', 'Value'])
                
                for key, value in data.items():
                    writer.writerow([key, value])
            
            print(f"\n✓ Results saved to: {filename}")
        except Exception as e:
            print(f"\n✗ Error saving file: {e}")
    
    @staticmethod
    def _save_json(result_text: str, calculation_type: str) -> None:
        """Save results as JSON file."""
        filename = ExportManager._generate_filename("json", calculation_type)
        
        try:
            # Parse the text output into structured data
            data = ExportManager._parse_output_to_dict(result_text)
            
            json_data = {
                "calculation_type": calculation_type,
                "timestamp": datetime.now().isoformat(),
                "results": data
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n✓ Results saved to: {filename}")
        except Exception as e:
            print(f"\n✗ Error saving file: {e}")
    
    @staticmethod
    def _parse_output_to_dict(text: str) -> Dict[str, Any]:
        """Parse formatted output text into dictionary."""
        data = {}
        lines = text.split('\n')
        
        for line in lines:
            # Skip decorative lines and headers
            if not line.strip() or line.strip().startswith('═') or line.strip().startswith('─') or line.strip().startswith('━'):
                continue
            if line.strip().startswith('║') or line.strip().startswith('│'):
                continue
            
            # Look for key-value pairs (lines with ':')
            if ':' in line:
                # Split on first colon only
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lstrip('•').strip()
                    value = parts[1].strip()
                    
                    # Skip empty values and section headers
                    if value and not value.startswith('═') and key:
                        data[key] = value
        
        return data


class BatchProcessor:
    """Handles batch processing of multiple IPs from a file."""
    
    @staticmethod
    def process_file(input_file: str, output_format: str = 'txt') -> None:
        """
        Process multiple IP addresses from an input file.
        
        Args:
            input_file: Path to input file (one IP/CIDR per line)
            output_format: Output format (txt, csv, json)
        """
        if not os.path.exists(input_file):
            print(f"\n✗ Error: File '{input_file}' not found.")
            return
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            if not lines:
                print(f"\n✗ Error: No valid IP addresses found in '{input_file}'")
                return
            
            print(f"\n📋 Found {len(lines)} IP address(es) to process.")
            response = input("Continue with batch processing? (Y/N): ").strip().upper()
            
            if response != 'Y':
                print("Batch processing cancelled.")
                return
            
            results = []
            
            for i, line in enumerate(lines, 1):
                print(f"\n[{i}/{len(lines)}] Processing: {line}")
                
                try:
                    # Parse the line
                    ip_address, subnet_mask, ipv6 = BatchProcessor._parse_line(line)
                    
                    # Calculate
                    if ipv6:
                        if subnet_mask.startswith('/'):
                            prefix = int(subnet_mask[1:])
                        else:
                            prefix = int(subnet_mask)
                        calculator = IPv6Calculator(ip_address, prefix)
                        output = calculator.format_output()
                    else:
                        calculator = SubnetCalculator(ip_address, subnet_mask)
                        output = calculator.format_output()
                    
                    results.append({
                        'input': line,
                        'output': output,
                        'success': True
                    })
                    
                    print("  ✓ Success")
                
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    results.append({
                        'input': line,
                        'error': str(e),
                        'success': False
                    })
            
            # Save results
            BatchProcessor._save_batch_results(results, output_format, input_file)
        
        except Exception as e:
            print(f"\n✗ Error processing file: {e}")
    
    @staticmethod
    def _parse_line(line: str) -> Tuple[str, str, bool]:
        """Parse a line from input file into IP, mask, and IPv6 flag."""
        if '/' in line:
            parts = line.split('/')
            ip_address = parts[0].strip()
            subnet_mask = '/' + parts[1].strip()
        elif ' ' in line:
            parts = line.split()
            ip_address = parts[0].strip()
            subnet_mask = parts[1].strip()
        else:
            raise ValueError("Invalid format. Use IP/CIDR or IP MASK")
        
        ipv6 = ':' in ip_address
        return ip_address, subnet_mask, ipv6
    
    @staticmethod
    def _save_batch_results(results: List[Dict], format_type: str, input_filename: str) -> None:
        """Save batch processing results."""
        ExportManager._ensure_export_folder()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        
        if format_type == 'txt':
            filename = os.path.join(ExportManager.EXPORT_FOLDER, f"slicenet_batch_{base_name}_{timestamp}.txt")
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"SliceNet Batch Processing Results\n")
                f.write(f"Input File: {input_filename}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Processed: {len(results)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Entry {i}: {result['input']}\n")
                    f.write('=' * 80 + "\n")
                    
                    if result['success']:
                        f.write(result['output'])
                    else:
                        f.write(f"\nError: {result['error']}\n")
                    
                    f.write("\n")
        
        elif format_type == 'json':
            filename = os.path.join(ExportManager.EXPORT_FOLDER, f"slicenet_batch_{base_name}_{timestamp}.json")
            
            json_data = {
                "input_file": input_filename,
                "timestamp": datetime.now().isoformat(),
                "total_processed": len(results),
                "successful": sum(1 for r in results if r['success']),
                "failed": sum(1 for r in results if not r['success']),
                "results": []
            }
            
            for result in results:
                entry = {
                    "input": result['input'],
                    "success": result['success']
                }
                
                if result['success']:
                    entry['data'] = ExportManager._parse_output_to_dict(result['output'])
                else:
                    entry['error'] = result['error']
                
                json_data['results'].append(entry)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        elif format_type == 'csv':
            filename = os.path.join(ExportManager.EXPORT_FOLDER, f"slicenet_batch_{base_name}_{timestamp}.csv")
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Input', 'Status', 'Details'])
                
                for result in results:
                    if result['success']:
                        data = ExportManager._parse_output_to_dict(result['output'])
                        details = ' | '.join([f"{k}: {v}" for k, v in data.items()])
                        writer.writerow([result['input'], 'Success', details])
                    else:
                        writer.writerow([result['input'], 'Failed', result['error']])
        
        print(f"\n✓ Batch results saved to: {filename}")


def is_ipv6(ip_str: str) -> bool:
    """Check if the IP address is IPv6."""
    return ':' in ip_str


def parse_arguments(args: list) -> Tuple[str, str, bool, Optional[int], bool]:
    """
    Parse command-line arguments.
    
    Returns:
        Tuple of (ip_address, subnet_mask, show_binary, show_subnets, is_ipv6)
    """
    if len(args) < 2:
        print_usage()
        sys.exit(1)
    
    show_binary = '--binary' in args or '-b' in args
    show_subnets = None
    
    # Check for --subnets flag
    for i, arg in enumerate(args):
        if arg == '--subnets' or arg == '-s':
            if i + 1 < len(args) and args[i + 1].isdigit():
                show_subnets = int(args[i + 1])
            else:
                print("Error: --subnets requires a CIDR value")
                sys.exit(1)
    
    # Remove flags from args
    args_clean = []
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg.startswith('-'):
            if arg in ['--subnets', '-s']:
                skip_next = True
            continue
        args_clean.append(arg)
    
    if len(args_clean) < 2:
        print_usage()
        sys.exit(1)
    
    ip_with_cidr = args_clean[1]
    
    # Check if IP contains CIDR notation
    if '/' in ip_with_cidr:
        parts = ip_with_cidr.split('/')
        ip_address = parts[0]
        subnet_mask = '/' + parts[1]
    elif len(args_clean) >= 3:
        # Separate IP and mask arguments
        ip_address = args_clean[1]
        subnet_mask = args_clean[2]
    else:
        print("Error: Subnet mask/prefix not provided")
        print_usage()
        sys.exit(1)
    
    # Detect IPv6
    ipv6 = is_ipv6(ip_address)
    
    return ip_address, subnet_mask, show_binary, show_subnets, ipv6


def print_usage():
    """Print usage instructions."""
    usage = """
Usage:
    python slicenet.py <IP_ADDRESS> <SUBNET_MASK> [OPTIONS]
    python slicenet.py <IP_ADDRESS>/<CIDR> [OPTIONS]
    python slicenet.py <IPv6_ADDRESS>/<PREFIX> [OPTIONS]
    python slicenet.py --range <START_IP> <END_IP>
    python slicenet.py --supernet <NETWORK1> <NETWORK2> [NETWORK3 ...]

Arguments:
    IP_ADDRESS      IPv4 address (e.g., 192.168.1.100)
    IPv6_ADDRESS    IPv6 address (e.g., 2001:db8::1 or 2001:0db8:0000:0000:0000:0000:0000:0001)
    SUBNET_MASK     Subnet mask in decimal (e.g., 255.255.255.0) or CIDR (e.g., 24 or /24)
    CIDR/PREFIX     CIDR notation for IPv4 (e.g., /24) or prefix for IPv6 (e.g., /64)

Options:
    --binary, -b                  Show binary representation and explain bitwise operations
    --subnets <CIDR/PREFIX>, -s   Generate table of all subnets of given size (IPv4 and IPv6)
    --range, -r                   Convert IP range to CIDR notation(s)
    --supernet, --aggregate, -a   Calculate supernet/aggregate CIDR for multiple networks
    --batch <FILE> [FORMAT], -f   Process multiple IPs from file (format: txt, csv, json)
    --help, -h                    Show this help message

Note: After each calculation, you'll be prompted to save results (Y/N) in TXT/CSV/JSON format.

IPv4 Examples:
    python slicenet.py 145.71.55.1/18
    python slicenet.py 145.71.64.0 255.255.255.128
    python slicenet.py 192.168.1.100/24 --binary
    python slicenet.py 10.0.0.50 255.255.0.0 -b
    python slicenet.py 192.168.1.0/24 --subnets 26
    python slicenet.py 10.0.0.0/16 -s 24

IPv6 Examples:
    python slicenet.py 2001:db8::1/64
    python slicenet.py 2001:0db8:85a3:0000:0000:8a2e:0370:7334/48
    python slicenet.py fe80::1/10 --binary
    python slicenet.py ::1/128
    python slicenet.py 2001:db8::/32 --subnets 48
    python slicenet.py 2001:db8:abcd::/48 -s 64

IP Range to CIDR Examples:
    python slicenet.py --range 192.168.1.10 192.168.1.50
    python slicenet.py -r 10.0.0.0 10.0.3.255
    python slicenet.py --range 2001:db8::1 2001:db8::ffff

Supernet/CIDR Aggregation Examples:
    python slicenet.py --supernet 192.168.0.0/24 192.168.1.0/24
    python slicenet.py -a 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24
    python slicenet.py --aggregate 2001:db8::/64 2001:db8:0:1::/64

Batch Processing Examples:
    python slicenet.py --batch ips.txt
    python slicenet.py --batch networks.txt json
    python slicenet.py -f subnets.txt csv
"""
    print(usage)


def print_help():
    """Print comprehensive help message."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                          SliceNet - HELP MENU                                ║
║                        IP Subnet Calculator Tool                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

A powerful tool for IPv4 and IPv6 subnet calculations, supporting 12 key features.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 USAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Subnet Calculation:
        python slicenet.py <IP>/<CIDR> [OPTIONS]
        python slicenet.py <IP> <MASK> [OPTIONS]

    Range to CIDR:
        python slicenet.py --range <START_IP> <END_IP>
        python slicenet.py -r <START_IP> <END_IP>

    Supernet/Aggregation:
        python slicenet.py --supernet <NETWORK1> <NETWORK2> [...]
        python slicenet.py -a <NETWORK1> <NETWORK2> [...]

    Batch Processing:
        python slicenet.py --batch <FILE> [FORMAT]
        python slicenet.py -f <FILE> [txt|csv|json]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OPTIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    -h, --help              Show this help message and exit
    -b, --binary            Show binary representation (32-bit for IPv4, 128-bit for IPv6)
    -s, --subnets <N>       Generate subnet table with prefix length N
    -r, --range             Convert IP range to CIDR notation(s)
    -a, --supernet          Calculate supernet/aggregate CIDR for multiple networks
                            (also: --aggregate)
    -f, --batch <FILE>      Process multiple IPs from file (also: --batch)
                            Optional: specify format (txt, csv, json)

    💾 Note: After calculations, you'll be prompted to save results (Y/N).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FEATURES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ✓ Basic Subnet Calculation      Calculate network, broadcast, host range
    ✓ Binary Representation          Understand bitwise operations
    ✓ IP Class Detection             Identify Class A/B/C/D/E (IPv4)
    ✓ IP Type Classification         Private, Public, Loopback, Link-Local, etc.
    ✓ Wildcard Mask                  For ACLs and routing configs (IPv4)
    ✓ Previous Network Calculation   Backward subnet planning
    ✓ Next Network Calculation       Forward subnet planning
    ✓ Subnet Table Generator         Divide networks into smaller subnets
    ✓ IP Range to CIDR Converter     Convert ranges to optimal CIDR blocks
    ✓ Supernet/CIDR Aggregation      Combine multiple networks into summary route
    ✓ Export/Save Results            Save to CSV/JSON/TXT with Y/N prompt
    ✓ Batch Processing               Process multiple IPs from file
    ✓ IPv6 Format Conversion         Compressed and expanded formats
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK START EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Basic IPv4 Calculation:
        python slicenet.py 192.168.1.100/24

    IPv4 with Decimal Mask:
        python slicenet.py 192.168.1.0 255.255.255.0

    Show Binary View:
        python slicenet.py 192.168.1.100/24 --binary

    Generate Subnet Table (divide /24 into /26 subnets):
        python slicenet.py 192.168.1.0/24 --subnets 26

    Convert IP Range to CIDR:
        python slicenet.py --range 192.168.1.10 192.168.1.50

    Combine Networks (Supernet):
        python slicenet.py --supernet 192.168.0.0/24 192.168.1.0/24

    Batch Process Multiple IPs:
        python slicenet.py --batch networks.txt json

    Basic IPv6 Calculation:
        python slicenet.py 2001:db8::1/64

    IPv6 Subnet Table:
        python slicenet.py 2001:db8::/48 --subnets 52

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 COMMON USE CASES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Network Planning:
        Design office networks with proper subnetting
        Example: python slicenet.py 10.0.0.0/16 -s 24

    Firewall Rules:
        Convert IP ranges to CIDR for ACLs
        Example: python slicenet.py -r 203.0.113.20 203.0.113.35

    Learning Subnetting:
        Understand subnet math with binary view
        Example: python slicenet.py 192.168.1.0/24 -b

    Documentation:
        Generate subnet tables for network docs
        Example: python slicenet.py 172.16.0.0/22 -s 26

    IPv6 Migration:
        Plan and calculate IPv6 networks
        Example: python slicenet.py 2001:db8::/32 -s 48

    Batch Processing:
        Process multiple networks from a file
        Example: python slicenet.py --batch iplist.txt csv

    Export Results:
        Save calculations to files for documentation
        After any calculation, choose Y to save as TXT/CSV/JSON

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 OUTPUT INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    IPv4 Results Include:
        • IP Address & Class (A/B/C/D/E)
        • IP Type (Private RFC 1918, Public, Loopback, etc.)
        • Network Address
        • Subnet Mask (decimal and CIDR)
        • Wildcard Mask
        • First & Last Host IPs
        • Broadcast IP
        • Total & Usable Host count
        • Previous Network address
        • Next Network address

    IPv6 Results Include:
        • IPv6 Address (full and compressed)
        • Prefix Length
        • Address Type (Global, Link-Local, ULA, etc.)
        • Network Address (full and compressed)
        • First & Last Addresses
        • Total Addresses
        • Previous Network
        • Next Network

    Range to CIDR Output:
        • Start & End IPs
        • Total IP count
        • Optimal CIDR blocks (minimal coverage)
        • IP count per block
        • Range covered by each block

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CIDR QUICK REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    IPv4:
        /30  →  4 IPs (2 usable)      →  Point-to-point links
        /29  →  8 IPs (6 usable)      →  Very small networks
        /28  →  16 IPs (14 usable)    →  Small VLANs
        /27  →  32 IPs (30 usable)    →  Small departments
        /26  →  64 IPs (62 usable)    →  Medium departments
        /25  →  128 IPs (126 usable)  →  Large departments
        /24  →  256 IPs (254 usable)  →  Standard LAN (Class C)
        /23  →  512 IPs (510 usable)  →  Large LANs
        /22  →  1,024 IPs             →  Very large LANs
        /16  →  65,536 IPs            →  Class B network
        /8   →  16.7M IPs             →  Class A network

    IPv6:
        /128 →  Single address        →  Host routes
        /64  →  18.4 quintillion      →  Standard LAN segment
        /56  →  256 /64 subnets       →  Residential allocation
        /48  →  65,536 /64 subnets    →  Enterprise/site allocation
        /32  →  4.3 billion /64s      →  ISP allocation

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ABOUT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    SliceNet v1.0.0 - IP Subnet Calculator
    
    Author:  SNB
    GitHub:  https://github.com/SNB220
    License: MIT
    
    A powerful, feature-rich subnet calculator supporting both IPv4 and IPv6
    with export capabilities, batch processing, and comprehensive analysis.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
    print(help_text)


def print_banner():
    """Print SliceNet ASCII art banner."""
    banner = """
===============================================================================
    
     _____ _ _          _   _      _   
    / ____| (_)        | \\ | |    | |  
   | (___ | |_  ___ ___|  \\| | ___| |_ 
    \\___ \\| | |/ __/ _ \\ . ` |/ _ \\ __|
    ____) | | | (_|  __/ |\\  |  __/ |_ 
   |_____/|_|_|\\___\\___|_| \\_|\\___|\\__|
                                        
          Cut through networks with precision
    
    Version: 1.0.0  |  Author: SNB  |  GitHub: SNB220
    
===============================================================================
    
    Quick Start: python slicenet.py 192.168.1.0/24
    Full Help:   python slicenet.py --help
    Version:     python slicenet.py --version
    
"""
    print(banner)


def main():
    """Main entry point."""
    try:
        # Check for version flag
        if '--version' in sys.argv or '-v' in sys.argv:
            print("\n" + "="*60)
            print("  SliceNet - IP Subnet Calculator")
            print("="*60)
            print("  Version:  1.0.0")
            print("  Author:   SNB")
            print("  GitHub:   https://github.com/SNB220")
            print("  License:  MIT")
            print("="*60 + "\n")
            sys.exit(0)
        
        # Check for help flag first
        if '--help' in sys.argv or '-h' in sys.argv:
            print_help()
            sys.exit(0)
        
        # Show banner for interactive use (not for --help or --version)
        print_banner()
        
        # Check for --batch mode
        if '--batch' in sys.argv or '-f' in sys.argv:
            # Batch processing mode
            args = [arg for arg in sys.argv[1:] if arg not in ['--batch', '-f']]
            
            if len(args) < 1:
                print("\nError: --batch requires an input file\n")
                print("Example: python slicenet.py --batch ips.txt\n")
                print("Optional: python slicenet.py --batch ips.txt json\n")
                sys.exit(1)
            
            input_file = args[0]
            output_format = args[1] if len(args) > 1 else 'txt'
            
            if output_format not in ['txt', 'csv', 'json']:
                print(f"\nError: Invalid format '{output_format}'. Use txt, csv, or json\n")
                sys.exit(1)
            
            BatchProcessor.process_file(input_file, output_format)
            return
        
        # Check for --supernet mode
        if '--supernet' in sys.argv or '--aggregate' in sys.argv or '-a' in sys.argv:
            # Supernet/CIDR aggregation mode
            args = [arg for arg in sys.argv[1:] if arg not in ['--supernet', '--aggregate', '-a']]
            
            if len(args) < 2:
                print("\nError: --supernet requires at least 2 networks in CIDR notation\n")
                print("Example: python slicenet.py --supernet 192.168.0.0/24 192.168.1.0/24\n")
                sys.exit(1)
            
            calculator = SupernetCalculator(args)
            output = calculator.format_output()
            print(output)
            
            # Prompt to save
            ExportManager.prompt_save(output, "supernet")
            return
        
        # Check for --range mode
        if '--range' in sys.argv or '-r' in sys.argv:
            # Range to CIDR mode
            args = [arg for arg in sys.argv[1:] if arg not in ['--range', '-r']]
            
            if len(args) < 2:
                print("\nError: --range requires START_IP and END_IP\n")
                print_usage()
                sys.exit(1)
            
            start_ip = args[0]
            end_ip = args[1]
            
            converter = IPRangeToCIDR(start_ip, end_ip)
            output = converter.format_output()
            print(output)
            
            # Prompt to save
            ExportManager.prompt_save(output, "range")
            return
        
        # Normal subnet calculation mode
        ip_address, subnet_mask, show_binary, show_subnets, ipv6 = parse_arguments(sys.argv)
        
        if ipv6:
            # Handle IPv6
            # Extract prefix
            if subnet_mask.startswith('/'):
                prefix = int(subnet_mask[1:])
            else:
                prefix = int(subnet_mask)
            
            calculator = IPv6Calculator(ip_address, prefix, show_binary, show_subnets)
            output = calculator.format_output()
            print(output)
            
            # Prompt to save
            ExportManager.prompt_save(output, "ipv6")
        else:
            # Handle IPv4
            calculator = SubnetCalculator(ip_address, subnet_mask, show_binary, show_subnets)
            output = calculator.format_output()
            print(output)
            
            # Prompt to save
            ExportManager.prompt_save(output, "ipv4")
        
    except ValueError as e:
        print(f"\nError: {e}\n")
        print_usage()
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
