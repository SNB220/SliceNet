# SliceNet - IP Subnet Calculator

A powerful Python-based CLI tool for calculating network details from IP addresses and subnet masks, supporting both IPv4 and IPv6.

**Author:** SNB | **GitHub:** [SNB220](https://github.com/SNB220) | **Version:** 1.0.0

## Quick Start

```bash
# Show help (comprehensive guide)
python slicenet.py --help

# IPv4 subnet calculation
python slicenet.py 192.168.1.100/24

# IPv6 subnet calculation
python slicenet.py 2001:db8::1/64

# Convert IP range to CIDR
python slicenet.py --range 192.168.1.10 192.168.1.50

# Generate subnet table
python slicenet.py 192.168.1.0/24 --subnets 26

# Show binary explanation
python slicenet.py 192.168.1.100/24 --binary
```

## Key Features

✅ **IPv4 & IPv6 Support** - Full support for both protocols  
✅ **12 Powerful Features** - From basic calculation to batch processing  
✅ **Range to CIDR** - Convert IP ranges to optimal CIDR notation(s)  
✅ **Supernet/CIDR Aggregation** - Combine multiple networks into summary route  
✅ **Export/Save Results** - Save calculations to CSV, JSON, or TXT files  
✅ **Batch Processing** - Process multiple IPs from a file  
✅ **Subnet Table Generator** - Divide networks into smaller subnets  
✅ **Binary View** - Understand the math behind subnetting  
✅ **IP Classification** - Detect IP class, type (private/public), and more  
✅ **No Dependencies** - Uses only Python standard library  
✅ **Cross-Platform** - Works on Windows, Linux, and macOS  

## Installation

**Requirements:** Python 3.7+

```bash
# Clone or download this repository
cd path/to/Sub-mask

# Run immediately - no installation needed!
python slicenet.py --help
```

## File Organization

```
SliceNet/
├── slicenet.py          # Main calculator
├── README.md            # This file
├── docs/                # 📚 All documentation
│   ├── FEATURES.md     # Complete feature reference
│   ├── GUIDE.md        # Examples & tutorials
│   └── ...             # More guides
├── exports/             # 💾 Your saved results (auto-created)
└── ARCHIVE/             # Old documentation
```

See **[DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md)** for complete file organization.

## Basic Usage

```bash
# Subnet calculation with CIDR notation
python slicenet.py <IP>/<PREFIX>

# Subnet calculation with decimal mask
python slicenet.py <IP> <MASK>

# IP range to CIDR converter
python slicenet.py --range <START_IP> <END_IP>

# Options:
#   --binary, -b     Show binary representation
#   --subnets N, -s  Generate subnet table (specify new prefix length)
#   --range, -r      Convert IP range to CIDR
```

## Example Output

```
==================================================
IP SUBNET CALCULATOR RESULTS
==================================================
IP Address: 192.168.1.100
IP Class: C
IP Type: Private (RFC 1918: 192.168.0.0/16)
Network Address: 192.168.1.0
Subnet Mask: 255.255.255.0 (/24)
Wildcard Mask: 0.0.0.255
First Host IP: 192.168.1.1
Last Host IP: 192.168.1.254
Broadcast IP: 192.168.1.255
Total Hosts: 256
Usable Hosts: 254
Next Network: 192.168.2.0
==================================================
```

## Documentation

📘 **[FEATURES.md](docs/FEATURES.md)** - Complete feature reference (all 12 features)  
📗 **[GUIDE.md](docs/GUIDE.md)** - Examples, tutorials, and real-world scenarios  
📦 **[EXPORT_BATCH_DEMO.md](docs/EXPORT_BATCH_DEMO.md)** - Export & batch processing guide  

**All saved files go to:** `exports/` folder (auto-created)

## Common Examples

### IPv4 Examples

```bash
# Basic /24 network
python slicenet.py 192.168.1.100/24

# With decimal subnet mask
python slicenet.py 10.0.0.1 255.255.255.0

# Show binary explanation
python slicenet.py 192.168.1.1/24 --binary

# Divide /24 into /26 subnets
python slicenet.py 192.168.1.0/24 --subnets 26

# Convert IP range to CIDR
python slicenet.py -r 192.168.1.10 192.168.1.50

# Combine networks into supernet
python slicenet.py --supernet 192.168.0.0/24 192.168.1.0/24

# Process multiple IPs from file
python slicenet.py --batch networks.txt json
```

After each calculation, you'll be prompted to save results (Y/N) in TXT, CSV, or JSON format.

### IPv6 Examples

```bash
# Basic /64 network
python slicenet.py 2001:db8::1/64

# Link-local address
python slicenet.py fe80::1/10

# With binary view
python slicenet.py 2001:db8::1/64 --binary

# Divide /48 into /52 subnets
python slicenet.py 2001:db8::/48 --subnets 52

# Combine IPv6 networks
python slicenet.py -a 2001:db8::/64 2001:db8:0:1::/64

# Convert IPv6 range to CIDR
python slicenet.py -r 2001:db8::1 2001:db8::ffff
```

## Feature Highlights

| Feature | IPv4 | IPv6 | Description |
|---------|------|------|-------------|
| Subnet Calculation | ✅ | ✅ | Calculate network, broadcast, host range |
| Binary View | ✅ | ✅ | Show bitwise operations (32-bit/128-bit) |
| IP Classification | ✅ | ✅ | Detect class, type, scope |
| Wildcard Mask | ✅ | N/A | For ACLs and routing configs |
| Next Network | ✅ | ✅ | Sequential subnet planning |
| Subnet Table | ✅ | ✅ | Divide into smaller subnets |
| Range to CIDR | ✅ | ✅ | Optimal CIDR block calculation |

## Testing

Run the test suite:

```bash
python test_slicenet.py
```

## Use Cases

- **Network Planning** - Design office networks with proper subnetting
- **Firewall Rules** - Convert IP ranges to CIDR for ACLs
- **Education** - Learn subnetting with binary view
- **Documentation** - Generate subnet tables for network docs
- **IPv6 Migration** - Plan and calculate IPv6 networks
- **Cloud Networking** - Configure AWS, Azure, GCP security groups

## Author

**SNB**  
GitHub: [@SNB220](https://github.com/SNB220)

## Contributing

Contributions welcome! Please test your changes with `test_slicenet.py`.

Found a bug or have a feature request? [Open an issue](https://github.com/SNB220/slicenet/issues)

## License

MIT License - feel free to use this tool in your projects!

## Support

⭐ **Star this project** on [GitHub](https://github.com/SNB220) if you find it useful!

---

**Need Help?** See [GUIDE.md](docs/GUIDE.md) for detailed examples and tutorials!
