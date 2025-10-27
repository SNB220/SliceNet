# SliceNet - IP Subnet Calculator

🌐 **Cut through networks with precision**

A powerful, professional Python-based CLI tool for network calculations, supporting both IPv4 and IPv6 with intelligent error handling and export capabilities.

**Author:** SNB | **GitHub:** [SNB220](https://github.com/SNB220) | **Version:** 1.0.0

## ✨ What's New

🚀 **Interactive Mode** - Run `python slicenet.py` for continuous command prompt  
🎨 **Stylish CLI Banner** - Eye-catching ASCII art welcome screen  
🔍 **IP Analysis Mode** - Just enter an IP (no mask needed) for quick info  
📝 **Smart Error Messages** - Helpful suggestions and examples for every error  
💾 **Auto-Export Folder** - Saves files to `exports/` (auto-created)  

## Quick Start

```bash
# Interactive mode - No need to type "python slicenet.py" repeatedly!
python slicenet.py
# Then enter commands like: 192.168.1.100/24
# Type 'exit' when done

# Show stylish help menu
python slicenet.py --help

# Quick IP lookup (no subnet mask needed!)
python slicenet.py 192.168.1.100

# IPv4 subnet calculation
python slicenet.py 192.168.1.100/24

# IPv6 subnet calculation
python slicenet.py 2001:db8::1/64

# Convert IP range to CIDR
python slicenet.py --range 192.168.1.10 192.168.1.50

# Aggregate multiple networks
python slicenet.py --supernet 192.168.1.0/24 192.168.2.0/24

# Generate subnet table
python slicenet.py 192.168.1.0/24 --subnets 26

# Batch process from file
python slicenet.py --batch ips.txt json
```

## Key Features

✅ **Interactive Mode** - Continuous command prompt for easier workflows  
✅ **IPv4 & IPv6 Support** - Full support for both protocols  
✅ **14 Powerful Features** - From basic calculation to batch processing  
✅ **IP Analysis Mode** - Quick lookup without subnet mask  
✅ **Range to CIDR** - Convert IP ranges to optimal CIDR notation(s)  
✅ **Supernet/CIDR Aggregation** - Combine multiple networks into summary route  
✅ **Export/Save Results** - Save calculations to CSV, JSON, or TXT files  
✅ **Batch Processing** - Process multiple IPs from a file  
✅ **Subnet Table Generator** - Divide networks into smaller subnets  
✅ **Binary View** - Understand the math behind subnetting  
✅ **IP Classification** - Detect IP class, type (private/public), and more  
✅ **Smart Error Handling** - Helpful suggestions for every mistake  
✅ **Stylish Interface** - Professional ASCII art banner  
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
├── exports/             # 💾 Your saved results (auto-created)

```


## Basic Usage

### Interactive Mode (Recommended!)

The easiest way to use SliceNet - no need to retype `python slicenet.py` every time:

```bash
# Start interactive mode
python slicenet.py

# Now enter commands directly at the SliceNet> prompt:
SliceNet> 192.168.1.0/24
SliceNet> 10.0.0.50
SliceNet> 2001:db8::1/64
SliceNet> --range 192.168.1.10 192.168.1.50
SliceNet> help
SliceNet> exit
```

### Command-Line Mode

```bash
# Quick IP analysis (no subnet mask needed!)
python slicenet.py <IP_ADDRESS>

# Subnet calculation with CIDR notation
python slicenet.py <IP>/<PREFIX>

# Subnet calculation with decimal mask
python slicenet.py <IP> <MASK>

# IP range to CIDR converter
python slicenet.py --range <START_IP> <END_IP>

# Supernet/aggregate networks
python slicenet.py --supernet <NETWORK1> <NETWORK2> [...]

# Batch processing
python slicenet.py --batch <FILE> [FORMAT]

# Options:
#   --binary, -b     Show binary representation
#   --subnets N, -s  Generate subnet table (specify new prefix length)
#   --range, -r      Convert IP range to CIDR
#   --supernet, -a   Aggregate multiple networks
#   --batch, -f      Process multiple IPs from file
#   --help, -h       Show comprehensive help
#   --version, -v    Show version information
```

## Example Output

### IP Analysis (No Subnet Mask)
```
======================================================================
SliceNet - IP ADDRESS ANALYSIS
======================================================================
IP Address: 192.168.1.100

IP Class: C
IP Type: Private (RFC 1918: 192.168.0.0/16)

CLASSFUL NETWORK INFORMATION:
----------------------------------------------------------------------
Default Subnet Mask: 255.255.255.0 (/24)
Network Address: 192.168.1.0
First Host: 192.168.1.1
Last Host: 192.168.1.254
Broadcast Address: 192.168.1.255
Total Hosts: 256
Usable Hosts: 254

COMMON SUBNET MASK POSSIBILITIES:
----------------------------------------------------------------------
  /24  (255.255.255.0   ) → 192.168.1.0      (     254 usable hosts)
  /25  (255.255.255.128 ) → 192.168.1.0      (     126 usable hosts)
  /26  (255.255.255.192 ) → 192.168.1.64     (      62 usable hosts)
  /27  (255.255.255.224 ) → 192.168.1.96     (      30 usable hosts)
  /28  (255.255.255.240 ) → 192.168.1.96     (      14 usable hosts)
  /29  (255.255.255.248 ) → 192.168.1.96     (       6 usable hosts)
  /30  (255.255.255.252 ) → 192.168.1.100    (       2 usable hosts)

💡 TIP: Run with subnet mask for detailed calculation
======================================================================
```

### Subnet Calculation
```
==================================================
SliceNet - IPv4 SUBNET CALCULATOR
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
Previous Network: 192.168.0.0
Next Network: 192.168.2.0
==================================================

SliceNet 🌐 — Cut through networks with precision.
Made with ❤️ by SNB | https://github.com/SNB220

💾 Would you like to save these results? (Y/N):
```

### Smart Error Handling
```
======================================================================
❌ ERROR
======================================================================

Invalid CIDR notation: /35. Must be between /0 and /32

💡 SUGGESTION:
   IPv4 CIDR must be between /0 and /32.

📝 EXAMPLE:
   python slicenet.py 192.168.1.0/24

📖 For complete usage guide, run:
   python slicenet.py --help

======================================================================
```

## Common Examples

### Quick IP Lookup (New!)

```bash
# Analyze any IP without subnet mask
python slicenet.py 8.8.8.8           # Public IP
python slicenet.py 192.168.1.100     # Private IP
python slicenet.py 127.0.0.1         # Loopback
python slicenet.py 2001:db8::1       # IPv6

# Shows: IP class, type, classful network, common subnet possibilities
```

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
python slicenet.py --range 192.168.1.10 192.168.1.50

# Combine networks into supernet
python slicenet.py --supernet 192.168.0.0/24 192.168.1.0/24

# Process multiple IPs from file
python slicenet.py --batch networks.txt json
```

**💡 Note:** After each calculation, you'll be prompted to save results (Y/N) in TXT, CSV, or JSON format.  
**📁 Files are saved to:** `exports/` folder (auto-created on first save)

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
| **IP Analysis** | ✅ | ✅ | Quick lookup without subnet mask |
| Subnet Calculation | ✅ | ✅ | Calculate network, broadcast, host range |
| Binary View | ✅ | ✅ | Show bitwise operations (32-bit/128-bit) |
| IP Classification | ✅ | ✅ | Detect class, type, scope |
| Wildcard Mask | ✅ | N/A | For ACLs and routing configs |
| Next/Previous Network | ✅ | ✅ | Sequential subnet planning |
| Subnet Table | ✅ | ✅ | Divide into smaller subnets |
| Range to CIDR | ✅ | ✅ | Optimal CIDR block calculation |
| Supernet Aggregation | ✅ | ✅ | Combine networks into summary |
| Export Results | ✅ | ✅ | TXT, CSV, JSON formats |
| Batch Processing | ✅ | ✅ | Process multiple IPs from file |
| **Smart Errors** | ✅ | ✅ | Helpful suggestions & examples |

## Testing

Run the test suite:

```bash
python test_slicenet.py
```

## Use Cases

- 🔍 **Quick IP Lookup** - Instant analysis of any IP without remembering subnet masks
- **Network Planning** - Design office networks with proper subnetting
- **Firewall Rules** - Convert IP ranges to CIDR for ACLs
- **Education** - Learn subnetting with binary view and helpful error messages
- **Documentation** - Generate subnet tables for network docs
- **IPv6 Migration** - Plan and calculate IPv6 networks
- **Cloud Networking** - Configure AWS, Azure, GCP security groups
- **Troubleshooting** - Verify network configurations with smart error guidance

## What Makes SliceNet Special?

🎨 **Beautiful Interface**
- Stylish ASCII art banner
- Interactive mode with continuous prompts
- Clean, professional output formatting
- Color-coded information (when terminal supports it)

🧠 **Intelligent Features**
- **Interactive Mode**: Run once, enter multiple commands without retyping
- **IP Analysis Mode**: Just type an IP - no subnet mask required!
- **Smart Error Messages**: Every error includes why it failed, helpful suggestions, and examples
- **Auto-Export Folder**: Saves organized results automatically

💪 **Powerful Yet Simple**
- Zero dependencies - just Python 3.7+
- Works immediately - no installation or setup
- Comprehensive help system with examples
- Production-ready code with extensive testing

🌐 **Complete Network Toolkit**
- 14 features covering all common networking tasks
- IPv4 and IPv6 full support
- From simple lookups to complex batch processing
- Export to multiple formats (TXT, CSV, JSON)

## Author

**SNB**  
GitHub: [@SNB220](https://github.com/SNB220)


## Support

⭐ **Star this project** on [GitHub](https://github.com/SNB220/SliceNet) if you find it useful!

🐛 **Found a bug?** Open an issue on GitHub  
💡 **Have a suggestion?** Contributions are welcome!

---

**SliceNet** 🌐 — Cut through networks with precision.  
Made with ❤️ by SNB

