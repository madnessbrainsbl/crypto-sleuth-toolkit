# Crypto Sleuth Toolkit

A comprehensive collection of cryptographic analysis tools, scripts, and documentation for security research and reverse engineering.

## Project Structure

```
crypto-sleuth-toolkit/
├── CryKeX/          # CryKeX tool for cryptographic key extraction
├── docs/            # Documentation and references
├── scripts/         # Collection of analysis scripts
│   ├── JWT analysis tools
│   ├── Binary analysis tools
│   ├── Key finding utilities
│   ├── Dynamic analysis scripts
│   └── Memory analysis tools
└── tools/           # Additional tools and configurations
```

## Components

### CryKeX
A specialized tool for cryptographic key extraction from various sources.

### Scripts
The main collection of Python, JavaScript, and PowerShell scripts for:
- JWT token analysis and validation
- Binary analysis for cryptographic functions
- Key extraction from memory and binaries
- Static and dynamic analysis of encryption implementations
- Frida scripts for runtime cryptography hooking
- Cross-platform tools for Windows and QNX systems

### Documentation
Comprehensive documentation for using the various tools and understanding cryptographic analysis techniques.

### Tools
Additional utilities and configuration files for advanced analysis.

## Requirements

- Python 3.x
- Various Python libraries (check individual scripts for specific requirements)
- Frida (for dynamic analysis scripts)
- PowerShell (for Windows scripts)
- Java (for Java-based tools)
- GDB (for debugging scripts)

## Usage

Navigate to the specific directory and run the desired tool:

```bash
# For scripts
cd scripts
python script_name.py -h

# For CryKeX
cd CryKeX
./CryKeX.sh
```

## License

This toolkit is for educational and authorized security research purposes only. Use responsibly and only on systems you have permission to test.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.
