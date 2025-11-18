## SID Hex Decoder

A lightweight Python tool that converts the hexadecimal SID returned by SQL Server’s `sys.fn_varbintohexstr(SUSER_SID())` into the standard Windows SID format (`S-1-...`).
Useful for penetration testers, incident responders, forensics analysts, and anyone who needs to decode raw SID values extracted from SQL Server.

## Overview

When querying SQL Server for a user’s SID, for example:
```sql
SELECT sys.fn_varbintohexstr(SUSER_SID('DOMAIN\Administrator'));
```
The result comes back as a hex-encoded binary SID (e.g., `0x0105000000000005150000009B8AC404...`).</br>
This script converts that hex string into a readable Windows Security Identifier.

## Usage
### Command-Line Argument

```bash
python3 decodeSID.py 0x0105000000000005150000009B8AC404...
```

### Interactive Mode

```bash
python3 decodeSID.py
Enter SID in hex (e.g. 0x010500000000000515000000...):
```

### Example Output:
```
Decoded SID: S-1-5-21-123456789-987654321-1122334455-500
```
