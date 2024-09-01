# No DPI
Uses simple SSL fragmentation to avoid DPI.
No system privileges needed.

Currently works in russia.

## How to install

Requires: Python 3.x

1) Download file nodpi.py and run `python3 nodpi.py` or open run.bat
2) Configure browser to use proxy on 127.0.0.1:8881
3) Enjoy!

## Known Bugs

- Doesn't bypass IP block
- Only TCP
- Doesn't work for HTTP only
- Not working with sites with strict TLS version
