# No DPI [Ver. 2.3]
Uses simple SSL fragmentation or fake packets to avoid DPI.
No system privileges needed.

Currently works in Russia.

Alternatives: [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)

## How to install

Requires: Python >= 3.8, npcap

1) Download file nodpi.py and run `python3 nodpi.py` or open nodpi.py file
2) Configure browser to use proxy on 127.0.0.1:8881 or configure your system to use local dns server
3) Disable kyber in browser
4) Configure: fake + fake_mode (1, 2, 3, 4) or/and fragment
5) Enjoy!

## Known Bugs

- Doesn't bypass IP block
- Only TCP
- Doesn't work for HTTP only
- Not working for blocked sites with old TLS
