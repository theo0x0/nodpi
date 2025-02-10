# No DPI [ver. 1.2]
Uses simple SSL fragmentation to avoid DPI.
No system privileges needed.

Currently works in Russia. Uses blocklist from russia-blacklist.txt You need to add new domains there or you can delete or rename this file to apply filter to all sites.

Простой прокси скрипт для обхода блокировок или замедления ТСПУ в России 

Alternatives: [GoodbyeDPI (Гудбай дипиай)](https://github.com/ValdikSS/GoodbyeDPI), [zapret (запрет)](https://github.com/bol-van/zapret)
Next versions: [No DPI 2](https://github.com/theo0x0/nodpi2), [No DPI 3 (Alpha)](https://github.com/theo0x0/nodpi3)

## How to install

Requires: Python >= 3.8

1) Download file nodpi.py and run `python3 nodpi.py` or open nodpi.py file
2) Configure browser to use proxy on 127.0.0.1:8881
3) In browser disable kyber
4) Enjoy!

## Known Bugs

- Doesn't bypass IP block
- Only TCP
- Doesn't work for HTTP only
- Not working with sites with old TLS
