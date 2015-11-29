-- DEBIAN APTs
python
python-torctl
tor
privoxy
vidalia

/etc/privoxy/config add at EOF
forward-socks4a / 127.0.0.1:9050 .

Alter hashed password:
tor --hash-password PASS
Script uses default PASS: 123

/etc/tor/torrc uncomment:
ControlPort 9051
HashedControlPassword 16:25F9C31C5E6D33A96086A4CEE7A6818CDBA0EA3EADE19118E65D95AC19

ln -s PATH_TO/anonbuster.py /usr/bin/anonbuster

-- Start Tor
-- Start Privoxy

Usage: anonbuster [options]

Options:
  -h, --help         show this help message and exit
  -u URL, --url=URL  target url (include http:// or https://)
  -w WORDLIST        path to wordlist
  -f FORM            query string for POST form
  -p PASSWD          password key of POST form
  -l FAILMATCH       regex fail message from url (\ backslash special
                     characters)
  -c                 add cookie session to POST form
  -k COOKIEFORM      cookie's key or value to POST form
  -e COOKIEMATCH     regex to fetch cookie session from url (include
                     parentheses (.*?) for match)
  -m                 invert key/value pair of cookie session POST form (remove
                     pair from form)
  -a USERAGENT       broswer user agent string to fake
  -t TORIP           number of tries before renewing TOR end node IP
  -s SKIPWORDS       skip number of initial words from wordlist
  -r FORKS           number of forks (childs) to perform scan
  -x URLMAXTRIES     number of tries to url before exit
  -i REDIRECT        number of tries to redirect urls before exit

Usage: anonbuster [options]

Required options: -u, -w, -f, -p, -l
