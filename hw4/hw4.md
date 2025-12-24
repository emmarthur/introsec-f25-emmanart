# Homework 4 - Network Security

## Part 1: Networking Room

I have completed the networking room.

![Networking Room Complete](images/networkingroomcomplete_emmanart.png)

## Part 2: Passive Reconnaissance

I have completed the passive reconnaissance room.

![Passive Reconnaissance Complete](images/passive_reconnaisance_complete_emmanart.png)

## Part 3: Active Reconnaissance

I have completed the active reconnaissance room.

![Active Reconnaissance Complete](images/active_reconnaisance_complete_emmanart.png)

## Part 4: Nmap

I have completed the nmap room.

![Nmap Complete](images/nmap_completed_emmanart.png)

## Part 5: tcpdump/BPF Practice Exercises

I verified that tcpdump is installed on my system by running `tcpdump --version`. The output shows:

```sh
❯ tcpdump --version
tcpdump version 4.99.5
libpcap version 1.10.5 (with TPACKET_V3)
OpenSSL 3.5.2 5 Aug 2025
64-bit build, 64-bit time_t
```

I listed the available network interfaces using `tcpdump -D`:

```sh
❯ tcpdump -D
1.eth0 [Up, Running, Connected]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
4.docker0 [Up, Disconnected]
5.bluetooth-monitor (Bluetooth Linux Monitor) [Wireless]
6.nflog (Linux netfilter log (NFLOG) interface) [none]
7.nfqueue (Linux netfilter queue (NFQUEUE) interface) [none]
8.dbus-system (D-Bus system bus) [none]
9.dbus-session (D-Bus session bus) [none]
```

### Question 5.1: Capture DNS Packets Only

I performed a tcpdump capture to capture only DNS packets using the filter `port 53`. I ran the command with Unix epoch timestamps (`-tt`), hex and ASCII output (`-X`), full packet capture (`-s 0`), and limited to 10 packets (`-c 10`):

```sh
❯ sudo tcpdump -tt -X -s 0 -c 10 -i any port 53 &
[1] 9067
tcpdump: WARNING: any: That device doesn't support promiscuous mode
(Promiscuous mode not supported on the "any" device)
```

While tcpdump was running in the background, I generated DNS traffic by running multiple nslookup commands:

```sh
❯ nslookup google.com
nslookup github.com
nslookup stackoverflow.com
Server:         10.255.255.254
Address:        10.255.255.254#53

Non-authoritative answer:
Name:   google.com
Address: 142.250.73.110
Name:   google.com
Address: 2607:f8b0:400a:80c::200e

Server:         10.255.255.254
Address:        10.255.255.254#53

Non-authoritative answer:
Name:   github.com
Address: 140.82.116.3

Server:         10.255.255.254
Address:        10.255.255.254#53

Non-authoritative answer:
Name:   stackoverflow.com
Address: 104.18.32.7
Name:   stackoverflow.com
Address: 172.64.155.249
```

The tcpdump capture output shows 10 DNS packets with full data dumps in hex and ASCII format with Unix epoch timestamps:

```
1763606512.995366 lo    In  IP 10.255.255.254.36308 > 10.255.255.254.domain: 18691+ A? google.com. (28)
        0x0000:  4500 0038 9b37 0000 4011 c982 0aff fffe  E..8.7..@.......
        0x0010:  0aff fffe 8dd4 0035 0024 1631 4903 0100  .......5.$.1I...
        0x0020:  0001 0000 0000 0000 0667 6f6f 676c 6503  .........google.
        0x0030:  636f 6d00 0001 0001                      com.....

1763606513.016302 lo    In  IP 10.255.255.254.domain > 10.255.255.254.36308: 18691 1/0/0 A 142.250.73.110 (44)
        0x0000:  4500 0048 867c 4000 4011 9e2d 0aff fffe  E..H.|@.@..-....
        0x0010:  0aff fffe 0035 8dd4 0034 1641 4903 8180  .....5...4.AI...
        0x0020:  0001 0001 0000 0000 0667 6f6f 676c 6503  .........google.
        0x0030:  636f 6d00 0001 0001 c00c 0001 0001 0000  com.............
        0x0040:  00d0 0004 8efa 496e                      ......In

1763606513.016998 lo    In  IP 10.255.255.254.55630 > 10.255.255.254.domain: 60489+ AAAA? google.com. (28)
        0x0000:  4500 0038 8cbb 0000 4011 d7fe 0aff fffe  E..8....@.......
        0x0010:  0aff fffe d94e 0035 0024 1631 ec49 0100  .....N.5.$.1.I..
        0x0020:  0001 0000 0000 0000 0667 6f6f 676c 6503  .........google.
        0x0030:  636f 6d00 001c 0001                      com.....

1763606513.020527 lo    In  IP 10.255.255.254.domain > 10.255.255.254.55630: 60489 1/0/0 AAAA 2607:f8b0:400a:80c::200e (56)
        0x0000:  4500 0054 867d 4000 4011 9e20 0aff fffe  E..T.}@.@.......
        0x0010:  0aff fffe 0035 d94e 0040 164d ec49 8180  .....5.N.@.M.I..
        0x0020:  0001 0001 0000 0000 0667 6f6f 676c 6503  .........google.
        0x0030:  636f 6d00 001c 0001 c00c 001c 0001 0000  com.............
        0x0040:  0099 0010 2607 f8b0 400a 080c 0000 0000  ....&...@.......
        0x0050:  0000 200e                                ....

1763606513.030674 lo    In  IP 10.255.255.254.42128 > 10.255.255.254.domain: 47493+ PTR? 254.255.255.10.in-addr.arpa. (45)
        0x0000:  4500 0049 36f2 4000 4011 edb6 0aff fffe  E..I6.@.@.......
        0x0010:  0aff fffe a490 0035 0035 1642 b985 0100  .......5.5.B....
        0x0020:  0001 0000 0000 0000 0332 3534 0332 3535  .........254.255
        0x0030:  0332 3535 0231 3007 696e 2d61 6464 7204  .255.10.in-addr.
        0x0040:  6172 7061 0000 0c00 01                   arpa.....

1763606513.034590 lo    In  IP 10.255.255.254.34352 > 10.255.255.254.domain: 44428+ A? github.com. (28)
        0x0000:  4500 0038 cfb8 0000 4011 9501 0aff fffe  E..8....@.......
        0x0010:  0aff fffe 8630 0035 0024 1631 ad8c 0100  .....0.5.$.1....
        0x0020:  0001 0000 0000 0000 0667 6974 6875 6203  .........github.
        0x0030:  636f 6d00 0001 0001                      com.....

1763606513.035427 lo    In  IP 10.255.255.254.domain > 10.255.255.254.42128: 47493 NXDomain 0/1/0 (104)
        0x0000:  4500 0084 867e 4000 4011 9def 0aff fffe  E....~@.@.......
        0x0010:  0aff fffe 0035 a490 0070 167d b985 8183  .....5...p.}....
        0x0020:  0001 0000 0001 0000 0332 3534 0332 3535  .........254.255
        0x0030:  0332 3535 0231 3007 696e 2d61 6464 7204  .255.10.in-addr.
        0x0040:  6172 7061 0000 0c00 01c0 1800 0600 0100  arpa............
        0x0050:  0000 1d00 2f04 646e 7330 0370 6478 0365  ..../.dns0.pdx.e
        0x0060:  6475 000a 686f 7374 6d61 7374 6572 c03e  du..hostmaster.>
        0x0070:  78b4 bf0b 0000 3840 0000 0384 0036 ee80  x.....8@.....6..
        0x0080:  0000 0708                                ....

1763606513.038292 lo    In  IP 10.255.255.254.domain > 10.255.255.254.34352: 44428 1/0/0 A 140.82.116.3 (44)
        0x0000:  4500 0048 867f 4000 4011 9e2a 0aff fffe  E..H..@.@..*....
        0x0010:  0aff fffe 0035 8630 0034 1641 ad8c 8180  .....5.0.4.A....
        0x0020:  0001 0001 0000 0000 0667 6974 6875 6203  .........github.
        0x0030:  636f 6d00 0001 0001 c00c 0001 0001 0000  com.............
        0x0040:  001e 0004 8c52 7403                      .....Rt.

1763606513.039084 lo    In  IP 10.255.255.254.44692 > 10.255.255.254.domain: 11147+ AAAA? github.com. (28)
        0x0000:  4500 0038 9bf0 0000 4011 c8c9 0aff fffe  E..8....@.......
        0x0010:  0aff fffe ae94 0035 0024 1631 2b8b 0100  .......5.$.1+...
        0x0020:  0001 0000 0000 0000 0667 6974 6875 6203  .........github.
        0x0030:  636f 6d00 001c 0001                      com.....

1763606513.042925 lo    In  IP 10.255.255.254.domain > 10.255.255.254.44692: 11147 0/1/0 (93)
        0x0000:  4500 0079 8680 4000 4011 9df8 0aff fffe  E..y..@.@.......
        0x0010:  0aff fffe 0035 ae94 0065 1672 2b8b 8180  .....5...e.r+...
        0x0020:  0001 0000 0001 0000 0667 6974 6875 6203  .........github.
        0x0030:  636f 6d00 001c 0001 c00c 0006 0001 0000  com.............
        0x0040:  0dfb 0035 0464 6e73 3103 7030 3805 6e73  ...5.dns1.p08.ns
        0x0050:  6f6e 6503 6e65 7400 0a68 6f73 746d 6173  one.net..hostmas
        0x0060:  7465 72c0 3162 bbb2 3700 00a8 c000 001c  ter.1b..7.......
        0x0070:  2000 1275 0000 000e 10                   ...u.....

10 packets captured
28 packets received by filter
0 packets dropped by kernel
```

### Question 5.2: Capture TCP Packets to Ports 443/8080 Originating from My Host

For Exercise 2, I needed to capture TCP packets that originate from my host and are destined for either port 443 or 8080. I first determined my IP address using `hostname -I`, which returned `172.23.91.31`. I then ran tcpdump with a filter that matches TCP packets from my source IP going to destination ports 443 or 8080. As before, I enabled Unix epoch timestamps, hex/ASCII dumps, full packet capture, and limited the capture to 10 packets. I ran the command in the background so that I could generate HTTPS traffic in the same terminal:

```sh
❯ sudo tcpdump -tt -X -s 0 -c 10 -i any 'tcp and (dst port 443 or dst port 8080) and src host 172.23.91.31' &
[1] 126521
tcpdump: WARNING: any: That device doesn't support promiscuous mode
(Promiscuous mode not supported on the "any" device)
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
```

While the capture ran, I generated HTTPS traffic by sending an HTTP HEAD request to Google with curl:

```sh
❯ curl -I https://www.google.com
HTTP/2 200
content-type: text/html; charset=ISO-8859-1
content-security-policy-report-only: object-src 'none';base-uri 'self';script-src 'nonce-vwuBh9pDTCsAdIYFcAed8Q' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
accept-ch: Sec-CH-Prefers-Color-Scheme
p3p: CP="This is not a P3P policy! See g.co/p3phelp for more info."
date: Thu, 20 Nov 2025 15:15:08 GMT
server: gws
x-xss-protection: 0
x-frame-options: SAMEORIGIN
expires: Thu, 20 Nov 2025 15:15:08 GMT
cache-control: private
set-cookie: AEC=AaJma5uDn-VX5uMW1RByVLhh2B1LywnPJjYKsxXBlF6eSauncET_Xq-W_Q; expires=Tue, 19-May-2026 15:15:08 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
set-cookie: NID=526=F_CxPxeB1NxDpAARUuoherMbgQlT4c19xA3881flnS2nV9ktMTy8la3ErT8F-oIz5dCKQnX3DIvASC4Wdx5bCwGiWBCtEphneIYWknG-abmppoYfU2fydLwR3gO6uwSYXSt5fbJ01VeNXdiWS5L2K_hIUZbWZKs8zUPH2HDMJI4OZ-GiALVInS3I26hjqCjF3mX8XOVxAs4viNuIZvWy; expires=Fri, 22-May-2026 15:15:08 GMT; path=/; domain=.google.com; HttpOnly
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
```

Tcpdump captured 10 packets that match the required filter, each with full hex/ASCII dumps and Unix epoch timestamps:

```
1763651708.372500 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [S], seq 1067673169, win 64240, options [mss 1460,sackOK,TS val 365868128 ecr 0,nop,wscale 10], length 0
        0x0000:  4500 003c 0b9a 4000 4006 762c ac17 5b1f  E..<..@.@.v,..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6651 0000 0000  .."..F..?.fQ....
        0x0020:  a002 faf0 b924 0000 0204 05b4 0402 080a  .....$..........
        0x0030:  15ce b460 0000 0000 0103 030a            ...`........

1763651708.383056 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [.], ack 1285903585, win 63, options [nop,nop,TS val 365868138 ecr 1143229652], length 0
        0x0000:  4500 0034 0b9b 4000 4006 7633 ac17 5b1f  E..4..@.@.v3..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6652 4ca5 54e1  .."..F..?.fRL.T.
        0x0020:  8010 003f b91c 0000 0101 080a 15ce b46a  ...?...........j
        0x0030:  4424 4cd4                                D$L.

1763651708.385069 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [P.], seq 0:1701, ack 1, win 63, options [nop,nop,TS val 365868141 ecr 1143229652], length 1701
        0x0000:  4500 06d9 0b9c 4000 4006 6f8d ac17 5b1f  E.....@.@.o...[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6652 4ca5 54e1  .."..F..?.fRL.T.
        0x0020:  8018 003f bfc1 0000 0101 080a 15ce b46d  ...?...........m
        0x0030:  4424 4cd4 1603 0106 a001 0006 9c03 0332  D$L............2
        0x0040:  b261 730a 2c09 816c 1c2e 4d6b 24d4 d81b  .as.,..l..Mk$...
        0x0050:  df42 e75d e92b 98d3 5170 2c7a 3e08 2620  .B.].+..Qp,z>.& 
        0x0060:  08cf 6f64 f826 ac65 4cf8 cae1 eb8c 8257  ..od.&.eL......W
        0x0070:  187f 8354 2bd5 4d45 4170 72cb 8d32 d7fd  ...T+.MEApr..2..
        0x0080:  00b6 1302 1303 1301 c02c c030 00a3 009f  .........,.0....
        0x0090:  cca9 cca8 ccaa c0ad c09f c05d c061 c057  ...........].a.W
        0x00a0:  c053 00a7 c02b c02f 00a2 009e c0ac c09e  .S...+./........
        0x00b0:  c05c c060 c056 c052 00a6 c0af c0ae c0a3  .\.`.V.R........
        0x00c0:  c0a2 c024 c028 006b 006a c073 c077 00c4  ...$.(.k.j.s.w..
        0x00d0:  00c3 006d 00c5 c023 c027 0067 0040 c072  ...m...#.'.g.@.r
        0x00e0:  c076 00be 00bd 006c 00bf c00a c014 0039  .v.....l.......9
        0x00f0:  0038 0088 0087 c019 003a 0089 c009 c013  .8.......:......
        0x0100:  0033 0032 009a 0099 0045 0044 c018 0034  .3.2.....E.D...4
        0x0110:  009b 0046 009d c09d c051 009c c09c c050  ...F.....Q.....P
        0x0120:  c0a1 c0a0 003d 00c0 003c 00ba 0035 0084  .....=...<...5..
        0x0130:  002f 0096 0041 00ff 0100 059d 0000 0013  ./...A..........
        0x0140:  0011 0000 0e77 7777 2e67 6f6f 676c 652e  .....www.google.
        0x0150:  636f 6d00 0b00 0403 0001 0200 0a00 1200  com.............
        0x0160:  1011 ec00 1d00 1700 1e00 1800 1901 0001  ................
        0x0170:  0100 1000 0e00 0c02 6832 0868 7474 702f  ........h2.http/
        0x0180:  312e 3100 1600 0000 1700 0000 3100 0000  1.1.........1...
        0x0190:  0d00 3c00 3a09 0509 0609 0404 0305 0306  ..<.:...........
        0x01a0:  0308 0708 0808 1a08 1b08 1c08 0908 0a08  ...............
        0x01b0:  0b08 0408 0508 0604 0105 0106 0103 0302  ...............
        0x01c0:  0303 0102 0103 0202 0204 0205 0206 0200  ...............
        0x01d0:  2b00 0908 0304 0303 0302 0301 002d 0002  +............-..
        0x01e0:  0101 0033 04ea 04e8 11ec 04c0 9fb7 cdf7  ...3............
        0x01f0:  e703 7662 0b99 ca66 b04a b572 f23b 8f38  ..vb...f.J.r.;.8
        0x0200:  cc60 8962 9b73 56e4 e772 e659 9a53 10cd  .`.b.sV..r.Y.S..
        0x0210:  a847 764d f003 5aba 6e4f b84d 8b56 3ad7  .GvM..Z.nO.M.V:.
        0x0220:  e905 51b6 1f42 839f 39d8 713b d09d cb55  ..Q..B..9.q;...U
        0x0230:  617e f989 30e5 3031 e961 1b14 9ff4 dc8b  a~..0.01.a......
        0x0240:  0258 2792 220f 090c 1fc5 1c05 46da 23dc  .X'.".......F.#.
        0x0250:  2872 7a43 7e27 a96e 3e14 b7a4 5295 0d33  (rzC~'.n>...R..3
        0x0260:  1a08 fc4c a428 381a 242d 1147 1ba3 397a  ...L.(8.$-.G..9z
        0x0270:  f850 2fcc c449 a2a5 927f 677d eaa5 8490  .P/..I....g}....
        0x0280:  4a07 e9e3 23ae 9366 c4a6 3562 85b5 56e1  J...#..f..5b..V.
        0x0290:  a8ae b6b6 dd22 25e2 41ca 7095 541c 3816  ....."%.A.p.T.8.
        0x02a0:  63f9 461e 636f 2307 c645 d22c b1dc b060  c.F.co#..E.,...`
        0x02b0:  2895 27c6 886c e1ce 79fb a3d1 494f cd20  (.'..l..y...IO..
        0x02c0:  28ba d355 6509 a91f 60a0 c293 2e6e bcc6  (..Ue...`....n..
        0x02d0:  b052 27b8 8824 d523 a0d3 a0b6 9a45 68fc  .R'..$.#.....Eh.
        0x02e0:  a012 f305 cddd 59ae 6b51 3065 63cb 57b0  .....Y.kQ0ec.W.
        0x02f0:  5cad 7548 a5b9 2d49 4a5a 3cbc 4d0c 0470  \.uH..-IJZ<.M..p
        0x0300:  235c 01a0 52a1 3aa3 ad3f 4c96 c138 92e2  #\..R.:..?L..8..
        0x0310:  4b04 7efa c62b a21b 3676 5598 a69e 0e42  K.~..+..6vU....B
        0x0320:  8769 b45a ae98 45d1 1741 e096 6076 9221  .i.Z..E..A..`v.!
        0x0330:  3249 59ae db22 cda5 12b0 834e 6e06 26cd  2IY..".....Nn.&.
        0x0340:  fac3 c583 4be8 15cf b73b 83ca 8107 7d94  ....K....;....}.
        0x0350:  a050 7c5d 7942 5adc 5a60 1bd4 538c a317  .P|]yBZ.Z`..S...
        0x0360:  fbaa 15c8 9b52 fc51 4c6d 966f 8b90 865a  .....R.QLm.o...Z
        0x0370:  6004 9d62 19da d457 6621 672c 7c9e a4f8  `..b...Wf!g,|...
        0x0380:  813c 10b4 20f7 9f48 ac1c 83cc c72c 89c1  .<.. ..H.....,..
        0x0390:  2209 b085 7a97 9a8c 1b0b 57cd 89e4 013b  "...z.....W....;
        0x03a0:  a671 7274 c41d d732 273c 08a3 fc7c 29d0  .qrt...2'<...|).
        0x03b0:  5343 da55 4033 6443 9669 250a a7cf 6737  SC.U@3dC.i%...g7
        0x03c0:  eec2 9e5a 8818 f200 0a58 c350 e928 53cd  ...Z.....X.P.(S.
        0x03d0:  4476 d7c5 904f 58a0 4390 2098 b65e fe97  Dv...OX.C....^..
        0x03e0:  2d90 742a af37 9062 105d ac45 477b 101d  -.t*.7.b.].EG{..
        0x03f0:  9c91 736e 7251 59d3 838d 6bc7 9119 552d  ..snrQY...k...U-
        0x0400:  f844 f07a 6dfe 690a 5122 3520 9159 fd37  .D.zm.i.Q"5..Y.7
        0x0410:  5144 5767 6527 b041 f43b c898 120f d498  QDWge'.A.;......
        0x0420:  6cd5 0e6d 0306 03f7 64ee d98a 4f56 c54f  l..m....d...OV.O
        0x0430:  8815 5ac9 aa7c acc2 b14b 640a 841f ea69  ..Z..|...Kd....i
        0x0440:  5b8f 9034 ba3b 94e8 d25a c390 85b8 1ba8  [..4.;...Z......
        0x0450:  b925 7754 303a f8fa 8006 7b74 77f3 bcc0  .%wT0:....{tw...
        0x0460:  997b 9389 6bd4 e937 b3f2 ac35 20cd 85b0  .{..k..7...5....
        0x0470:  7ce8 4c4a 3508 59a4 375f bd74 65f0 dc75  |.LJ5.Y.7_.te..u
        0x0480:  79f3 22f6 7960 993c 2e92 500b 9e78 3da7  y.".y`.<..P..x=.
        0x0490:  a203 9c9a 4116 91c5 d9c2 20bb 9492 88d2  ....A..... .....
        0x04a0:  953f 7309 09bc 7de1 3115 cdd2 4391 028d  .?s...}.1...C...
        0x04b0:  569b b206 40a0 1ed9 142a 52a1 b3e8 a4e0  V...@....*R.....
        0x04c0:  2c0c d238 11f7 09c9 0167 5781 100e c2a3  ,..8.....gW.....
        0x04d0:  a611 3a2c d35c c846 fa3e 3126 1a49 c6ce  ..:,.\.F.>1&.I..
        0x04e0:  2231 41a2 173c 35b5 5190 36ac ae47 128b  "1A..<5.Q.6..G..
        0x04f0:  4bb7 d494 0fc5 5ac4 736a 8424 b9cd f8d7  K.....Z.sj.$....
        0x0500:  a6b0 d28f 5774 5c84 3204 a5e2 1266 f0ba  ....Wt\.2....f..
        0x0510:  129a 34b8 5317 7c0a 9071 4077 3386 22e3  ..4.S.|..q@w3.".
        0x0520:  7750 3b5a c65c a448 6f43 1224 f56c b1cc  wP;Z.\.HoC.$.l..
        0x0530:  0fcf 01d0 2e25 2f31 209d 85b5 4c6f 1174  .....%/1....Lo.t
        0x0540:  6491 5f66 f381 a771 5bed b492 2745 0c92  d._f...q[...'E..
        0x0550:  884b 8e21 4e8a c904 47d5 b73e 905a f337  .K.!N...G..>.Z.7
        0x0560:  158b fba0 9ff3 cf5d ac55 4b98 461b 2496  .......].UK.F.$.
        0x0570:  b559 5765 da86 1128 917e 589b e309 2b3e  .YWe...(.~X...+>
        0x0580:  613d aada 0ca1 0b64 4d94 3b90 d043 c602  a=.....dM.;..C..
        0x0590:  b055 84ac 9db1 504e 9aa1 ff21 322d bb69  .U....PN...!2-.i
        0x05a0:  ca40 046f c90d 09c9 cc4c 5056 5d9c c240  .@.o.....LPV]..@
        0x05b0:  3578 dbb7 0e89 0a6a 8775 a894 588a 610c  5x.....j.u..X.a.
        0x05c0:  413f 43a6 d4d6 b11e c491 2b52 ccf3 2b6d  A?C.......+R..+m
        0x05d0:  b853 1076 306f 1a85 5666 9ab7 46f9 52dd  .S.v0o..Vf..F.R.
        0x05e0:  b030 8960 acd5 359b 1368 97a5 c8a0 3a29  .0.`..5..h....:)
        0x05f0:  7898 c567 c9eb 9c24 da67 2b99 16a2 890f  x..g...$.g+.....
        0x0600:  6892 cfb0 d895 7ecb 1500 d55e e1d0 65fb  h.....~....^..e.
        0x0610:  3a80 fdb9 298a fbb0 ce67 8293 9880 ccfa  :...)....g......
        0x0620:  b971 396a 88f2 19ca e690 5e08 1456 301b  .q9j......^..V0.
        0x0630:  caa4 bd9a 2152 3769 9f38 312a aa6c 21a6  ....!R7i.81*.l!.
        0x0640:  e065 7130 711b 430a 7930 2fdf 1a85 4148  .eq0q.C.y0/...AH
        0x0650:  51d2 a222 9986 12ca 3438 19e0 70aa 4111  Q.."....48..p.A.
        0x0660:  47b3 8817 bbc3 7083 3466 8a64 edb2 3ee1  G.....p.4f.d..>.
        0x0670:  3c32 3744 ee44 e641 f000 e3a4 7d11 efb7  <27D.D.A....}...
        0x0680:  ffa1 0496 35d7 b7eb 6571 6438 13b8 bcea  ....5...eqd8....
        0x0690:  2231 0b35 3a26 e3cb 8eb3 66ab 0b45 bdcf  "1.5:&....f..E..
        0x06a0:  5c53 d78d 8d63 0962 378a 3c5b 001d 0020  \S...c.b7.<[... 
        0x06b0:  4af5 4468 5fbc 3e4f 63ad fb47 9f77 044e  J.Dh_.>Oc..G.w.N
        0x06c0:  ec3a 6ae2 b0c0 5a4e 2ae4 4b8f 8436 5c4f  .:j...ZN*.K..6\O
        0x06d0:  001b 0005 0400 0100 03                   ......

1763651708.400052 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [.], ack 4953, win 61, options [nop,nop,TS val 365868155 ecr 1143229670], length 0
        0x0000:  4500 0034 0b9e 4000 4006 7630 ac17 5b1f  E..4..@.@.v0..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6cf7 4ca5 6839  .."..F..?.l.L.h9
        0x0020:  8010 003d b91c 0000 0101 080a 15ce b47b  ...=...........{
        0x0030:  4424 4ce6                                D$L.

1763651708.400059 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [.], ack 5204, win 61, options [nop,nop,TS val 365868156 ecr 1143229670], length 0
        0x0000:  4500 0034 0b9f 4000 4006 762f ac17 5b1f  E..4..@.@.v/..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6cf7 4ca5 6934  .."..F..?.l.L.i4
        0x0020:  8010 003d b91c 0000 0101 080a 15ce b47c  ...=...........|
        0x0030:  4424 4ce6                                D$L.

1763651708.401418 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [P.], seq 1701:1781, ack 5204, win 63, options [nop,nop,TS val 365868157 ecr 1143229670], length 80
        0x0000:  4500 0084 0ba0 4000 4006 75de ac17 5b1f  E.....@.@.u..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6cf7 4ca5 6934  .."..F..?.l.L.i4
        0x0020:  8018 003f b96c 0000 0101 080a 15ce b47d  ...?.l.........}
        0x0030:  4424 4ce6 1403 0300 0101 1703 0300 452d  D$L...........E-
        0x0040:  298f d79b 77aa bf8e 2bf0 e5b9 0a04 c680  )...w...+.......
        0x0050:  9f10 06bc 4682 252a d80e 376b abd5 d975  ....F.%*..7k...u
        0x0060:  cf8b ae08 2581 b2cd 56ba adf7 e36b 1d5d  ....%...V....k.]
        0x0070:  a1f6 5a2a 4e46 d229 a3a5 36d1 5b51 1566  ..Z*NF.)..6.[Q.f
        0x0080:  fb9b 0e66                                ...f

1763651708.401680 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [P.], seq 1781:1912, ack 5204, win 63, options [nop,nop,TS val 365868157 ecr 1143229670], length 131
        0x0000:  4500 00b7 0ba1 4000 4006 75aa ac17 5b1f  E.....@.@.u..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6d47 4ca5 6934  .."..F..?.mGL.i4
        0x0020:  8018 003f b99f 0000 0101 080a 15ce b47d  ...?...........}
        0x0030:  4424 4ce6 1703 0300 7e83 ce09 213e 22cf  D$L.....~...!>".
        0x0040:  fdee 68a7 fe34 b30b 80ef b971 2185 fac9  ..h..4.....q!...
        0x0050:  539c 04e3 6303 70bc b540 8326 3fab 9420  S...c.p..@.&?..
        0x0060:  edfa d47b 1329 2b65 f230 524e 224d 390f  ...{.)+e.0RN"M9.
        0x0070:  e46f d6f5 0881 4621 8149 7e43 cd6b 13c2  .o....F!.I~C.k..
        0x0080:  e80e 98f2 0195 3512 ff98 7fd0 7174 d175  ......5.....qt.u
        0x0090:  d1e5 9dff a3f5 9845 c098 efbe 5f0a 6f3e  .......E...._.o>
        0x00a0:  442f d511 52ef a155 f89c cd16 0779 7734  D/..R..U.....yw4
        0x00b0:  a6cf bd0c c3d3 0b                        .....

1763651708.408126 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [P.], seq 1912:1943, ack 5854, win 63, options [nop,nop,TS val 365868164 ecr 1143229677], length 31
        0x0000:  4500 0053 0ba2 4000 4006 760d ac17 5b1f  E..S..@.@.v..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6dca 4ca5 6bbe  .."..F..?.m.L.k.
        0x0020:  8018 003f b93b 0000 0101 080a 15ce b484  ...?.;..........
        0x0030:  4424 4ced 1703 0300 1a25 f127 84e0 fa36  D$L......%.'...6
        0x0040:  8957 d171 c38f 7450 387d 8aad 2cc6 5827  .W.q..tP8}..,.X'
        0x0050:  9680 94                                  ...

1763651708.444028 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [.], ack 6735, win 63, options [nop,nop,TS val 365868199 ecr 1143229679], length 0
        0x0000:  4500 0034 0ba3 4000 4006 762b ac17 5b1f  E..4..@.@.v+..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6de9 4ca5 6f2f  .."..F..?.m.L.o/
        0x0020:  8010 003f b91c 0000 0101 080a 15ce b4a7  ...?............
        0x0030:  4424 4cef                                D$L.

1763651708.444448 eth0  Out IP 172.23.91.31.46662 > qro02s27-in-f4.1e100.net.https: Flags [P.], seq 1943:1982, ack 6735, win 63, options [nop,nop,TS val 365868200 ecr 1143229679], length 39
        0x0000:  4500 005b 0ba4 4000 4006 7603 ac17 5b1f  E..[..@.@.v..[.
        0x0010:  8efb 22c4 b646 01bb 3fa3 6de9 4ca5 6f2f  .."..F..?.m.L.o/
        0x0020:  8018 003f b943 0000 0101 080a 15ce b4a8  ...?.C..........
        0x0030:  4424 4cef 1703 0300 22aa 38c9 73e8 5073  D$L.....".8.s.Ps
        0x0040:  63dd 566b cec2 e6b8 1e7f aa3a 4b89 8839  c.Vk.......:K..9
        0x0050:  bda8 dc8f ef26 2748 02e6 be              .....&'H..

10 packets captured
14 packets received by filter
0 packets dropped by kernel
```

### Question 5.3: Capture Inbound TCP/UDP Traffic to Ports 20000-35000

For Exercise 3, I needed to capture traffic that is either UDP or TCP, is inbound to my computer, and destined for a port between 20000 and 35000. I ran tcpdump with a filter to capture packets destined for port 25000 (within the required range):

```sh
❯ sudo tcpdump -tt -X -s 0 -c 10 -i any '(tcp or udp) and dst port 25000' &
[1] 3251
tcpdump: WARNING: any: That device doesn't support promiscuous mode
(Promiscuous mode not supported on the "any" device)
```

To generate inbound traffic, I started a Python HTTP server on port 25000 and then made multiple HTTP requests to it:

```sh
❯ python3 -m http.server 25000 &
[2] 2646
Serving HTTP on 0.0.0.0 port 25000 (http://0.0.0.0:25000/) ...

❯ for i in {1..10}; do curl -s http://localhost:25000 > /dev/null; done
```

The tcpdump capture output shows 10 TCP packets with full data dumps in hex and ASCII format with Unix epoch timestamps:

```
1763686787.455212 lo    In  IP6 ip6-localhost.40844 > ip6-localhost.25000: Flags [S], seq 3416072505, win 65476, options [mss 65476,sackOK,TS val 1071162153 ecr 0,nop,wscale 10], length 0
        0x0000:  6004 076b 0028 0640 0000 0000 0000 0000  `..k.(.@........
        0x0010:  0000 0000 0000 0001 0000 0000 0000 0000  ................
        0x0020:  0000 0000 0000 0001 9f8c 61a8 cb9d 2139  ..........a...!9
        0x0030:  0000 0000 a002 ffc4 0030 0000 0204 ffc4  .........0......
        0x0040:  0402 080a 3fd8 a329 0000 0000 0103 030a  ....?..)........

1763686787.455325 lo    In  IP localhost.52018 > localhost.25000: Flags [S], seq 3638175276, win 65495, options [mss 65495,sackOK,TS val 2316303487 ecr 0,nop,wscale 10], length 0
        0x0000:  4500 003c 3ef8 4000 4006 fdc1 7f00 0001  E..<>.@.@.......
        0x0010:  7f00 0001 cb32 61a8 d8da 262c 0000 0000  .....2a...&,....
        0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a  .....0..........
        0x0030:  8a0f fc7f 0000 0000 0103 030a            ............

1763686787.455358 lo    In  IP localhost.52018 > localhost.25000: Flags [.], ack 2515699745, win 64, options [nop,nop,TS val 2316303487 ecr 2316303487], length 0
        0x0000:  4500 0034 3ef9 4000 4006 fdc8 7f00 0001  E..4>.@.@.......
        0x0010:  7f00 0001 cb32 61a8 d8da 262d 95f2 8821  .....2a...&-...!
        0x0020:  8010 0040 fe28 0000 0101 080a 8a0f fc7f  ...@.(..........
        0x0030:  8a0f fc7f                                ....

1763686787.455489 lo    In  IP localhost.52018 > localhost.25000: Flags [P.], seq 0:79, ack 1, win 64, options [nop,nop,TS val 2316303487 ecr 2316303487], length 79
        0x0000:  4500 0083 3efa 4000 4006 fd78 7f00 0001  E...>.@.@..x....
        0x0010:  7f00 0001 cb32 61a8 d8da 262d 95f2 8821  .....2a...&-...!
        0x0020:  8018 0040 fe77 0000 0101 080a 8a0f fc7f  ...@.w..........
        0x0030:  8a0f fc7f 4745 5420 2f20 4854 5450 2f31  ....GET./.HTTP/1
        0x0040:  2e31 0d0a 486f 7374 3a20 6c6f 6361 6c68  .1..Host:.localh
        0x0050:  6f73 743a 3235 3030 300d 0a55 7365 722d  ost:25000..User-
        0x0060:  4167 656e 743a 2063 7572 6c2f 382e 3135  Agent:.curl/8.15
        0x0070:  2e30 0d0a 4163 6365 7074 3a20 2a2f 2a0d  .0..Accept:.*/*.
        0x0080:  0a0d 0a                                  ....

1763686787.476770 lo    In  IP localhost.52018 > localhost.25000: Flags [.], ack 156, win 64, options [nop,nop,TS val 2316303509 ecr 2316303509], length 0
        0x0000:  4500 0034 3efb 4000 4006 fdc6 7f00 0001  E..4>.@.@.......
        0x0010:  7f00 0001 cb32 61a8 d8da 267c 95f2 88bc  .....2a...&|....
        0x0020:  8010 0040 fe28 0000 0101 080a 8a0f fc95  ...@.(..........
        0x0030:  8a0f fc95                                ....

1763686787.476796 lo    In  IP localhost.52018 > localhost.25000: Flags [.], ack 665, win 64, options [nop,nop,TS val 2316303509 ecr 2316303509], length 0
        0x0000:  4500 0034 3efc 4000 4006 fdc5 7f00 0001  E..4>.@.@.......
        0x0010:  7f00 0001 cb32 61a8 d8da 267c 95f2 8ab9  .....2a...&|....
        0x0020:  8010 0040 fe28 0000 0101 080a 8a0f fc95  ...@.(..........
        0x0030:  8a0f fc95                                ....

1763686787.476875 lo    In  IP localhost.52018 > localhost.25000: Flags [F.], seq 79, ack 666, win 64, options [nop,nop,TS val 2316303509 ecr 2316303509], length 0
        0x0000:  4500 0034 3efd 4000 4006 fdc4 7f00 0001  E..4>.@.@.......
        0x0010:  7f00 0001 cb32 61a8 d8da 267c 95f2 8aba  .....2a...&|....
        0x0020:  8011 0040 fe28 0000 0101 080a 8a0f fc95  ...@.(..........
        0x0030:  8a0f fc95                                ....

1763686787.484208 lo    In  IP6 ip6-localhost.40854 > ip6-localhost.25000: Flags [S], seq 3861079355, win 65476, options [mss 65476,sackOK,TS val 1071162182 ecr 0,nop,wscale 10], length 0
        0x0000:  6009 7a75 0028 0640 0000 0000 0000 0000  `.zu.(.@........
        0x0010:  0000 0000 0000 0001 0000 0000 0000 0000  ................
        0x0020:  0000 0000 0000 0001 9f96 61a8 e623 653b  ..........a..#e;
        0x0030:  0000 0000 a002 ffc4 0030 0000 0204 ffc4  .........0......
        0x0040:  0402 080a 3fd8 a346 0000 0000 0103 030a  ....?..F........

1763686787.484266 lo    In  IP localhost.52034 > localhost.25000: Flags [S], seq 4162861612, win 65495, options [mss 65495,sackOK,TS val 2316303516 ecr 0,nop,wscale 10], length 0
        0x0000:  4500 003c 11fc 4000 4006 2abe 7f00 0001  E..<..@.@.*.....
        0x0010:  7f00 0001 cb42 61a8 f820 3a2c 0000 0000  .....Ba...:,....
        0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a  .....0..........
        0x0030:  8a0f fc9c 0000 0000 0103 030a            ............

1763686787.484282 lo    In  IP localhost.52034 > localhost.25000: Flags [.], ack 1148443678, win 64, options [nop,nop,TS val 2316303516 ecr 2316303516], length 0
        0x0000:  4500 0034 11fd 4000 4006 2ac5 7f00 0001  E..4..@.@.*.....
        0x0010:  7f00 0001 cb42 61a8 f820 3a2d 4473 dc1e  .....Ba...:-Ds..
        0x0020:  8010 0040 fe28 0000 0101 080a 8a0f fc9c  ...@.(..........
        0x0030:  8a0f fc9c                                ....

10 packets captured
22 packets received by filter
0 packets dropped by kernel
```

## Part 6: Network Traffic Analysis

I analyzed network packet data from CSV files to understand the function of the networks. The data files R.csv (100k packets) and O.csv (1M packets) contain packet header information in CSV format.

### Question 6.2: Finding Statistics on TCP and UDP Services

I extended the provided `scancsv.py` script to add a `-stats` flag that counts the use of all well-known destination port numbers (1-1024) for TCP and UDP protocols. The script only produces output when the `-stats` flag is used.

#### Script Implementation

The original `scancsv.py` script was written in Python 2 syntax. I first encountered a syntax error when running it with Python 3:

```sh
❯ python3 scancsv.py R.csv
  File "/mnt/c/Users/emmak/Desktop/Projects/PythonStuff/PSUSec/introsec-f25-emmanart/hw4/scancsv.py", line 19
    print "numPackets:%u numBytes:%u" % (numPackets,numBytes)
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
```

I fixed this by converting the print statements from Python 2 to Python 3 syntax, adding parentheses around the print arguments.

I then modified `scancsv.py` to add the `-stats` functionality:
1. Added argument parsing using `argparse` to support the `-stats` flag
2. Created two dictionaries (`tcp_ports` and `udp_ports`) to store port counts
3. In the packet processing loop, when `-stats` flag is used:
   - For TCP packets (protocol 6), count destination ports (1-1024) in the `tcp_ports` dictionary
   - For UDP packets (protocol 17), count destination ports (1-1024) in the `udp_ports` dictionary
4. After processing all packets, when `-stats` flag is present, display:
   - Packet and byte statistics
   - IP protocol statistics
   - TCP destination port counts (sorted by port number)
   - UDP destination port counts (sorted by port number)
5. The script produces no output unless the `-stats` flag is used

#### Results for R.csv

I ran the script with the `-stats` flag on R.csv:

```sh
❯ python3 scancsv.py -stats R.csv
numPackets:99142 numBytes:71683046

  1:         7
  2:         2
  6:     39138
 17:     59995

TCP Destination Ports (1-1024):

  TCP port 22: 448 packets
  TCP port 23: 118 packets
  TCP port 25: 201 packets
  TCP port 80: 1361 packets
  TCP port 110: 990 packets
  TCP port 113: 55 packets
  TCP port 119: 68 packets
  TCP port 135: 24 packets
  TCP port 139: 9455 packets
  TCP port 515: 125 packets
  TCP port 700: 40 packets
  TCP port 712: 301 packets
  TCP port 721: 66 packets
  TCP port 891: 239 packets

UDP Destination Ports (1-1024):

  UDP port 53: 428 packets
  UDP port 67: 3 packets
  UDP port 68: 3 packets
  UDP port 137: 121 packets
  UDP port 138: 118 packets
```

**Question 6.3: Analysis of R.csv port statistics:**

The highest traffic ports are TCP port 139 (9,455 packets) for NetBIOS file sharing, TCP port 80 (1,361 packets) for HTTP web traffic, TCP port 110 (990 packets) for POP3 email, and UDP port 53 (428 packets) for DNS. The high volume of NetBIOS traffic (port 139) and presence of email services (POP3, SMTP), along with web browsing and SSH, suggests this is a **work network** with Windows-based file sharing and typical office communication services.

#### Results for O.csv

I ran the script with the `-stats` flag on O.csv:

```sh
❯ python3 scancsv.py -stats O.csv
numPackets:999914 numBytes:366325065

  1:      6794
  6:    950654
 17:     38332
 47:      2626
 50:      1484
 89:        24

TCP Destination Ports (1-1024):

  TCP port 13: 5 packets
  TCP port 21: 60 packets
  TCP port 22: 26383 packets
  TCP port 23: 6 packets
  TCP port 25: 211205 packets
  TCP port 53: 357 packets
  TCP port 80: 156397 packets
  TCP port 110: 1266 packets
  TCP port 111: 4 packets
  TCP port 113: 162 packets
  TCP port 119: 3347 packets
  TCP port 135: 4398 packets
  TCP port 139: 7605 packets
  TCP port 143: 624 packets
  TCP port 179: 8 packets
  TCP port 257: 5 packets
  TCP port 280: 4 packets
  TCP port 411: 4 packets
  TCP port 443: 4673 packets
  TCP port 445: 10867 packets
  TCP port 465: 100 packets
  TCP port 993: 2164 packets
  TCP port 995: 250 packets
  TCP port 1023: 14 packets

UDP Destination Ports (1-1024):

  UDP port 1: 3 packets
  UDP port 13: 1 packets
  UDP port 37: 2 packets
  UDP port 53: 21563 packets
  UDP port 123: 394 packets
  UDP port 137: 396 packets
  UDP port 138: 122 packets
  UDP port 161: 30 packets
  UDP port 225: 2 packets
  UDP port 500: 655 packets
  UDP port 601: 2 packets
  UDP port 1024: 186 packets
```

**Question 6.3: Analysis of O.csv port statistics:**

Highest traffic is SMTP (port 25 - 211k packets), HTTP (port 80 - 156k), SSH (port 22 - 26k), DNS (port 53 - 21k), and SMB (port 445 - 10k). Also has routing protocols (GRE, IPSEC, OSPF) and nearly 1 million total packets. This looks like an **ISP or data center network** handling email and routing infrastructure.

### Question 6.4: Counting Distinct IP Addresses

I added a `--countip` option to the script that creates a list of distinct IP addresses with their usage counts, sorted by usage count. 

#### Script Implementation

I added the following code to implement IP address counting:

1. Added the argument parser option:
```python
parser.add_argument('--countip', action='store_true', help='Count distinct IP addresses')
```

2. Created a dictionary to store IP counts:
```python
ip_counts = {}
```

3. In the packet processing loop, counted both source and destination IP addresses:
```python
if args.countip:
    if pkt.ipsrc is not None:
        ip_counts[pkt.ipsrc] = ip_counts.get(pkt.ipsrc, 0) + 1
    if pkt.ipdst is not None:
        ip_counts[pkt.ipdst] = ip_counts.get(pkt.ipdst, 0) + 1
```

4. After processing all packets, sorted and printed the results:
```python
if args.countip:
    ips_sorted = sorted(ip_counts.items(), key=lambda i: i[1], reverse=True)
    for ip, count in ips_sorted:
        print(f"{ip} : {count}")
```

I initially sorted the IP addresses in ascending order, but changed it to descending order (`reverse=True`) so I could easily see which IP addresses had the most usage counts at the top of the output.

#### Results for R.csv

I ran the script with the `--countip` option on R.csv and saved the output to a file:

```sh
❯ python3 scancsv.py --countip R.csv > R_countip_output.txt
```

To view the top 5 IP addresses by usage count:

```sh
❯ head -5 R_countip_output.txt
10.5.63.230 : 59411
234.142.142.142 : 42981
10.5.63.36 : 15926
10.5.63.231 : 12083
10.5.63.204 : 12003
```

#### Results for O.csv

I ran the script with the `--countip` option on O.csv and saved the output to a file:

```sh
❯ python3 scancsv.py --countip O.csv > O_countip_output.txt
```

To view the top 5 IP addresses by usage count:

```sh
❯ head -5 O_countip_output.txt
192.245.12.221 : 288305
192.245.12.242 : 119218
192.245.12.230 : 106948
66.156.15.246 : 63660
192.245.12.164 : 46186
```

**Question 6.6: Analysis of R.csv and O.csv IP counts (determining network prefix):**

**R.csv:** The `10.5.63.0/24` network dominates traffic, with most top IPs in this private range. Top IP is `10.5.63.230` (59k packets), then multicast `234.142.142.142` (42k). `10.5.63.36` (15k packets) is likely a router. This confirms it's a **work network** - private corporate network with internal file sharing.

**O.csv:** The `192.245.12.0/24` network dominates traffic. Top IPs are `192.245.12.221` (288k packets), `192.245.12.242` (119k), and `192.245.12.230` (106k). Also has external IPs like `66.156.15.246` (63k). High packet counts (hundreds of thousands per IP) and multiple infrastructure IPs confirm this is an **ISP or data center network**.

**Question 6.5: How IP counts inform the network type characterization:**

IP counts confirm the network types. R.csv has a concentrated private network (`10.5.63.0/24`) with internal IPs dominating, confirming it's a work network. O.csv has `192.245.12.0/24` with multiple high-traffic IPs (hundreds of thousands each) and many external IPs, confirming it's an ISP or data center.

### Question 6.7: Protocol Analysis: GRE, IPSEC, and OSPF

I extended the `--countip` option to filter by IP protocol number, allowing identification of IP addresses that use specific routing and tunneling protocols. This helps identify network infrastructure devices.

#### Script Implementation

I added the following modifications to support protocol filtering:

1. Added the protocol argument:
```python
parser.add_argument('--protocol', type=int, help='Filter by IP protocol number')
```

2. Created a dictionary to track the protocol for each IP:
```python
prot_ip = {}
```

3. Modified the IP counting logic to filter by protocol when `--protocol` is specified:
```python
if args.countip:
    # Only count if protocol matches (if --protocol filter is set)
    if args.protocol is None or proto == args.protocol:
        if pkt.ipsrc is not None:
            ip_counts[pkt.ipsrc] = ip_counts.get(pkt.ipsrc, 0) + 1
            prot_ip[pkt.ipsrc] = proto
        if pkt.ipdst is not None:
            ip_counts[pkt.ipdst] = ip_counts.get(pkt.ipdst, 0) + 1
            prot_ip[pkt.ipdst] = proto
```

4. Modified the output to include the protocol number:
```python
if args.countip:
    ips_sorted = sorted(ip_counts.items(), key=lambda i: i[1], reverse=True)
    for ip, count in ips_sorted:
        print(f"{ip}, {prot_ip[ip]}: {count}")
```

#### Results for O.csv

I ran the script to find IP addresses using GRE (protocol 47), IPSEC (protocol 50), and OSPF (protocol 89):

```sh
❯ python3 scancsv.py --countip --protocol 47 O.csv > O_GRE_countip.txt
❯ python3 scancsv.py --countip --protocol 89 O.csv > O_OSPF_countip.txt
❯ python3 scancsv.py --countip --protocol 50 O.csv > O_IPSEC_countip.txt
```

To view the top IP addresses for each protocol:

```sh
❯ head -20 O_GRE_countip.txt
209.104.16.215, 47: 2567
198.182.113.9, 47: 2567
209.104.16.58, 47: 59
66.134.158.90, 47: 59

❯ head -20 O_OSPF_countip.txt
207.182.35.58, 89: 16
207.182.35.49, 89: 12
207.182.35.50, 89: 8
207.182.35.60, 89: 4
207.182.35.47, 89: 4
207.182.35.55, 89: 4

❯ head -20 O_IPSEC_countip.txt
198.182.113.1, 50: 690
146.216.2.59, 50: 690
207.182.35.50, 50: 667
128.196.69.2, 50: 613
209.104.16.119, 50: 68
151.193.130.121, 50: 68
12.9.142.163, 50: 42
192.70.160.132, 50: 42
207.182.45.254, 50: 23
207.182.36.178, 50: 19
207.182.45.153, 50: 15
216.253.194.82, 50: 15
204.17.35.131, 50: 12
216.133.8.30, 50: 2
207.182.36.166, 50: 2
```

**Analysis of protocol-specific IP addresses:**

**GRE (protocol 47)**: The top IPs are `209.104.16.215` and `198.182.113.9` (both with 2,567 packets), indicating these are tunnel endpoints used for network encapsulation.

**OSPF (protocol 89)**: All top IPs are in the `207.182.35.0/24` network range (`207.182.35.58`, `207.182.35.49`, `207.182.35.50`, etc.), confirming these are routers participating in OSPF routing protocol for network topology discovery.

**IPSEC (protocol 50)**: The top IPs include `198.182.113.1` and `146.216.2.59` (both with 690 packets), `207.182.35.50` (667 packets), and `128.196.69.2` (613 packets). These are VPN endpoints using IPSEC for secure communication, with `207.182.35.50` appearing in both OSPF and IPSEC results, indicating it's a router handling both routing and VPN services.

**Question 6.8: Finding another network prefix:**

The `207.182.35.0/24` network shows up in OSPF and IPSEC traffic, separate from the main `192.245.12.0/24` network. This looks like the infrastructure/routing network used by routers, while `192.245.12.0/24` is the customer-facing network.

**Question 6.9: Does OSPF information inform the network type answer?**

Yes. Multiple routers in the `207.182.35.0/24` network using OSPF confirms this is an ISP or data center with proper routing infrastructure, not just a simple work or home network.

## Question 6.10: Finding Server Machines (--connto option)

**Question 6.10.1, 6.10.2, 6.10.3: Implementation:**

I added the `--connto` option to `scancsv.py` to identify server machines by counting connections to services (ports 1-1024). The script tracks:
- Each destination IP address (`ipdst`)
- The protocol and destination port tuples (`<proto, dport>`) where proto is 'tcp' or 'udp' and dport is the destination port
- Distinct source IP-source port combinations that connect to each destination

The output is sorted by the number of distinct source IP-source port combinations in descending order, so servers that serve many different connections appear at the top.

**Code added to scancsv.py:**

```python
parser.add_argument('--connto', action='store_true', help='Count connections to services (ports 1-1024)')

# In the loop:
if args.connto:
    if pkt.ipdst is not None:
        dport = None
        proto_name = None
        if proto == 6 and pkt.tcpdport is not None:  # TCP
            dport = pkt.tcpdport
            proto_name = 'tcp'
        elif proto == 17 and pkt.udpdport is not None:  # UDP
            dport = pkt.udpdport
            proto_name = 'udp'
        
        if dport is not None and 1 <= dport <= 1024:
            if pkt.ipdst not in connto_data:
                connto_data[pkt.ipdst] = {'ports': set(), 'sources': set()}
            connto_data[pkt.ipdst]['ports'].add((proto_name, dport))
            if pkt.ipsrc is not None:
                sport = pkt.tcpsport if proto == 6 else pkt.udpsport
                if sport is not None:
                    connto_data[pkt.ipdst]['sources'].add((pkt.ipsrc, sport))

# Output section:
if args.connto:
    sorted_dests = sorted(connto_data.items(), key=lambda x: len(x[1]['sources']), reverse=True)
    for ipdst, data in sorted_dests:
        num_sources = len(data['sources'])
        sorted_ports = sorted(data['ports'], key=lambda x: (x[0], x[1]))
        ports_str = ', '.join([f"{proto}/{port}" for proto, port in sorted_ports])
        print(f"{ipdst} has {num_sources} distinct ipsrc on ports: {ports_str}")
```

**Commands executed:**

```bash
python3 scancsv.py R.csv --connto > R_connto_output.txt
python3 scancsv.py O.csv --connto > O_connto_output.txt
```

**Top 20 servers from R.csv:**

```
10.5.63.6 has 151 distinct ipsrc on ports: tcp/22, tcp/25, tcp/110, udp/53
32.97.255.112 has 54 distinct ipsrc on ports: tcp/80
209.67.181.11 has 50 distinct ipsrc on ports: tcp/80
10.5.63.7 has 42 distinct ipsrc on ports: tcp/80, tcp/135, tcp/139, tcp/721, udp/137, udp/138
10.5.63.255 has 37 distinct ipsrc on ports: udp/137, udp/138
208.10.192.175 has 23 distinct ipsrc on ports: tcp/80
204.71.200.246 has 12 distinct ipsrc on ports: tcp/80
10.5.63.1 has 11 distinct ipsrc on ports: tcp/113, udp/53
10.5.63.230 has 11 distinct ipsrc on ports: tcp/139, udp/137, udp/138
207.46.142.26 has 11 distinct ipsrc on ports: tcp/80
216.101.171.2 has 10 distinct ipsrc on ports: tcp/110
193.164.170.30 has 10 distinct ipsrc on ports: tcp/110
209.67.181.20 has 9 distinct ipsrc on ports: tcp/80
10.5.63.200 has 9 distinct ipsrc on ports: tcp/80, tcp/139
208.10.192.176 has 8 distinct ipsrc on ports: tcp/80
208.10.192.202 has 7 distinct ipsrc on ports: tcp/80
10.5.63.14 has 6 distinct ipsrc on ports: tcp/113, udp/137, udp/138
10.5.63.22 has 5 distinct ipsrc on ports: tcp/23, tcp/139
10.5.63.27 has 4 distinct ipsrc on ports: tcp/113, tcp/139, udp/137
10.5.63.11 has 4 distinct ipsrc on ports: tcp/139, udp/137
```

**Top 20 servers from O.csv:**

```
192.245.12.221 has 1519 distinct ipsrc on ports: tcp/25, tcp/80, tcp/113, tcp/135, tcp/139, udp/123
192.245.12.234 has 1311 distinct ipsrc on ports: tcp/22, tcp/25, tcp/135
192.245.12.242 has 1272 distinct ipsrc on ports: tcp/22, tcp/25, tcp/135, udp/137
192.245.12.230 has 1062 distinct ipsrc on ports: tcp/22, tcp/25, tcp/135
192.245.12.233 has 1062 distinct ipsrc on ports: tcp/22, tcp/25, tcp/135, tcp/445
192.245.12.56 has 764 distinct ipsrc on ports: tcp/22, tcp/135, udp/53
192.245.12.7 has 631 distinct ipsrc on ports: tcp/23, tcp/25, tcp/80, tcp/135, udp/53, udp/123
192.245.12.50 has 486 distinct ipsrc on ports: udp/13, udp/37, udp/53
192.245.12.8 has 272 distinct ipsrc on ports: tcp/22, tcp/23, tcp/25, tcp/110, tcp/135, tcp/143, tcp/993, tcp/995, udp/53, udp/123
192.245.12.52 has 240 distinct ipsrc on ports: tcp/53, tcp/135, udp/53
192.245.12.246 has 224 distinct ipsrc on ports: tcp/22, tcp/25
192.245.12.231 has 223 distinct ipsrc on ports: tcp/22, tcp/25, tcp/135
207.182.38.2 has 209 distinct ipsrc on ports: tcp/25, tcp/53, tcp/445, udp/53
192.245.12.245 has 174 distinct ipsrc on ports: tcp/25, tcp/80, tcp/110, tcp/135, udp/53
206.165.5.10 has 155 distinct ipsrc on ports: udp/53
192.245.12.31 has 144 distinct ipsrc on ports: tcp/25, tcp/80, tcp/135, tcp/445
204.153.45.185 has 123 distinct ipsrc on ports: tcp/80
192.245.12.9 has 106 distinct ipsrc on ports: tcp/22, tcp/23, tcp/25, tcp/110, tcp/135, tcp/143, tcp/445, tcp/465, tcp/993, tcp/995, tcp/1023, udp/53
207.182.38.90 has 94 distinct ipsrc on ports: tcp/25, tcp/80, tcp/443
207.182.38.80 has 89 distinct ipsrc on ports: tcp/25, tcp/80, tcp/139, tcp/445
```

**Analysis of server machines:**

**R.csv servers:**
The top server `10.5.63.6` has 151 distinct source IPs serving SSH, SMTP, POP3, and DNS. Most servers are in the `10.5.63.0/24` network, indicating a smaller work network.

**O.csv servers:**
The top servers have much higher connection counts (1,519+ distinct source IPs) and are concentrated in the `192.245.12.0/24` network, indicating an ISP or data center infrastructure.

