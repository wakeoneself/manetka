// Source of the UDP shim built on bridge servers. Tested with a local loopback echo (see tests/shim.test.ts).
export const shimSource=`// maNETka UDP shim: wraps every datagram in an 8-byte STUN-like header
// (type 0x0001, length, magic cookie 0x2112A442) between two bridge servers.
package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"time"
)

const hdr = 8
const maxSessions = 4096
const idle = 3 * time.Minute

func wrap(dst, p []byte) []byte {
	dst = append(dst[:0], 0x00, 0x01, byte(len(p)>>8), byte(len(p)), 0x21, 0x12, 0xA4, 0x42)
	return append(dst, p...)
}

func unwrap(p []byte) ([]byte, bool) {
	if len(p) < hdr || p[0] != 0x00 || p[1] != 0x01 || p[4] != 0x21 || p[5] != 0x12 || p[6] != 0xA4 || p[7] != 0x42 {
		return nil, false
	}
	if int(p[2])<<8|int(p[3]) != len(p)-hdr {
		return nil, false
	}
	return p[hdr:], true
}

func main() {
	mode := flag.String("mode", "", "entry (plain clients, wrapped upstream) or exit (wrapped clients, plain upstream)")
	listen := flag.String("listen", "", "UDP listen address")
	target := flag.String("target", "", "UDP target address")
	flag.Parse()
	if (*mode != "entry" && *mode != "exit") || *listen == "" || *target == "" {
		log.Fatal("usage: -mode entry|exit -listen host:port -target host:port")
	}
	exit := *mode == "exit"
	la, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ta, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatal(err)
	}
	_ = ln.SetReadBuffer(4 << 20)
	_ = ln.SetWriteBuffer(4 << 20)
	var mu sync.Mutex
	sessions := map[string]*net.UDPConn{}
	buf := make([]byte, 65535)
	out := make([]byte, 0, 65535+hdr)
	for {
		n, from, err := ln.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		var payload []byte
		if exit {
			p, ok := unwrap(buf[:n])
			if !ok {
				continue
			}
			payload = p
		} else {
			out = wrap(out, buf[:n])
			payload = out
		}
		key := from.String()
		mu.Lock()
		up := sessions[key]
		if up == nil {
			if len(sessions) >= maxSessions {
				mu.Unlock()
				continue
			}
			up, err = net.DialUDP("udp", nil, ta)
			if err != nil {
				mu.Unlock()
				continue
			}
			_ = up.SetReadBuffer(4 << 20)
			sessions[key] = up
			go func(up *net.UDPConn, from *net.UDPAddr, key string) {
				defer func() {
					mu.Lock()
					if sessions[key] == up {
						delete(sessions, key)
					}
					mu.Unlock()
					up.Close()
				}()
				rb := make([]byte, 65535)
				ob := make([]byte, 0, 65535+hdr)
				for {
					_ = up.SetReadDeadline(time.Now().Add(idle))
					n, err := up.Read(rb)
					if err != nil {
						return
					}
					var p []byte
					if exit {
						ob = wrap(ob, rb[:n])
						p = ob
					} else {
						q, ok := unwrap(rb[:n])
						if !ok {
							continue
						}
						p = q
					}
					_, _ = ln.WriteToUDP(p, from)
				}
			}(up, from, key)
		}
		mu.Unlock()
		_, _ = up.Write(payload)
	}
}
`
export const shimGoMod='module shim\n\ngo 1.21\n'
