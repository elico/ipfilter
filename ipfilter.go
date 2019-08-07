package ipfilter

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/mikioh/ipaddr"
	"github.com/yl2chen/cidranger"
)

// Debug level of the library
var Debug = 0

// ParseBlockListLine Parse a line from a blocklist of the formats:
// - The PeerGuardian Text Lists (P2P) Format
// - The eMule Text Lists (DAT) Format (First and second)
// - Linux IPSET ipv4 hash:ip ipset
//
// Returns ok if the line contains one of the next:
// - IPv4/6 Range(first last ip)
// - Single IPv4 address
// - Single IPv4 CIDR
// - Single IPv6 CIDR
// and within the spec of the file line format.
func ParseBlockListLine(l string) (cidrsList []ipaddr.Prefix, ok bool, err error) {
	l = strings.TrimSpace(l)
	allHashes := stringFindAllIndex(l, "#")

	if len(l) == 0 || (len(allHashes) > 0 && allHashes[0] == 0) {
		return
	}

	// Find out the line format:
	allColumns := stringFindAllIndex(l, ":")
	allDashes := stringFindAllIndex(l, "-")
	allCommas := stringFindAllIndex(l, ",")
	allDotts := stringFindAllIndex(l, ".")
	allBackSlashes := stringFindAllIndex(l, "/")

	var singleIP, v4CIDR, v6CIDR bool
	var firstIP, lastIP net.IP
	var cidrV4, cidrV6 *net.IPNet
	var note, rating string
	if Debug > 0 {
		fmt.Println(l)
	}
	// Parse first and second IP then rating and note
	switch {
	case len(allColumns) > 0 && len(allDashes) == 1 && len(allCommas) == 0:
		if Debug > 0 {
			fmt.Println("p2p Format")
		}
		// p2p Format
		// Some organization:1.0.0.0-1.255.255.255
		// Some organization:2600:380:F510::1-2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE

		firstIP = net.ParseIP(strings.TrimSpace(l[allColumns[0]+1 : allDashes[0]-1]))
		lastIP = net.ParseIP(strings.TrimSpace(l[allDashes[0]+1:]))
		note = strings.TrimSpace(l[:allColumns[0]-1])

	case len(allCommas) == 3:
		if Debug > 0 {
			fmt.Println("First DAT Format")
		}
		// Primary DAT Format
		// 001.000.000.000 , 001.255.255.255 , 100 , Some organization
		// 2600:380:F510::1 , 2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE , 100 , Some organization

		firstIP = net.ParseIP(strings.TrimSpace(l[0 : allCommas[0]-1]))
		lastIP = net.ParseIP(strings.TrimSpace(l[allCommas[0]+1 : allCommas[1]-1]))
		rating = strings.TrimSpace(l[allCommas[1]+1 : allCommas[2]-1])
		note = strings.TrimSpace(l[allCommas[2]+1:])

	case len(allDashes) == 1 && len(allCommas) == 2:
		if Debug > 0 {
			fmt.Println("Secondary DAT Format")
		}
		// Secondary DAT Format
		// 000.000.000.000 - 000.255.255.255 , 000 , Bogon
		// 2600:380:F510::1 - 2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE , 000 , Some organization

		firstIP = net.ParseIP(strings.TrimSpace(l[:allDashes[0]-1]))
		lastIP = net.ParseIP(strings.TrimSpace(l[allDashes[0]+1 : allCommas[0]-1]))
		rating = strings.TrimSpace(l[allCommas[0]+1 : allCommas[1]-1])
		note = strings.TrimSpace(l[allCommas[1]+1:])

	case len(allDotts) == 3 && len(allBackSlashes) == 1:
		if Debug > 0 {
			fmt.Println("A single IPv4 CIDR")
		}
		// A single IPv4 CIDR
		_, cidrV4, _ = net.ParseCIDR(strings.TrimSpace(l))
		if cidrV4 != nil {
			v4CIDR = true
		}
	case len(allDotts) == 3:
		if Debug > 0 {
			fmt.Println("A single IPv4 address")
		}
		// A single IPv4 address
		_, cidrV4, _ = net.ParseCIDR(strings.TrimSpace(l + "/32"))
		if cidrV4 != nil {
			singleIP = true
		}
	case len(allColumns) > 3 && len(allBackSlashes) == 1:
		if Debug > 0 {
			fmt.Println("A single IPv6 CIDR")
		}
		// A single IPv6 CIDR
		_, cidrV6, _ = net.ParseCIDR(strings.TrimSpace(l))
		if cidrV4 != nil {
			v6CIDR = true
		}
	default:
		if Debug > 0 {
			fmt.Println("Default")
		}
		err = errors.New("Invalid line format")
		return
	}
	// For debug purposes
	if Debug > 0 {
		fmt.Println("FirsIP =>", firstIP, "cidrV4 =>", cidrV4, "cidrV6=> ", cidrV6, "LastIP =>", lastIP, "Rating =>", rating, "Note =>", note)
	}

	switch {
	case cidrV4 != nil && (v4CIDR || singleIP):
		newPrefix := []ipaddr.Prefix{}
		cidrsList = append(newPrefix, *ipaddr.NewPrefix(cidrV4))
	case cidrV6 != nil && v6CIDR:
		newPrefix := []ipaddr.Prefix{}
		cidrsList = append(newPrefix, *ipaddr.NewPrefix(cidrV6))
	case firstIP == nil || lastIP == nil || len(firstIP) != len(lastIP):
		// Checks both IPv4 and IPv6
		err = errors.New("bad IP range")
		return
	default:
		if Debug > 0 {
			fmt.Println("Default")
		}
		cidrsList = ipaddr.Summarize(firstIP, lastIP)
	}
	if Debug > 0 {
		fmt.Println("Will return this cidrlist =>", cidrsList)
	}
	ok = true
	return
}

// NewFromFilename Creates an cidranger.Ranger from a line-delimited P2P Plaintext filename.
func NewFromFilename(filename string) (ret cidranger.Ranger, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewFromReader(f)

}

// NewFromReader Creates an cidranger.Ranger from a line-delimited P2P Plaintext file io.Reader.
func NewFromReader(f io.Reader) (ret cidranger.Ranger, err error) {
	ret = cidranger.NewPCTrieRanger()

	scanner := bufio.NewScanner(f)
	lineNum := 1
	for scanner.Scan() {
		r, ok, lineErr := ParseBlockListLine(string(scanner.Bytes()))
		if lineErr != nil {
			// We don't want to stop the process because of one line..
			// err = fmt.Errorf("error parsing line %d: %s", lineNum, lineErr)
			// return
		}
		if Debug > 0 {
			fmt.Println("ParseLine =>", r)
		}
		lineNum++
		if !ok {
			continue
		}

		for _, singleCIDR := range r {
			_, net, _ := net.ParseCIDR(singleCIDR.String())
			ret.Insert(cidranger.NewBasicRangerEntry(*net))
		}
	}
	err = scanner.Err()
	if err != nil {
		return
	}
	return
}
