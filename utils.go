package ipfilter

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

// IsInRange2 ttt
func IsInRange2(trial net.IP, lower net.IP, upper net.IP) bool {
	if bytes.Compare(trial, lower) >= 0 && bytes.Compare(trial, upper) <= 0 {
		return true
	}
	return false
}

func readIP(longIPStr string) (net.IP, error) {
	ip := net.ParseIP(longIPStr)
	if ip == nil {
		return nil, errors.New("Error parsing IP address")
	}
	return ip, nil
}

func stringFindAllIndex(str, substr string) []int {
	var mySlice = make([]int, 0)
	if !strings.Contains(str, substr) {
		return mySlice
	}

	current := 0
	pos := 0
	for {
		if current > len(str) {
			break
		}

		pos = strings.Index(str[current:], substr)
		if pos == -1 {
			break
		}
		mySlice = append(mySlice, current+pos)
		current = current + pos + len(substr)
	}
	return mySlice
}
