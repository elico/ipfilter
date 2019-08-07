package ipfilter

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

var testLinesDATV1 = []string{"# This is a comment.  These Ranges are blocked:",
	"001.000.000.000 , 001.255.255.255 , 100 , Some organization",
	"008.000.000.000 , 008.255.255.255 , 100 , Another organization",
	"# This is another comment.  These Ranges are allowed:",
	"016.000.000.000 , 016.255.255.255 , 200 , Yet another organization",
	"032.000.000.000 , 032.255.255.255 , 200 , And another",
	" # This is a comment.  These Ranges are blocked:",
	"2600:380:F510::1 , 2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE , 200 , And another"}

var testLinesDATV2 = []string{"# This is a comment.  These Ranges are blocked:",
	"001.000.000.000 - 001.255.255.255 , 100 , Some organization",
	"008.000.000.000 - 008.255.255.255 , 100 , Another organization",
	"# This is another comment.  These Ranges are allowed:",
	"016.000.000.000 - 016.255.255.255 , 200 , Yet another organization",
	"032.000.000.000 - 032.255.255.255 , 200 , And another",
	" # This is a comment.  These Ranges are blocked:",
	"2600:380:F510::1 - 2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE , 200 , And another"}

var testLinesP2P = []string{"Some organization:1.0.0.0-1.255.255.255",
	"# This is a comment.  These Ranges are blocked:",
	"Some organization:2600:380:F510::1-2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE",
	"    # This is a comment.  These Ranges are blocked:"}

var testIPAddresses = []string{"001.000.000.000", "001.255.255.255", "008.000.000.000", "008.255.255.255",
	"016.000.000.000", "016.255.255.255",
	"032.000.000.000", "032.255.255.255",
	"2600:380:F510::1", "2600:380:F51F:FFFF:FFFF:FFFF:FFFF:FFFE", "1.4.198.25"}

func TestEmuleDat(t *testing.T) {
	ip, err := readIP("2600:380:F510::1")
	if err != nil {
		t.Log("Oh noes - the IPV6 Couldn't be parsed")
		t.Fail()
	}
	fmt.Println(ip)

	ip, err = readIP("001.000.000.000")
	if err != nil {
		t.Log("Oh noes - the Long IPV4 Couldn't be parsed")
		t.Fail()
	}
	fmt.Println(ip)

	ip, err = readIP("008.255.255.255")
	if err != nil {
		t.Log("Oh noes - the Long IPV4 Couldn't be parsed")
		t.Fail()
	}
	fmt.Println(ip)
}

func TestFindAllIndex(t *testing.T) {
	str := "001.000.000.000 , 001.255.255.255 , 100 , Some organization"
	substr := ","
	fmt.Println(len(str))
	res := stringFindAllIndex(str, substr)
	if len(res) != 3 {
		t.Log("Oh noes - the index of the comma is weird")
		t.Fail()
	}
	fmt.Println(res)

	for _, v := range res {
		if v > len(str) {
			t.Log("Oh noes - the index of the comma is out of range")
			t.Fail()
		}
	}
	fmt.Println(res, "Is fine and IN range")

}
func TestParseDATV1Line(t *testing.T) {
	for _, line := range testLinesDATV1 {
		cidrlist, ok, err := ParseBlockListLine(line)
		if ok {
			fmt.Println(cidrlist, ok, err)
		}
	}
}

func TestParseDATV2Line(t *testing.T) {
	// Debug = 1
	for _, line := range testLinesDATV2 {
		cidrlist, ok, err := ParseBlockListLine(line)
		if ok {
			fmt.Println(cidrlist, ok, err)
		}
	}
}

func TestParseP2PLine(t *testing.T) {
	for _, line := range testLinesP2P {
		cidrlist, ok, err := ParseBlockListLine(line)
		if ok {
			fmt.Println(cidrlist, ok, err)
		}
	}
}

func TestParseWrongDATFile(t *testing.T) {
	filename := "./test-files/guarding.p2p"
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be open")
		t.Log(err.Error())
		t.Fail()
	}

	cidrRangerFile, err := NewFromReader(f)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}

	fmt.Println(cidrRangerFile)

}

func stringSliceContainsSubstr(slice []string, item string) bool {

	for _, s := range slice {
		if strings.Contains(s, item) {
			return true
		}

	}
	return false
}

func TestParseOKDATFile(t *testing.T) {
	filename := "./test-files/ipfilter.dat-works"
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be open")
		t.Log(err.Error())
		t.Fail()
	}
	cidrRangerFile, err := NewFromReader(f)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}
	for _, ipAddress := range testIPAddresses {
		fmt.Println(cidrRangerFile.Contains(net.ParseIP(ipAddress)))
	}

	cidrRangerFile, err = NewFromFilename(filename)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}

}

func TestParseOKIPSETFile(t *testing.T) {
	filename := "./test-files/stopforumspam_7d.ipset"
	// Debug = 1
	cidrRangerFile, err := NewFromFilename(filename)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}
	for _, ipAddress := range testIPAddresses {
		fmt.Println(cidrRangerFile.Contains(net.ParseIP(ipAddress)))
	}
}

func TestInternalNetworks(t *testing.T) {
	filename := "./test-files/guarding.p2p-works"
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be open")
		t.Log(err.Error())
		t.Fail()
	}

	cidrRangerFile, err := NewFromReader(f)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}

	fmt.Println(cidrRangerFile.Contains(net.ParseIP("192.168.200.255")))
	fmt.Println(cidrRangerFile.Contains(net.ParseIP("2600:380:F510::100")))
	fmt.Println(cidrRangerFile.Contains(net.ParseIP("2600:380:F509::100")))

}

func TestCIRDRanger(t *testing.T) {
	filename := "./test-files/ipfilter.dat-works"
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be open")
		t.Log(err.Error())
		t.Fail()
	}
	cidrRangerFile, err := NewFromReader(f)
	if err != nil {
		t.Log("Oh noes - the file " + filename + " Could not be parsed")
		t.Log(err.Error())
		t.Fail()
	}

	fmt.Println(cidrRangerFile.Contains(net.ParseIP("192.168.89.151")))
}
