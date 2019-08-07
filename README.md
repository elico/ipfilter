## P2P Block lists formats
### The PeerGuardian Text Lists (P2P) Format
- <https://sourceforge.net/p/peerguardian/wiki/dev-blocklist-format-p2p/>

```
# This is a comment
Some organization:1.0.0.0-1.255.255.255
Another organization:8.0.0.0-8.255.255.255

# This is another comment
Yet another organization:16.0.0.0-16.255.255.255
And another:32.0.0.0-32.255.255.255
```
### IPv6 compatablity
Since IPv6 uses colons(":") and this format uses it as a seperator the first rule is
that the note cannot hold any colons and there for the first one is a seperator.
So the format would be:
`alphabetical note:ipv6First-ipv6Last`

parsing pesudo:
```
end of note = find index of the first colon
end of ipv6First = find index of the first dash
end of ipv6Last = end of the line
```

format validation pesudo:
```
verify is an ip(lines[end of note:end of ipv6First])
verify is an ip(lines[end of ipv6First:end of the line])
comment can be empty
```

### The PeerGuardian Binary Lists (P2B) Format
- <https://sourceforge.net/p/peerguardian/wiki/dev-blocklist-format-p2b/>

This format is a bit complex... so first we need to learn couple examples from:
- <https://github.com/ip2location/ip2location-ruby> (users bindata package)
- <https://github.com/ip2location/ip2location-go> (uses custom binary readers)

### The eMule Text Lists (DAT) Format
#### Primary Format
```
# This is a comment.  These ranges are blocked:
001.000.000.000 , 001.255.255.255 , 100 , Some organization
008.000.000.000 , 008.255.255.255 , 100 , Another organization

# This is another comment.  These ranges are allowed:
016.000.000.000 , 016.255.255.255 , 200 , Yet another organization
032.000.000.000 , 032.255.255.255 , 200 , And another
```
#### IPv6 compatablity
Since IPv6 uses colons(":") and this format uses comma(",) as a seperator
The only restcition is that the comment should not include comma(",")

So the format would be:
`firstip , lastip , rating , note`

parsing pesudo:
```
end of ipv6First = find index of the first comma
end of ipv6Last = find index of the next(second) comma
end of rating = find index of the next(third) comma
end of note = end of the line
```


#### Secondary Format
```
000.000.000.000 - 000.255.255.255 , 000 , Bogon
001.002.004.000 - 001.002.004.255 , 000 , China Internet Information Center (CNNIC)
001.009.096.105 - 001.009.096.105 , 000 , Botnet on Telekom Malaysia

```
#### IPv6 compatablity
Since IPv6 uses colons(":") and this format uses dash ("-) and comma(",")as a seperator
The only restcition is that the comment should not include comma(",")
and the first dash("-") should be a seperatore between two ip addresses in the range.

So the format would be:
`firstip - lastip , rating , note`

parsing pesudo:
```
end of ipv6First = find index of the first dash
end of ipv6Last = find index of the first comma
end of rating = find index of the next(second) comma
end of note = end of the line
```
#### Command to convert a p2p DAT formatted file(secondary) into DAT format(first):
`ruby -ne 'puts "#{$_.sub("-",",").chomp}"' filename`

## Firewall block sets
- Linux netfilter ipset
- Linux netfilter nftables set


## GoLang related Libraries
- <https://github.com/yl2chen/cidranger>
- <https://github.com/mikioh/ipaddr>
- <https://github.com/jpillora/ipfilter>
- <https://gist.github.com/mzimmerman/78e19eeb2393f9d6ec2ab063d9338273>
- <https://sourceforge.net/p/peerguardian/wiki/dev-blocklist-format-dat/>

- <https://raw.githubusercontent.com/anacrolix/torrent/master/iplist/packed.go>

Data Feed Example link: <http://upd.emule-security.org/ipfilter.zip>

The encoding of a eMule .dat list is not formally defined, but many parsers assume they are ASCII or ISO-8859-1.
PeerGuardian 2 (Windows) assumes eMule .dat lists are encoded in ISO-8859-1 if they do not begin with a UTF-8 BOM.

Based upon the old PhoenixLabs Wiki page <http://web.archive.org/web/20090424225818/http://wiki.phoenixlabs.org/wiki/DAT_Format>