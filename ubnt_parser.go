package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ubntTLV_MAC      = 0x01
	ubntTLV_IP       = 0x02
	ubntTLV_Version  = 0x06
	ubntTLV_Hostname = 0x0b
	ubntTLV_Model    = 0x0c
	ubntTLV_Platform = 0x0d
)

type UBNTDevice struct {
	MAC      string
	IP       string
	Hostname string
	Model    string
	Platform string
	Version  string
}

func parseUBNTPacket(data []byte) *UBNTDevice {
	if len(data) < 4 {
		return nil
	}

	r := bytes.NewReader(data[4:])
	device := &UBNTDevice{}

	for r.Len() > 3 {
		// Read TLV header
		t, _ := r.ReadByte()

		var l uint16
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			break
		}

		if int(l) > r.Len() {
			fmt.Printf("Invalid TLV: length %d exceeds remaining %d\n", l, r.Len())
			break
		}

		value := make([]byte, l)
		r.Read(value)

		switch t {
		case ubntTLV_MAC:
			if len(value) == 6 {
				device.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
					value[0], value[1], value[2], value[3], value[4], value[5])
			}
		case ubntTLV_IP:
			if len(value) == 4 {
				device.IP = fmt.Sprintf("%d.%d.%d.%d", value[0], value[1], value[2], value[3])
			} else if len(value) == 10 {
				// IP is last 4 bytes in 10-byte structure
				ip := value[6:]
				device.IP = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
			}
		case ubntTLV_Version:
			device.Version = string(value)
		case ubntTLV_Hostname:
			device.Hostname = string(value)
		case ubntTLV_Model:
			device.Model = string(value)
		case ubntTLV_Platform:
			device.Platform = string(value)
		default:
			// Ignore unknown TLVs
		}
	}

	if device.MAC == "" && device.IP == "" {
		return nil
	}
	return device
}
