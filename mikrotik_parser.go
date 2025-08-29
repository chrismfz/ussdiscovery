package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

// MikroTikDevice holds the information we extract from MNDP TLVs.
type MikroTikDevice struct {
    MAC      string
    IP       string
    Identity string
    Version  string
    Platform string
    Board    string
    Bridge   string
}

// tlvHandler is called for each known TLV.
type tlvHandler func(d *MikroTikDevice, value []byte)

var handlers = map[uint16]tlvHandler{
    1:  handleMAC,
    5:  handleIdentity,
    7:  handleVersion,
    8:  handlePlatform,
    10: handleUptime,    // optional
    11: handleSoftwareID, // optional
    12: handleBoard,
    14: handleUnpack,    // optional
    15: handleIPv6,      // optional
    16: handleBridge,
    17: handleIPv4,
}

// parseMikroTikPacket decodes a raw MNDP packet into a MikroTikDevice.
// Returns nil if there’s nothing useful inside.
func parseMikroTikPacket(data []byte) *MikroTikDevice {
    // must have at least 4-byte MNDP header + one 4-byte TLV header
    if len(data) < 8 {
        return nil
    }

    // skip the 4-byte MNDP header
    data = data[4:]
    r := bytes.NewReader(data)
    dev := &MikroTikDevice{}

    for r.Len() > 0 {
        var tag, length uint16
        if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
            break
        }
        if err := binary.Read(r, binary.BigEndian, &length); err != nil {
            break
        }
        if int(length) > r.Len() {
            // malformed length; bail out
            break
        }

        value := make([]byte, length)
        if _, err := r.Read(value); err != nil {
            break
        }

        if h, ok := handlers[tag]; ok {
            h(dev, value)
        } else {
            logUnknown(tag, value)
        }
    }

    // drop empty responses
    if dev.MAC == "" && dev.IP == "" {
        return nil
    }
    return dev
}

// --- individual TLV handlers ---

func handleMAC(d *MikroTikDevice, v []byte) {
    if len(v) == 6 {
        d.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
            v[0], v[1], v[2], v[3], v[4], v[5])
    }
}

func handleIPv4(d *MikroTikDevice, v []byte) {
    if len(v) == 4 {
        d.IP = fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
    }
}

func handleIdentity(d *MikroTikDevice, v []byte) {
    d.Identity = string(v)
}

func handleVersion(d *MikroTikDevice, v []byte) {
    d.Version = string(v)
}

func handlePlatform(d *MikroTikDevice, v []byte) {
    d.Platform = string(v)
}

func handleBoard(d *MikroTikDevice, v []byte) {
    d.Board = string(v)
}

func handleBridge(d *MikroTikDevice, v []byte) {
    d.Bridge = string(v)
}

// Optional TLVs you can choose to handle or ignore:
func handleUptime(d *MikroTikDevice, v []byte) {
    // TLV 10: 4-byte uptime in seconds (big-endian)
}
func handleSoftwareID(d *MikroTikDevice, v []byte) {
    // TLV 11: software identifier string
}
func handleUnpack(d *MikroTikDevice, v []byte) {
    // TLV 14: single-byte flag
}
func handleIPv6(d *MikroTikDevice, v []byte) {
    // TLV 15: 16-byte IPv6 address
}

// logUnknown prints any TLV we haven’t registered in handlers.
func logUnknown(tag uint16, v []byte) {
    fmt.Printf(
        "Unknown TLV Tag: 0x%04x | Length: %d | HEX: % x\n",
        tag, len(v), v,
    )
}
