package main

import (
	"encoding/json"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"log"
	"encoding/hex"
	"strings"
	"encoding/binary"
	"time"
)

type NTLMChallenge struct {
	TargetName           string
	NetBIOSDomainName    string
	NetBIOSComputerName  string
	DNSDomainName        string
	DNSComputerName      string
	DNSTreeName          string
	ProductVersion       string
	SystemTime           string
}

type NTLMInfo struct {
	NetBIOSComputerName []string `json:"netbios_computer_name"`
	ProductVersion      []string `json:"product_version"`
	SystemTime          []string `json:"system_time"`
	TargetName          []string `json:"target_name"`
	NetBIOSDomainName   []string `json:"netbios_domain_name"`
	DNSComputerName     []string `json:"dns_computer_name"`
	DNSDomainName       []string `json:"dns_domain_name"`
	DNSTreeName         []string `json:"dns_tree_name"`
	ImgName             []string `json:"screenshot_name"`
}

type FullResponse struct {
	NTLMInfo NTLMInfo `json:"ntlm_info"`
	IPPort   string   `json:"ip_port"`
}

const (
	signature = "NTLMSSP\x00"
	ntEpochOffset = 11644473600
)

// **** Wireshark Packet ****
//char peer0_0[] = 
//{ /* Packet 4 */
//  0x03, 0x00, 0x00, 0x13, 
//  0x0e, 0xe0, 0x00, 0x00, 
//  0x00, 0x00, 0x00, 0x01, 
//  0x00, 0x08, 0x00, 0x0b, 
//  0x00, 0x00, 0x00 				 
//};

func GetNtlmInfo(addr string, SyncSave chan string) {

	server := addr

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // 2sec timeout
	defer cancel()

	var conn net.Conn
	var err error
	done := make(chan bool)

	go func() {
		conn, err = net.Dial("tcp", server)
		done <- true
	}()

	select {
	case <-ctx.Done():
		fmt.Println("Connection error: waiting time exceeded (2 секунды)")
		close(SyncSave)
		return
	case <-done:
		if err != nil {
			log.Fatalf("Connection error: %v", err)
			close(SyncSave)
		}
	}

	defer conn.Close()

	// X.224 Connection Request PDU (TPKT + X.224)
	syncPacket := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT Header (версия 3, длина 19 байт)
		0x0e,                   // X.224 Length Indicator
		0xe0,                   // X.224 CR(0xe) CDT(0x0) -> 0xe
		0x00, 0x00,             // X.224 DST-REF
		0x00, 0x00,             // X.224 SRC-REF
		0x00,                   // X.224 CLASS OPTION
		0x01, 0x00, 0x08,       // X.224 RDP Negotiation Request (Type: 0x01, Flags: 0x00, Length: 0x08)
		0x00, 0x0b, 0x00, 0x00, // Requested Protocols (PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID)
		0x00,                   // Padding
	}

	_, err = conn.Write(syncPacket)
	if err != nil {
		log.Fatalf("Error sending data: %v", err)
		close(SyncSave)
	}

	// read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Error reading the response: %v", err)
		close(SyncSave)
	}

	fmt.Printf("\nServer response\n%s", hex.Dump(buffer[:n]))

	// switch to TLS
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()

	// NTLM Negotiate
	ntlmNegotiate := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28, // ASN
		0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, // "NTLMSSP" Signature
		0x01, 0x00, 0x00, 0x00, // NTLM Message Type 1
		0xB7, 0x82, 0x08, 0xE2, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain Name Fields
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation Fields
		0x0A, 0x00, // Product Major Version (Windows 10 = 10)
		0x63, 0x45, // Product Build (17763)
		0x00, 0x00, 0x00, // Reserved
		0x0F, // NTLM Revision
	}

	_, err = tlsConn.Write(ntlmNegotiate)
	if err != nil {
		fmt.Println("Error sending NTLM Negotiate:", err)
		close(SyncSave)
		return
	}

	n, err = tlsConn.Read(buffer)
	if err != nil {
		fmt.Println("NTLM Challenge Reading Error:", err)
		close(SyncSave)
		return
	}

	err = parseNTLMTargetInfo(buffer[:n], addr, SyncSave)
	if err != nil {
	        fmt.Println(err)
			close(SyncSave)
       		return
    	}
}

func parseNTLMTargetInfo(data []byte, addr string, SyncSave chan string) error {
	
	var challenge NTLMChallenge
	var targetLen, targetOffset int
	
	//fmt.Printf("\nTarget Info\n%s", hex.Dump(data))
	
	pos := strings.Index(string(data), signature)
	if pos == -1 {
		return fmt.Errorf("NTLM signature not found")
	}
	
	buffer := data[pos:] // discard ASN header
	
	if len(buffer) < 48 {
		return fmt.Errorf("Error: NTLM Challenge is too short")
	}
	
	msgType := int(binary.LittleEndian.Uint16(buffer[8:12]))  // 4byte LE
	if msgType != 0x2 { 
		return fmt.Errorf("NTLM Challenge (Type 2) was expected, type received %d", msgType)
	}
	
	targetLen =  int(binary.LittleEndian.Uint16(buffer[12:14]))  // 2byte LE
	targetOffset = int(binary.LittleEndian.Uint16(buffer[16:20])) // 4byte LE
	
	if targetLen > 0 {
	// get TargetName
		challenge.TargetName = string(removeNullBytes(buffer[targetOffset:targetOffset + targetLen]))
	}
	
	var domainLen, domainOffset int
	
	domainLen = int(binary.LittleEndian.Uint16(buffer[40:42])) 
	domainOffset = int(binary.LittleEndian.Uint16(buffer[44:48])) 
	
	// win9x check...?
	
	// get version major/minor/build
	challenge.ProductVersion = fmt.Sprintf("%d.%d.%d", buffer[48], buffer[49], 
					int(binary.LittleEndian.Uint16(buffer[50:52])))
	
	if domainLen == 0 {
		return fmt.Errorf("Domain Length 0, target TargetInfo empty")
	}
	
	var dataLen, offset, fieldType, fieldLen int
	
	dataLen = len(buffer)
	offset = domainOffset // type pos
	
	for ; ; {
	
		if offset >= dataLen {
			break
		}
		
		fieldType = int(buffer[offset])
		fieldLen = int(binary.LittleEndian.Uint16(buffer[offset+2:offset+4])) 
		
		offset += 4
		
		if fieldLen == 0 {
			continue
		}
		
		switch fieldType {
			case 0x2:
				challenge.NetBIOSDomainName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x1:
				challenge.NetBIOSComputerName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x3:
				challenge.DNSComputerName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x4:
				challenge.DNSDomainName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x5:
				challenge.DNSTreeName = 
					string(removeNullBytes(buffer[offset:offset+fieldLen]))
			case 0x7:
				challenge.SystemTime = 
					ConvertFILETIME(buffer[offset:offset+fieldLen])
		}
		
		offset += fieldLen
	}
	
	fmt.Println(challenge)
	
	imgName := <-SyncSave
	
	fmt.Println(challenge, "AFTER CHANEL INPUT")
	
	response := FullResponse{
		NTLMInfo: NTLMInfo{
			NetBIOSComputerName: []string{challenge.NetBIOSComputerName},
			ProductVersion:      []string{challenge.ProductVersion},
			SystemTime:          []string{challenge.SystemTime},
			TargetName:          []string{challenge.TargetName},
			NetBIOSDomainName:   []string{challenge.NetBIOSDomainName},
			DNSComputerName:     []string{challenge.DNSComputerName},
			DNSDomainName:       []string{challenge.DNSDomainName},
			DNSTreeName:         []string{challenge.DNSTreeName},
			ImgName:             []string{imgName},
		},
		IPPort: addr,
	}

	filename := fmt.Sprintf("%s_%s.json", strings.ReplaceAll(addr, ":", "_"), time.Now().Format("2006-01-02"))
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to write JSON: %v", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %v", err)
	}

	fmt.Printf("\nSuccessfully saved NTLM info to %s\n", filename)
	printChallengeInfo(&challenge)
	return nil
}

func removeNullBytes(data []byte) []byte {
	var result []byte
	for _, b := range data {
		if b != 0x0 { 
			result = append(result, b)
		}
	}
	return result
}

func ConvertFILETIME(filetime []byte) string {
	if len(filetime) != 8 {
		panic("Invalid FILETIME length")
	}

	ft := binary.LittleEndian.Uint64(filetime)

	seconds := int64(ft/10000000) - ntEpochOffset
	nanoseconds := int64(ft%10000000) * 100
	t := time.Unix(seconds, nanoseconds).UTC()
	
	return t.Format(time.RFC3339)
}

func printChallengeInfo(challenge* NTLMChallenge) {
	fmt.Println("\n|Target_Name:", challenge.TargetName)
	fmt.Println("|NetBIOS_Domain_Name:", challenge.NetBIOSDomainName)
	fmt.Println("|NetBIOS_Computer_Name:", challenge.NetBIOSComputerName)
	fmt.Println("|DNS_Domain_Name:", challenge.DNSDomainName)
	fmt.Println("|DNS_Computer_Name:", challenge.DNSComputerName)
	fmt.Println("|DNS_Tree_Name:", challenge.DNSTreeName)
	fmt.Println("|Product_Version:", challenge.ProductVersion)
	fmt.Println("|System_Time:", challenge.SystemTime)
}
