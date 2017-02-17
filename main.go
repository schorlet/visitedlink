// Command visitedlink helps reading chromium Visited Links.
//
//  Usage:
//  visitedlink <Visited Link file> urls...
// Prints each url on stdout if visited or else on stderr.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path"
)

const fileSignature int32 = 0x6b6e4c56
const fileVersion int32 = 3
const headerSize int32 = 24

var hash = md5.New()

type fileHeader struct {
	Signature int32
	Version   int32
	Length    int32
	Used      int32
	Salt      [8]uint8
}

func main() {
	log.SetFlags(0)

	if len(os.Args) < 3 {
		log.Println(`Usage:
	visitedlink <Visited Link file> urls...

Prints each url on stdout if visited or else on stderr.`)
		os.Exit(2)
	}

	// open file
	name := path.Clean(os.Args[1])
	file, err := os.Open(name)
	if err != nil {
		log.Fatalf("Unable to open %q: %v", name, err)
	}
	defer file.Close()

	// read header
	header := new(fileHeader)
	err = binary.Read(file, binary.LittleEndian, header)
	if err != nil {
		log.Fatalf("Unable to read %q: %v", name, err)
	}

	// verify header
	err = verifyHeader(file, header)
	if err != nil {
		log.Fatalf("Bad header: %v", err)
	}

	// search for urls
	for i := 2; i < len(os.Args); i++ {
		url := os.Args[i]
		fp := fingerprint(url, header.Salt)
		fpm := modulo(fp, header.Length)

		if isVisited(file, fp, fpm) {
			fmt.Println(url)
		} else {
			log.Println(url)
		}
	}
}

func verifyHeader(file *os.File, header *fileHeader) error {
	if header.Signature != fileSignature {
		return fmt.Errorf("bad signature: %x, want: %x", header.Signature, fileSignature)
	}
	if header.Version != fileVersion {
		return fmt.Errorf("bad version: %x, want: %x", header.Version, fileVersion)
	}

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("unable to stat: %v", err)
	}

	size := int64(header.Length*8 + headerSize)
	if stat.Size() != size {
		return fmt.Errorf("bad file size: %x, want: %x", stat.Size(), size)
	}

	return nil
}

func isVisited(file io.ReadSeeker, fp uint64, fpm int32) bool {
	pos := headerSize + fpm*8
	_, err := file.Seek(int64(pos), io.SeekStart)
	if err != nil {
		return false
	}

	var fpc uint64
	for {
		err = binary.Read(file, binary.LittleEndian, &fpc)
		if err != nil {
			return false
		}

		if fpc == 0 {
			break
		} else if fpc == fp {
			return true
		}
	}

	return false
}

func fingerprint(url string, salt [8]uint8) uint64 {
	hash.Reset()

	// ignore errors as hash/Hash.Writer never returns an error
	hash.Write(salt[:])
	hash.Write([]byte(url))

	// sum is [16]byte
	sum := hash.Sum(nil)

	// use the top 64 bits
	return binary.LittleEndian.Uint64(sum[:8])
}

func modulo(fp uint64, length int32) int32 {
	v := fp % uint64(length)
	return int32(v)
}
