// Package visitedlink helps reading chromium Visited Links.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
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

	name := path.Clean(os.Args[1])
	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read header
	header := new(fileHeader)
	err = binary.Read(file, binary.LittleEndian, header)
	if err != nil {
		log.Fatal(err)
	}
	verifyHeader(file, header)

	// search urls
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

func verifyHeader(file *os.File, header *fileHeader) {
	if fileSignature != header.Signature {
		log.Fatal("bad signature")
	}
	if fileVersion != header.Version {
		log.Fatal("bad version")
	}
	if header.Used > header.Length {
		log.Fatal("bad used count")
	}

	size := int64(header.Length*8 + headerSize)
	stat, _ := file.Stat()
	if size != stat.Size() {
		log.Fatal("bad file size")
	}
}

func isVisited(file *os.File, fp uint64, fpm int32) bool {
	pos := headerSize + fpm*8
	_, err := file.Seek(int64(pos), 0)

	for fpc := uint64(0); err == nil; {
		err = binary.Read(file, binary.LittleEndian, &fpc)

		if fpc == 0 {
			break
		} else if fp == fpc {
			return true
		}
	}

	return false
}

func fingerprint(url string, salt [8]uint8) uint64 {
	hash.Reset()
	hash.Write(salt[:])
	hash.Write([]byte(url))

	// sum is [16]byte
	sum := hash.Sum(nil)

	// uses the top 64 bits
	return binary.LittleEndian.Uint64(sum[:8])
}

func modulo(fp uint64, length int32) int32 {
	v := fp % uint64(length)
	return int32(v)
}
