// Command visitedlink helps reading chromium Visited Links.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
)

const (
	fileSignature int32 = 0x6b6e4c56
	fileVersion   int32 = 3
	headerSize    int32 = 24
)

var (
	visitedFile = flag.String("visited", "Visited Links", "path to the 'Visited Links' file")
	link        = flag.String("link", "", "link to check")
	update      = flag.Bool("update", false, "set (un)visited if not")
)

type fileHeader struct {
	Signature int32
	Version   int32
	Length    int32
	Used      int32
	Salt      [8]uint8
}

func init() {
	log.SetFlags(0)
	log.SetPrefix(os.Args[0] + ": ")
}

func main() {
	flag.Parse()

	file, err := openFile()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}()

	// read header
	header, err := readHeader(file)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// fingerprint
	fp := fingerprint(*link, header.Salt)
	fpm := modulo(fp, header.Length)

	// update
	if *update {
		if err := updateValue(file, fp, fpm); err != nil {
			log.Fatalf("Error: %v", err)
		}
	}

	// visited link ?
	visited := readValue(file, fp, fpm)
	fmt.Printf("%t\n", visited)
}

func openFile() (*os.File, error) {
	name := path.Clean(*visitedFile)
	if *update {
		return os.OpenFile(name, os.O_RDWR|os.O_SYNC, 0600)
	}
	return os.Open(name)
}

func readHeader(file *os.File) (*fileHeader, error) {
	header := new(fileHeader)
	if err := binary.Read(file, binary.LittleEndian, header); err != nil {
		return nil, err
	}
	if err := verifyHeader(file, header); err != nil {
		return nil, err
	}
	return header, nil
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
		return err
	}
	size := int64(header.Length*8 + headerSize)
	if stat.Size() != size {
		return fmt.Errorf("bad file size: %d, want: %d", stat.Size(), size)
	}
	return nil
}

func fingerprint(link string, salt [8]uint8) uint64 {
	hash := md5.New()

	// ignore errors as hash/Hash.Writer never returns an error
	hash.Write(salt[:])
	hash.Write([]byte(link))

	// sum is [16]byte
	sum := hash.Sum(nil)

	// use the top 64 bits
	return binary.LittleEndian.Uint64(sum[:8])
}

func modulo(fp uint64, length int32) int32 {
	v := fp % uint64(length)
	return int32(v)
}

func readValue(file io.ReadSeeker, fp uint64, fpm int32) bool {
	var pos = headerSize + fpm*8

	_, err := file.Seek(int64(pos), io.SeekStart)
	if err != nil {
		return false
	}

	for {
		var fpc uint64
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

func updateValue(file *os.File, fp uint64, fpm int32) error {
	var pos = headerSize + fpm*8

	_, err := file.Seek(int64(pos), io.SeekStart)
	if err != nil {
		return err
	}

	write := func(value uint64) error {
		_, err := file.Seek(int64(pos), io.SeekStart)
		if err != nil {
			return err
		}
		err = binary.Write(file, binary.LittleEndian, value)
		if err != nil {
			return err
		}
		return file.Sync()
	}

	for {
		var fpc uint64
		err = binary.Read(file, binary.LittleEndian, &fpc)
		if err != nil {
			return err
		}
		if fpc == 0 {
			return write(fp)
		} else if fpc == fp {
			return write(uint64(0))
		}
	}
}
