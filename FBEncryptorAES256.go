package EncryptorAES256CBC

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	defaultKey = "fadekiebos1573udoap30elz79vidwyc"
)

var (
	block      cipher.Block
	privateKey string
)

func init() {
	Init(defaultKey)
}

func Init(pKey string) {
	var err error
	block, err = aes.NewCipher([]byte(pKey))
	if err != nil {
		panic(err)
	}
}

func Encryptor(by []byte) ([]byte, error) {
	by = padding(by)
	cliperData := make([]byte, len(by)+aes.BlockSize)
	iv := cliperData[len(by):]
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cliperData[:len(by)], by)

	//gziped not used
	// var buf bytes.Buffer
	// writer := gzip.NewWriter(&buf)
	// defer writer.Close()
	// _, err = writer.Write(cliperData)
	// writer.Flush()
	// fmt.Println(err)
	// fmt.Println(buf.Len())
	// fmt.Println(buf)
	return cliperData, nil
}

func Descrptor(by []byte) ([]byte, error) {
	//gziped not used
	// reader, err := gzip.NewReader(bytes.NewBuffer(by))
	// if err == nil {
	// 	undatas, err := ioutil.ReadAll(reader)
	// 	defer reader.Close()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	by = undatas
	// 	fmt.Println(undatas)
	// }

	bylen := len(by)
	if bylen%16 != 0 {
		return nil, errors.New("不是16倍数")
	}
	cipherdata := make([]byte, bylen)
	iv := by[bylen-16:]
	cipherdata = by[:bylen-16]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherdata, cipherdata)
	cipherdata = trim(cipherdata)
	return cipherdata, nil
}

var (
	padBytes = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
)

func padding(src []byte) []byte {
	rem := len(src) % aes.BlockSize
	if rem != 0 {
		src = append(src, padBytes[:aes.BlockSize-rem]...)
	}
	return src
}

func trim(src []byte) []byte {
	if len(src) < 16 {
		return src
	}
	padSuffix := src[len(src)-15:]
	src = src[:len(src)-15]
	for _, v := range padSuffix {
		if v > 0x0f {
			src = append(src, v)
		}
	}
	return src
}
