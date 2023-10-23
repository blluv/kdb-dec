package android

import (
	"encoding/base64"
	"strconv"

	"github.com/blluv/kdb-dec/utils"
)

var KDB_PREFIXES = []string{
	"", "", "12", "24", "18", "30", "36", "12", "48", "7", "35", "40", "17", "23", "29", "isabel", "kale", "sulli", "van", "merry", "kyle", "james", "maddux", "tony", "hayden", "paul", "elijah", "dorothy", "sally", "bran", "extr.ursra",
}

var KDB_PW = []byte{0, 22, 0, 8, 0, 9, 0, 111, 0, 2, 0, 23, 0, 43, 0, 8, 0, 33, 0, 33, 0, 10, 0, 16, 0, 3, 0, 3, 0, 7, 0, 6, 0, 0}

var KDB_IV = []byte{15, 8, 1, 0, 25, 71, 37, 220, 21, 245, 23, 224, 225, 21, 12, 53}

func generateSalt(userId uint64, encType uint32) []byte {
	salt := make([]byte, 16)
	for i := 0; i < 16; i++ {
		salt[i] = 0
	}

	if userId <= 0 {
		return salt
	}

	s := KDB_PREFIXES[encType] + strconv.Itoa(int(userId))
	for i := 0; i < 16; i++ {
		salt[i] = s[i]
	}
	return salt
}

func deriveKey(userId uint64, encType uint32) []byte {
	salt := generateSalt(userId, encType)
	key := utils.Sha1Pbkdf(salt, KDB_PW, 2, 32)
	return key
}

func Decrypt(userId uint64, data string, encType uint32) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	key := deriveKey(userId, encType)
	plain, err := utils.DecryptAESCBC(KDB_IV, key, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
