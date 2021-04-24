package hasher

import (
	"crypto/sha512"
	b64 "encoding/base64"
	"fmt"
)

func Hash(input, secret string) string {
	data := []byte(secret + input)
	h := sha512.New()
	h.Write(data)
	hash := fmt.Sprintf("%x", h.Sum(nil))
	first := hash[0:6]
	last := hash[len(hash)-6:]
	result := first + last
	result = b64.StdEncoding.EncodeToString([]byte(result))

	return fmt.Sprintf("_%s@", result)
}
