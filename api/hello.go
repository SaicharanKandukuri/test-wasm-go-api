package handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
  "os/exec"
  "github.com/go-git/go-git/v5"
)

func Handler(w http.ResponseWriter, r *http.Request) {
  // Encrypt the message
  encrypted, err := encrypt("Hello from Go!")
  if err != nil {
      fmt.Fprintf(w, "Error: %s", err)
      return
  }
  fmt.Fprintf(w, "<h1>Hello from Go!</h1>")
  fmt.Fprintf(w, "<p>Encrypted: %s</p>", encrypted)

  // touch test
  cmd := exec.Command("touch", "/tmp/test")
  err = cmd.Run()
  if err != nil {
    fmt.Fprintf(w, "Error: %s", err)
  }
  fmt.Fprintf(w, "<p>touch /tmp/test</p>")

  // clone test
  _, err = git.PlainClone("/tmp", false, &git.CloneOptions{
    URL: "https://github.com/shikharvashistha/notes-wasm-go",
  })

  if err != nil {
    fmt.Fprintf(w, "Error: %s", err)
  }
  fmt.Fprintf(w, "<p>clone success</p>")

  // try to excute ls -l in /tmp
  cmd = exec.Command("ls", "-l", "/tmp")
  out, err := cmd.Output()
  if err != nil {
    fmt.Fprintf(w, "Error: %s", err)
  }
  fmt.Fprintf(w, "<p>ls -l /tmp</p>")
  fmt.Fprintf(w, "<p>%s</p>", out)
}

func encrypt(input string) (string, error) {
  // Generate a 16-byte random key
  key, err := generateKey(16)
  if err != nil {
      return "", err
  }

  // Convert the key to a byte array
  keyBytes, err := base64.StdEncoding.DecodeString(key)
  if err != nil {
      return "", err
  }

  // Generate a new AES cipher block from the key
  block, err := aes.NewCipher(keyBytes)
  if err != nil {
      return "", err
  }

  // Pad the input to a multiple of the block size
  paddedInput := pad(input, block.BlockSize())

  // Generate a new initialization vector (IV)
  iv := make([]byte, aes.BlockSize)
  _, err = rand.Read(iv)
  if err != nil {
      return "", err
  }

  // Create a new AES CBC encryption mode with the block and IV
  mode := cipher.NewCBCEncrypter(block, iv)

  // Encrypt the padded input
  encrypted := make([]byte, len(paddedInput))
  mode.CryptBlocks(encrypted, paddedInput)

  // Base64-encode the IV and encrypted data
  result := key + ":" + base64.StdEncoding.EncodeToString(iv) + ":" + base64.StdEncoding.EncodeToString(encrypted)

  return result, nil
}
// pad pads the input to a multiple of the blockSize using PKCS7 padding
func pad(input string, blockSize int) []byte {
  padding := blockSize - len(input)%blockSize
  padText := bytes.Repeat([]byte{byte(padding)}, padding)
  return append([]byte(input), padText...)
}

func generateKey(length int) (string, error) {
  key := make([]byte, length)
  _, err := rand.Read(key)
  if err != nil {
      return "", err
  }
  return base64.StdEncoding.EncodeToString(key), nil
}
