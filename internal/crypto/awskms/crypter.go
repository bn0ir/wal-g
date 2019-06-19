package awskms

import (
	"bufio"
	"github.com/minio/sio"
	"github.com/wal-g/wal-g/internal/crypto"
	"github.com/wal-g/wal-g/internal/ioextensions"
	"github.com/wal-g/wal-g/internal/tracelog"
	"io"
)

// Crypter is AWS KMS Crypter implementation
type Crypter struct {
	SymmetricKey crypto.SymmetricKey
}

// Encrypt creates encryption writer from ordinary writer
func (crypter *Crypter) Encrypt(writer io.Writer) (io.WriteCloser, error) {
	if len(crypter.SymmetricKey.GetKey()) == 0 {
		err := crypter.SymmetricKey.Generate()
		if err != nil {
			tracelog.ErrorLogger.Printf("Can't generate symmetric key: %v", err)
		}

		err = crypter.SymmetricKey.Encrypt()
		if err != nil {
			tracelog.ErrorLogger.Printf("Can't encrypt symmetric key: %v", err)
		}
	}

	bufferedWriter := bufio.NewWriter(writer)
	_, err := bufferedWriter.Write(crypter.SymmetricKey.GetEncryptedKey())

	if err != nil {
		tracelog.ErrorLogger.Printf("Can't write encryption key to s3: %v", err)
		return nil, err
	}

	encryptedWriter, err := sio.EncryptWriter(bufferedWriter, sio.Config{Key: crypter.SymmetricKey.GetKey()})

	if err != nil {
		tracelog.ErrorLogger.Printf("AWS KMS can't create encrypted writer: %v", err)
		return nil, err
	}

	return ioextensions.NewOnCloseFlusher(encryptedWriter, bufferedWriter), nil
}

// Decrypt creates decrypted reader from ordinary reader
func (crypter *Crypter) Decrypt(reader io.Reader) (io.Reader, error) {
	encryptedSymmetricKey := make([]byte, crypter.SymmetricKey.GetEncryptedKeyLen())
	_, err := reader.Read(encryptedSymmetricKey)
	if err != nil {
		tracelog.ErrorLogger.Printf("Can't read encryption key from s3: %v", err)
		return reader, err
	}

	crypter.SymmetricKey.SetEncryptedKey(encryptedSymmetricKey)

	err = crypter.SymmetricKey.Decrypt()
	if err != nil {
		tracelog.ErrorLogger.Printf("Can't decrypt symmetric key: %v", err)
	}

	return sio.DecryptReader(reader, sio.Config{Key: crypter.SymmetricKey.GetKey()})
}

// CrypterFromKeyID creates AWS KMS Crypter with given KMS Key ID
func CrypterFromKeyID(CseKmsID string) crypto.Crypter {
	return &Crypter{SymmetricKey: NewSymmetricKey(CseKmsID, 32, 184)}
}