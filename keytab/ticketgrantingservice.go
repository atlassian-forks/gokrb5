package keytab

// import (
// 	"gopkg.in/jcmturner/gokrb5.v7/types"
// )

// TicketGrantingService for authentication
type TicketGrantingService interface {
	// GenerateKVNO(username string, realm string, password string, princname types.PrincipalName, etype etype.EType) (int, types.EncryptionKey, types.PrincipalName, error)
	// GenerateKVNO(username string, realm string, password string, enctype int) (int, types.EncryptionKey, error)
	GenerateKVNO(username string, realm string, password string, enctype int) (int, error)
}
