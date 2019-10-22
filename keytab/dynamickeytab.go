// Package keytab implements Kerberos keytabs: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html.
package keytab

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

const (
	numComponents int16  = 2
	service       string = "HTTP"
	nametype      int32  = 1
)

// DynamicKeytabImpl implements the Keytab interface defined in keytab.go
type DynamicKeytabImpl struct {
	Keytab *KeytabImpl
	Mutex  sync.RWMutex

	spns      []string
	realm     string
	username  string
	password  string
	tgs       TicketGrantingService
	logger    *log.Logger
	handleErr func(error)
}

// GetEncryptionKey implemented in original keytab.go
func (d *DynamicKeytabImpl) GetEncryptionKey(princName types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, error) {
	return d.Keytab.GetEncryptionKey(princName, realm, kvno, etype)
}

// Marshal implemented in original keytab.go
func (d *DynamicKeytabImpl) Marshal() ([]byte, error) {
	return d.Keytab.Marshal()
}

// Write unimplemented
func (d *DynamicKeytabImpl) Write(w io.Writer) (int, error) {
	return -1, nil
}

// Unmarshal implemented in original keytab.go
func (d *DynamicKeytabImpl) Unmarshal(b []byte) error {
	return d.Keytab.Unmarshal(b)
}

// IsPopulated checks if there are entries in the Keytab
func (d *DynamicKeytabImpl) IsPopulated() bool {
	return d.Keytab.IsPopulated()
}

// Create makes a new DynamicKeytabImpl object with the parameters specified
func Create(spns []string, realm string, username string, password string, tgs TicketGrantingService, logger *log.Logger, handleErr func(error)) *DynamicKeytabImpl {
	return &DynamicKeytabImpl{
		Keytab:    &KeytabImpl{},
		spns:      spns,
		realm:     realm,
		username:  username,
		password:  password,
		tgs:       tgs,
		logger:    logger,
		handleErr: handleErr,
	}
}

// Generate creates a new keytab and entries slice. Then it populates the entries with values from the service descriptor.
func (d *DynamicKeytabImpl) Generate() error {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	for _, spn := range d.spns {
		for enctype := 10; enctype <= 30; enctype++ {
			// trying to keep the timestamp the same format as in the original keytab struct
			timestamp := time.Unix(time.Now().Unix(), 0)
			principalName := types.NewPrincipalName(nametype, spn)
			key, err := d.generateEncryptionKey(principalName, enctype, types.PADataSequence{})
			if err != nil {
				// d.logger.Printf("unable to generate encryption key for enctype %d. continuing", enctype)
				continue
			}
			// FIX THIS
			kvno, err := d.tgs.GenerateKVNO(principalName.PrincipalNameString(), d.realm, d.password, enctype)
			if err != nil {

				continue
			}
			d.logger.Printf("successful for enctype %d", enctype)
			d.logger.Printf("with key %d %+v\n", key.KeyType, key.KeyValue)
			components := []string{service, spn}
			var principal = principal{numComponents, d.realm, components, nametype}

			var entry = entry{
				Principal: principal,
				Timestamp: timestamp,
				KVNO8:     uint8(kvno),
				Key:       key,
				KVNO:      uint32(kvno),
			}
			d.Keytab.Entries = append(d.Keytab.Entries, entry)

		}
	}
	d.Keytab.version = 2
	f, err := os.Create("/tmp/test.keytab")
	if err != nil {
		return err
	}
	d.Keytab.Write(f)
	if !d.IsPopulated() {
		return fmt.Errorf("generate failed and no entries created")
	}
	return nil
}

func (d *DynamicKeytabImpl) generateEncryptionKey(principalName types.PrincipalName, enctype int, pad []types.PAData) (types.EncryptionKey, error) {
	// key, _, err := crypto.GetKeyFromPassword(d.password, principalName, d.realm, int32(enctype), pad)
	var key types.EncryptionKey
	et, err := crypto.GetEtype(int32(enctype))
	if err != nil {
		return key, fmt.Errorf("error getting encryption type: %v", err)
	}
	sk2p := et.GetDefaultStringToKeyParams()
	k, err := et.StringToKey(d.password, "", sk2p)
	if err != nil {
		return key, fmt.Errorf("error deriving key from string: %+v", err)
	}
	key = types.EncryptionKey{
		KeyType:  int32(enctype),
		KeyValue: k,
	}

	return key, err
}

// Start generates a new encryption key every 5 minutes
func (d *DynamicKeytabImpl) Start(ctx context.Context) error {
	err := d.Generate()
	if err != nil {
		d.logger.Println("error when generating the dynamic keytab")
		return err
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := d.Generate()
				if err != nil {
					d.handleErr(err)
				}
			}
		}
	}()
	return nil
}
