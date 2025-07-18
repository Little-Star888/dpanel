package ssh

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/donknap/dpanel/common/service/storage"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

var keyErr *knownhosts.KeyError

func NewDefaultKnownHostCallback() *DefaultKnownHostsCallback {
	return &DefaultKnownHostsCallback{
		path: storage.Local{}.GetSshKnownHostsPath(),
	}
}

type DefaultKnownHostsCallback struct {
	path string
}

func (self DefaultKnownHostsCallback) Handler(hostname string, remote net.Addr, key ssh.PublicKey) error {
	var ok bool
	var err error

	// 如果找到了并且有错才表示有问题，否则正常添加 host
	if ok, err = self.check(hostname, remote, key); ok && err != nil {
		return err
	}
	if !ok {
		err = self.add(hostname, remote, key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self DefaultKnownHostsCallback) check(hostname string, remote net.Addr, key ssh.PublicKey) (found bool, err error) {
	if _, err = os.Stat(self.path); err != nil {
		_, _ = os.Create(self.path)
	}

	callback, err := knownhosts.New(self.path)
	if err != nil {
		return false, err
	}
	err = callback(hostname, remote, key)
	if err == nil {
		return true, nil
	}
	// Make sure that the error returned from the callback is host not in file error.
	// If keyErr.Want is greater than 0 length, that means host is in file with different key.
	if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
		return true, keyErr
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func (self DefaultKnownHostsCallback) add(hostname string, remote net.Addr, key ssh.PublicKey) error {
	var err error
	f, err := os.OpenFile(self.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	remoteNormalized := knownhosts.Normalize(remote.String())
	hostNormalized := knownhosts.Normalize(hostname)
	addresses := []string{remoteNormalized}

	if hostNormalized != remoteNormalized {
		addresses = append(addresses, hostNormalized)
	}
	_, err = f.WriteString(knownhosts.Line(addresses, key) + "\n")
	return err
}

func (self DefaultKnownHostsCallback) Delete(hostPattern string) error {
	lock := sync.RWMutex{}
	lock.Lock()
	defer lock.Unlock()
	file, err := os.Open(self.path)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	content := make([][]byte, 0)
	reader := bufio.NewReader(file)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if strings.HasPrefix(string(line), hostPattern) {
			continue
		}
		content = append(content, line)
	}
	return os.WriteFile(self.path, bytes.Join(content, []byte("\n")), 0600)
}
