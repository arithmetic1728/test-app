package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

//============================= 1. cert utilities ========================

type Source func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

var errSourceUnavailable = errors.New("certificate source is unavailable")

//========== 1.1 CBA cert ===============

type secureConnectMetadata struct {
	Cmd []string `json:"cert_provider_command"`
}

type secureConnectSource struct {
	metadata secureConnectMetadata

	// Cache the cert to avoid executing helper command repeatedly.
	cachedCertMutex sync.Mutex
	cachedCert      *tls.Certificate
}

func NewSecureConnectSource() (Source, error) {
	user, err := user.Current()
	if err != nil {
		// Error locating the default config means Secure Connect is not supported.
		return nil, errSourceUnavailable
	}
	configFilePath := filepath.Join(user.HomeDir, ".secureConnect", "context_aware_metadata.json")

	file, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Config file missing means Secure Connect is not supported.
			return nil, errSourceUnavailable
		}
		return nil, err
	}

	var metadata secureConnectMetadata
	if err := json.Unmarshal(file, &metadata); err != nil {
		return nil, fmt.Errorf("cert: could not parse JSON in %q: %w", configFilePath, err)
	}
	if err := validateMetadata(metadata); err != nil {
		return nil, fmt.Errorf("cert: invalid config in %q: %w", configFilePath, err)
	}
	return (&secureConnectSource{
		metadata: metadata,
	}).getClientCertificate, nil
}

func validateMetadata(metadata secureConnectMetadata) error {
	if len(metadata.Cmd) == 0 {
		return errors.New("empty cert_provider_command")
	}
	return nil
}

func (s *secureConnectSource) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.cachedCertMutex.Lock()
	defer s.cachedCertMutex.Unlock()
	if s.cachedCert != nil && !isCertificateExpired(s.cachedCert) {
		return s.cachedCert, nil
	}
	// Expand OS environment variables in the cert provider command such as "$HOME".
	for i := 0; i < len(s.metadata.Cmd); i++ {
		s.metadata.Cmd[i] = os.ExpandEnv(s.metadata.Cmd[i])
	}
	command := s.metadata.Cmd
	data, err := exec.Command(command[0], command[1:]...).Output()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	s.cachedCert = &cert
	return &cert, nil
}

// isCertificateExpired returns true if the given cert is expired or invalid.
func isCertificateExpired(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Now().After(parsed.NotAfter)
}

//=================== 1.2 ECP cert ====================

type ecpSource struct {
	key *client.Key
}

func NewEnterpriseCertificateProxySource(configFilePath string) (Source, error) {
	if configFilePath == "" {
		user, err := user.Current()
		if err != nil {
			// Error locating the default config means Secure Connect is not supported.
			return nil, errSourceUnavailable
		}
		configFilePath = filepath.Join(user.HomeDir, ".config", "gcloud", "certificate_config.json")
	}
	key, err := client.Cred(configFilePath)
	if err != nil {
		if errors.Is(err, client.ErrCredUnavailable) {
			return nil, errSourceUnavailable
		}
		return nil, err
	}

	return (&ecpSource{
		key: key,
	}).getClientCertificate, nil
}

func (s *ecpSource) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	var cert tls.Certificate
	cert.PrivateKey = s.key
	cert.Certificate = s.key.CertificateChain()
	return &cert, nil
}

func createProxyToServerClient(useEcp bool) *http.Client {
	var clientCertSource Source
	var err error
	if useEcp {
		clientCertSource, err = NewEnterpriseCertificateProxySource("")
	} else {
		clientCertSource, err = NewSecureConnectSource()
	}
	if err != nil {
		log.Fatal(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: clientCertSource,
			},
			// Disable http 2.0
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}
	return httpClient
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

type proxy struct {
}

func (p *proxy) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)
	x, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Println(err.Error())
		return
	}
	log.Println(fmt.Sprintf("%q", x))

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		msg := "unsupported protocal scheme " + req.URL.Scheme
		http.Error(wr, msg, http.StatusBadRequest)
		log.Println(msg)
		return
	}
	req.URL.Scheme = "https"
	x, err = httputil.DumpRequest(req, true)
	if err != nil {
		log.Println(err.Error())
		return
	}
	log.Println(fmt.Sprintf("%q", x))

	client := createProxyToServerClient(true)

	//http: Request.RequestURI can't be set in client requests.
	//http://golang.org/src/pkg/net/http/client.go
	req.RequestURI = ""

	delHopHeaders(req.Header)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		log.Fatal("ServeHTTP:", err)
	}
	defer resp.Body.Close()

	log.Println(req.RemoteAddr, " ", resp.Status)

	delHopHeaders(resp.Header)

	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
}

func main() {
	var addr = flag.String("addr", "127.0.0.1:9999", "The addr of the application.")
	flag.Parse()

	handler := &proxy{}

	log.Println("Starting proxy server on", *addr)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
