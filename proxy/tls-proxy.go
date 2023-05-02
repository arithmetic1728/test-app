package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

//============================== 2. Proxy ===============================

// createCert creates a new certificate/private key pair for the given domains,
// signed by the parent/parentKey certificate. hoursValid is the duration of
// the new certificate's validity.
func createCert(dnsNames []string, parent *x509.Certificate, parentKey crypto.PrivateKey, hoursValid int) (cert []byte, priv []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sample MITM proxy"},
		},
		DNSNames:  dnsNames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(hoursValid) * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("failed to encode certificate to PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemCert == nil {
		log.Fatal("failed to encode key to PEM")
	}

	return pemCert, pemKey
}

// loadX509KeyPair loads a certificate/key pair from files, and unmarshals them
// into data structures from the x509 package. Note that private key types in Go
// don't have a shared named interface and use `any` (for backwards
// compatibility reasons).
func loadX509KeyPair(certFile, keyFile string) (cert *x509.Certificate, key any, err error) {
	cf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	kf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(cf)
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(kf)
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// mitmProxy is a type implementing http.Handler that serves as a MITM proxy
// for CONNECT tunnels. Create new instances of mitmProxy using createMitmProxy.
type mitmProxy struct {
	caCert *x509.Certificate
	caKey  any
	useEcp bool
}

// createMitmProxy creates a new MITM proxy. It should be passed the filenames
// for the certificate and private key of a certificate authority trusted by the
// client's machine.
func createMitmProxy(caCertFile, caKeyFile string, useEcp bool) *mitmProxy {
	log.Println("creating the proxy")
	caCert, caKey, err := loadX509KeyPair(caCertFile, caKeyFile)
	if err != nil {
		log.Fatal("Error loading CA certificate/key:", err)
	}
	log.Printf("loaded CA certificate and key; IsCA=%v\n", caCert.IsCA)

	return &mitmProxy{
		caCert: caCert,
		caKey:  caKey,
		useEcp: useEcp,
	}
}

func (p *mitmProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println("serve http")
	if req.Method == http.MethodConnect {
		p.proxyConnect(w, req)
	} else {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
	}
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

// proxyConnect implements the MITM proxy for CONNECT tunnels.
func (p *mitmProxy) proxyConnect(w http.ResponseWriter, proxyReq *http.Request) {
	log.Printf("CONNECT requested to %v (from %v)", proxyReq.Host, proxyReq.RemoteAddr)

	// "Hijack" the client connection to get a TCP (or TLS) socket we can read
	// and write arbitrary data to/from.
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("http server doesn't support hijacking connection")
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Fatal("http hijacking failed")
	}

	// proxyReq.Host will hold the CONNECT target host, which will typically have
	// a port - e.g. example.org:443
	// To generate a fake certificate for example.org, we have to first split off
	// the host from the port.
	host, _, err := net.SplitHostPort(proxyReq.Host)
	if err != nil {
		log.Fatal("error splitting host/port:", err)
	}

	// Create a fake TLS certificate for the target host, signed by our CA. The
	// certificate will be valid for 10 days - this number can be changed.
	pemCert, pemKey := createCert([]string{host}, p.caCert, p.caKey, 240)
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		log.Fatal(err)
	}

	// Send an HTTP OK response back to the client; this initiates the CONNECT
	// tunnel. From this point on the client will assume it's connected directly
	// to the target.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Fatal("error writing status to client:", err)
	}

	// Configure a new TLS server, pointing it at the client connection, using
	// our certificate. This server will now pretend being the target.
	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		MinVersion:               tls.VersionTLS13,
		Certificates:             []tls.Certificate{tlsCert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Create a buffered reader for the client connection; this is required to
	// use http package functions with this connection.
	connReader := bufio.NewReader(tlsConn)

	// Run the proxy in a loop until the client closes the connection.
	for {
		// Read an HTTP request from the client; the request is sent over TLS that
		// connReader is configured to serve. The read will run a TLS handshake in
		// the first invocation (we could also call tlsConn.Handshake explicitly
		// before the loop, but this isn't necessary).
		// Note that while the client believes it's talking across an encrypted
		// channel with the target, the proxy gets these requests in "plain text"
		// because of the MITM setup.
		r, err := http.ReadRequest(connReader)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		// We can dump the request; log it, modify it...
		if b, err := httputil.DumpRequest(r, false); err == nil {
			log.Printf("incoming request:\n%s\n", string(b))
		}

		// Take the original request and changes its destination to be forwarded
		// to the target server.
		changeRequestToTarget(r, proxyReq.Host)

		// Send the request to the target server and log the response.
		httpClient := createProxyToServerClient(p.useEcp)

		//resp, err := http.DefaultClient.Do(r)
		resp, err := httpClient.Do(r)
		if err != nil {
			log.Fatal("error sending request to target:", err)
		}
		if b, err := httputil.DumpResponse(resp, false); err == nil {
			log.Printf("target response:\n%s\n", string(b))
		}
		defer resp.Body.Close()

		// Send the target server's response back to the client.
		if err := resp.Write(tlsConn); err != nil {
			log.Println("error writing response back:", err)
		}
	}
}

// changeRequestToTarget modifies req to be re-routed to the given target;
// the target should be taken from the Host of the original tunnel (CONNECT)
// request.
func changeRequestToTarget(req *http.Request, targetHost string) {
	targetUrl := addrToUrl(targetHost)
	targetUrl.Path = req.URL.Path
	targetUrl.RawQuery = req.URL.RawQuery
	req.URL = targetUrl
	// Make sure this is unset for sending the request through a client
	req.RequestURI = ""
}

func addrToUrl(addr string) *url.URL {
	if !strings.HasPrefix(addr, "https") {
		addr = "https://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func main() {
	var addr = flag.String("addr", "127.0.0.1:9999", "proxy address")
	caCertFile := flag.String("cacertfile", "/usr/local/google/home/sijunliu/wks/proxy/test-app/proxy/certs/ca_cert.pem", "certificate .pem file for trusted CA")
	caKeyFile := flag.String("cakeyfile", "/usr/local/google/home/sijunliu/wks/proxy/test-app/proxy/certs/ca_private_key.pem", "key .pem file for trusted CA")
	useEcp := flag.Bool("useEcp", true, "If true use ECP otherwise use CBA as the cert source")
	flag.Parse()

	proxy := createMitmProxy(*caCertFile, *caKeyFile, *useEcp)

	log.Println("Starting proxy server on", *addr)
	if err := http.ListenAndServe(*addr, proxy); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
