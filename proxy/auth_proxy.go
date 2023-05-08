package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

//============================= 1. cert utilities ========================

type Source func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

var errSourceUnavailable = errors.New("certificate source is unavailable")

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

// =================== 1.3 custom CA cert ====================

// Generate CA cert/key on the fly.
func createCaCert(config Config) (*x509.Certificate, crypto.PrivateKey, error) {
	// create private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create self signed cert as CA cert
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"googleapis auth proxy"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	// dump cert to pem
	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	f, err := os.OpenFile(config.AuthProxy.CaCertPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write(certPem.Bytes()); err != nil {
		f.Close()
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// =================== 1.4 create cert for destination using custom CA cert ====================

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
			Organization: []string{"Googleapis auth proxy"},
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

//============================== 2. Proxy ===============================

//========== 2.1 Conventional pass through proxy ========================

func (p *AuthProxy) proxyConnectConventional(w http.ResponseWriter, req *http.Request) {
	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		log.Println("failed to dial to target", req.Host)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Fatal("http server doesn't support hijacking connection")
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Fatal("http hijacking failed")
	}

	log.Println("tunnel established")
	go copyConn(targetConn, clientConn)
	go copyConn(clientConn, targetConn)
}

func copyConn(dst io.WriteCloser, src io.ReadCloser) {
	io.Copy(dst, src)
	dst.Close()
	src.Close()
}

//=============================== 2.2 MITM proxy ========================

// proxyConnect implements the MITM proxy for CONNECT tunnels.
func (p *AuthProxy) proxyConnectMitm(w http.ResponseWriter, proxyReq *http.Request) {
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
		httpClient := p.createProxyToServerClient()

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

func (p *AuthProxy) createProxyToServerClient() *http.Client {
	clientCertSource, err := NewEnterpriseCertificateProxySource(p.config.Transport.Ecp.JsonPath)
	if err != nil {
		log.Fatal(err)
	}

	if p.config.CustomerProxy.Addr != "" {
		customerProxy, _ := url.Parse(p.config.CustomerProxy.Addr)
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					GetClientCertificate: clientCertSource,
				},
				// Disable http 2.0
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
				Proxy:        http.ProxyURL(customerProxy),
			},
		}
		return httpClient
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

//=============================== 2.3 auth proxy ========================

// AuthProxy is a type implementing http.Handler that serves as a MITM proxy
// for CONNECT tunnels. Create new instances of AuthProxy using createAuthProxy.
type AuthProxy struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	config Config
}

func (p *AuthProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println("serve http")
	if req.Method == http.MethodConnect {
		p.proxyConnect(w, req)
	} else {
		http.Error(w, "this proxy only supports CONNECT", http.StatusMethodNotAllowed)
	}
}

func (p *AuthProxy) proxyConnect(w http.ResponseWriter, proxyReq *http.Request) {
	log.Printf("CONNECT requested to %v (from %v)", proxyReq.Host, proxyReq.RemoteAddr)

	if strings.Contains(proxyReq.Host, "mtls.googleapis.com") {
		log.Println("Using MITM proxy")
		p.proxyConnectMitm(w, proxyReq)
	} else {
		log.Println("Using conventional proxy")
		p.proxyConnectConventional(w, proxyReq)
	}
}

// ============================ 2.4 auth proxy config json =====================
type CredConfig struct {
	Type string `json:"type"`
}

type EcpConfig struct {
	JsonPath string `json:"certificate_config_json_path"`
}

type TransportConfig struct {
	Ecp EcpConfig `json:"enterprise_certificate"`
}

type ProxySetting struct {
	Addr       string `json:"addr"`
	CaCertPath string `json:"ca_cert_path"`
}

type Config struct {
	CredConfig    CredConfig      `json:"credential"`
	Transport     TransportConfig `json:"transport"`
	CustomerProxy ProxySetting    `json:"customer_proxy"`
	AuthProxy     ProxySetting    `json:"auth_proxy"`
}

// ============================ 2.5 main func              =====================

func main() {
	// read the configuration file
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	defaultConfigPath := filepath.Join(currentDir, "auth_proxy_config.json")
	var configPath = flag.String("config_file", defaultConfigPath, "configuration json file path")
	flag.Parse()
	jsonFile, err := os.Open(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var config Config
	json.Unmarshal([]byte(byteValue), &config)
	fmt.Printf("created auth proxy with config: %+v\n", config)

	// create the auth proxy
	caCert, caKey, err := createCaCert(config)
	proxy := AuthProxy{
		caCert: caCert,
		caKey:  caKey,
		config: config,
	}
	if err != nil {
		log.Fatal("Failed to create the auth proxy:", err)
	}

	// serve the auth proxy
	log.Println("Starting proxy server on", config.AuthProxy.Addr)
	if err := http.ListenAndServe(config.AuthProxy.Addr, &proxy); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
