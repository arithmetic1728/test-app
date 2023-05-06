# overview

`client` folder contains a python app to talk to pubsub mtls endpoint via auth proxy. It calls pubsub list API twice, one without streaming and one with streaming.

`proxy` folder contains:
- `certs` folder: the CA cert used by the `auth-proxy.go`, the script inside the folder can be ran to generate the CA cert
- `auth_proxy.go`: the https auth proxy, which passes through the non mtls.googleapis endpoints requests, and serves as MITM proxy for mtls.googleapis.com requests. For the latter case the MITM proxy can use either CBA or ECP cert to do mtls with mtls.googleapis.com. The network call is: client -> auth-proxy -> destination endpoint.

This auth proxy can also be configured to talk to any destination endpoints via a customer proxy. The network call is: client -> auth-proxy -> customer proxy -> destination endpoint.

The auth proxy runs at http://127.0.0.1:9999
- `customer_proxy.go`: a https pass through proxy for testing the customer proxy use case. It runs at http://127.0.0.1:8888

# 1. Test preparation: set up client

## 1.1 set up the cert needed by auth proxy

Go to the `proxy/cert` folder from the root directory, run `./generate_cert.sh`. This will generate the CA cert and private key.

## 1.2 set up a python client test app to use auth proxy

Open one terminal, go to the `client` folder.

Run the following with "sijunliu@beyondcorp.us" account and `sijunliu-dca-test` project.

```
gcloud auth application-default login
```

Next install the dependencies.
```
python -m pip install -r requirements.txt
```

## 1.3 set up gcloud to use auth proxy

First run the following with "sijunliu@beyondcorp.us" account and `sijunliu-dca-test` project.

```
gcloud auth login
gcloud config set project sijunliu-dca-test
```

Then set up gcloud as follows to use auth proxy

```
gcloud config set proxy/type http
gcloud config set proxy/address localhost
gcloud config set proxy/port 9999
gcloud config set core/custom_ca_certs_file /usr/local/google/home/sijunliu/wks/proxy/test-app/proxy/certs/ca_cert.pem
```

Next enable mtls for gcloud. Note that gcloud will auto switch to mtls endpoint, and this is all we need (we don't actually need the mtls connection since the auth proxy doesn't check the client cert).

```
gcloud config set context_aware/use_client_certificate true
```

# 2. Test case: test with the python app

## 2.1 test with the auth proxy

Open a terminal, and go to the `proxy` folder. Use the following command to run the auth proxy, you can specify which cert source to use, ECP or CBA, by setting `-useEcp` to true or false, by default it uses ECP cert.

E.g. for using CBA cert
```
go run -v auth-proxy.go -useEcp false
```

E.g. for using ECP cert
```
go run -v auth-proxy.go
```

Next let's open another terminal and go to the `client` folder, run the python app with `python app.py`. The app should run successfully. You can look at the log from the terminal that runs auth proxy to see what requests are mode.

## 2.2 test with both auth proxy and customer proxy

First start the customer proxy in `proxy` folder in a new terminal by running
```
go run -v customer-proxy.go
```

Then start the auth proxy in `proxy` folder in a new terminal by running
```
go run -v auth-proxy.go -callCustomerProxy true
```
Note that we need to set `callCustomerProxy` to true.

Then open a new terminal in `client` folder and run
```
python app.py
```

You can make sure the customer proxy is used by looking at the log.

# 3. Test case: test with gcloud

## 3.1 test with the auth proxy

Start the auth proxy as described in section 2.1, then in a new terminal run

```
gcloud pubsub topics list
```

## 3.2 test with both auth proxy and customer proxy

Start the auth/customer proxy as described in section 2.2, then run 
```
gcloud pubsub topics list
```