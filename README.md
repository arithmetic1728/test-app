# set up client

Open one terminal, go to the `client` folder.

Run the following with "sijunliu@beyondcorp.us" and `sijunliu-dca-test` project.

```
gcloud auth application-default login
```

Next install the dependencies.
```
python -m pip install -r requirements.txt
```

# proxy

Open another terminal, and go to the `proxy` folder.

First go to the `cert` folder, run `./generate_cert.sh`. This will generate the CA cert and private key.

Next go back to the `proxy` folder, then run the proxy, you can specify which cert source to use, ecp or CBA, by setting `-useEcp` to true or false.
```
go run -v tls-proxy.go -useEcp true
```

Then run the python app in the previous terminal `python app.py`.

# use gcloud

First run the proxy, then set up gcloud as follows:

```
gcloud config set proxy/type http
gcloud config set proxy/address localhost
gcloud config set proxy/port 9999
gcloud config set core/custom_ca_certs_file /usr/local/google/home/sijunliu/wks/proxy/test-app/proxy/certs/ca_cert.pem
gcloud config set context_aware/use_client_certificate true
```

Then run
```
gcloud pubsub topics list
```




