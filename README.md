# set up client

Open one terminal, go to the `client` folder, then run

```
gcloud auth application-default login
python -m pip install -r requirements.txt
```

# proxy

Open another terminal, and go to the `proxy` folder.

First go to the `cert` folder, run `./generate_cert.sh`. This will generate the CA cert and private key.

Next run the proxy,
```
go run -v tls-proxy.go -cacertfile ./certs/rootCA.pem -cakeyfile ./certs/rootCA-key.pem
```

Then run the python app in the previous terminal `python app.py`.




