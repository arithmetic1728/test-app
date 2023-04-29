# set up client

Open one terminal, go to the `client` folder, then run

```
gcloud auth application-default login
python -m pip install -r requirements.txt
```

# proxy

Open another terminal, and go to the `proxy` folder.

## Test 1: use the connect-tunnel proxy

```
go run -v connect-tunnel-proxy.go
```

Then run the python app in the previous terminal `python app.py`.

## Test 2: use the connect-mitm proxy

```
go run -v connect-mitm-proxy.go -cacertfile ./certs/rootCA.pem -cakeyfile ./certs/rootCA-key.pem
```

Then run the python app in the previous terminal `python app.py`.




