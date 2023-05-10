```
export GRPC_PROXY_EXP=127.0.0.1:9999
export GOOGLE_API_USE_MTLS_ENDPOINT="always"
```

```
mvn compile
mvn exec:java -Dexec.mainClass="com.mycompany.app.App"
```