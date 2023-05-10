```
export GRPC_PROXY_EXP=127.0.0.1:9999
```

```
mvn compile
mvn exec:java -Dexec.mainClass="com.mycompany.app.App"
```