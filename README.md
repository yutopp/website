# yutopp.net

## webpage

### dev
```
sass --scss --watch src/sass:static/style
hugo server
```

## builder

### build image
```
docker build -t yutopp/yutopp.net-builder:latest _builder
docker push yutopp/yutopp.net-builder:latest
```
