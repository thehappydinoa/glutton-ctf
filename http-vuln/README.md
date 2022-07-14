# Vulnerable HTTP Server

[Website](https://www.npmjs.com/package/fake-http)

- Vulnerability
  - services.http.request.headers.server
    - [1.20.0](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017)
  - ~~services.http.request.headers.x_powered_by~~

## Run Locally

```sh
npm install
npm run start
```

## Run production config

```sh
npm run start:prod
```
