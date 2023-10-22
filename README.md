## Lisansly User Service

[![CI](https://github.com/Lisansly/user-api/actions/workflows/master.yml/badge.svg?branch=master&event=push)](https://github.com/Lisansly/user-api/actions/workflows/master.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Lisansly_user-api&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=Lisansly_user-api)

### Running Locally

Before invoking the function, you must set environment variables in the 'env.local.json' file.</br>
Afterward, you can invoke the function.</br>
Make sure to open Docker in the background.

```shell
make build && make zip

# then

sls invoke local -f funcName
# or
serverless invoke local -f funcName
```

### Linting
Needs golangci-lint package installed locally

```shell
make lint
```

### Testing

```shell
make test
```

### Git Hooks:
Needs pre-commit package installed locally

Installation:
```shell
pre-commit install
```

Run:
```shell
pre-commit run
```

