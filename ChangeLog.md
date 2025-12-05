### 2025-12-05 Version 1.0.4
* Support CloudSSO credentials provider.
* Support OAuth credentials provider.

### 2025-12-02 Version 1.0.4rc1
* Support CloudSSO credentials provider.
* Support OAuth credentials provider.

### 2025-10-14 Version 1.0.3
* Update logger level.

### 2025-05-06 Version 1.0.2
* Resolve home path in all environments.
* Resolve loop in synchronously function.

### 2025-04-22 Version 1.0.2rc1
* Resolve home path in all environments.

### 2025-04-18 Version 1.0.1
* Support StsToken mode in cli profile.
* Remove basic level for logging.

### 2025-04-08 Version 1.0.0
* Refactor all credentials providers.
* Dropped support for Python 3.6.
* Update dependencies.

### 2025-03-17 Version 1.0rc4
* Remove internal function calls.

### 2025-02-28 Version 1.0rc3
* Fix some bugs.

### 2025-02-19 Version 1.0rc2
* Fix credentials profiles path.

### 2025-02-19 Version 1.0rc1
* Refactor all credentials providers.
* Dropped support for Python 3.6.

### 2024-10-28 Version 0.3.6
* Support IMDS v2 default for ecs ram role.

### 2024-07-31 Version 0.3.5
* Support region or endpoint for sts requests.
* Support user agent for credentials requests.
* Solve the inconsistency of credentials refreshes.

### 2024-06-12 Version 0.3.4
* Support env ALIBABA_CLOUD_SECURITY_TOKEN.

### 2024-05-24 Version 0.3.3
* Support IMDSv2 for ecs ram role.
* Support env ALIBABA_CLOUD_ECS_IMDSV2_ENABLE.

### 2023-02-28 Version 0.3.2
* Support credentials.ini under $HOME.

### 2023-02-01 Version 0.3.1
* Support oidc credential in credential chain.
* Support env ALIBABA_CLOUD_ROLE_ARN/ALIBABA_CLOUD_OIDC_PROVIDER_ARN/ALIBABA_CLOUD_ROLE_SESSION_NAME for oidc credential.

### 2022-10-13 Version 0.3.0
* Support oidc credentials.
* Fix ram credentials.

### 2021-09-28 Version 0.2.0
* Support credentials uri.

### 2020-02-03 Version 0.1.4
* Optimize the way to obtain the credentials.ini file.

### 2020-01-28 Version 0.1.3
* Support async refresh credentials.

### 2020-12-11 Version 0.1.2
* Fix AttributeError.

### 2020-12-09 Version 0.1.1
* Change overwrite to a method with `_async` suffix

### 2020-12-07 Version 0.1.0
* Drop support for python3.4.
* Drop support for python3.5.
* Added support for python3.9.
* Support async io client.

### 2020-09-18 Version 0.0.8
* Print debugging information in debug mode when configuring DEBUG environment variables.

### 2020-08-26 Version 0.0.7
* Improve the logic of automatic refresh token.

### 2020-08-10 Version 0.0.6
* EcsRamRole&RsaKeyPair support refresh token.

### 2020-07-20 Version 0.0.5

* Improve install requires library version.

### 2020-07-15 Version 0.0.4

* Processed INI file comments

### 2020-07-07 Version 0.0.3
* Supported python 3.4

### 2020-06-19 Version 0.0.2
* Fixed user path

### 2020-05-27 Version 0.0.1
* First release