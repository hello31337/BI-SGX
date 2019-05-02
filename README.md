# BI-SGX : Bioinformatic Interpreter on SGX-based Secure Computing Cloud

## Introduction
These codes are interpreter which uses Intel(R) SGX's protection features and specializes for bioinformatical computations. The basical framework of these codes are heavily based on [Intel(R) Software Guard Extensions (SGX) Remote Attestation End-to-End Sample](https://github.com/intel/sgx-ra-sample).

Contrary to Intel's original RA sample, this model uses inverted client-server model. In other words:
* ISV (SGX side) runs as server, which waits for SP's request after RA
* SP (non-SGX side) runs as client, which send request to ISV after RA

The reason why implemented as this inverted model is, in bioinformatical computation (or secret computation), usually user would like to use SGX features as cloud server with sending or storing their data in protected way.

The main contributions of this code are:
* This interpreter provides much friendly coding rule than using SGXSDK itself.
* Provides code protect feature without any annoying build/installation.
* Provides various bioinfomatically-utilized methods as default in interpreter.
* Provides integrated cloud platform which can be used as secure cloud storage and secure cloud computation base, and can make two features corporate.

## Installation

### Prerequisites
Contrary to Intel's original RA sample, these codes are developed for Linux platform, so Windows OS is unexpected. Perhaps these can be run on Windows, but no performance guarantee.

* Ensure your platform's OS is
  * CentOS 7.4 (64-bit)
  * Ubuntu 16.04 LTS (64-bit)
  * Ubuntu 18.04 LTS (64-bit)

* Ensure that you have built and installed the Intel SGX packages (Both of these must be SGX 2.x version):
  * [Intel SGX Software Development Kit and Platform Software package for Linux](https://github.com/intel/linux-sgx)
  * [Intel SGX Driver for Linux](https://github.com/intel/linux-sgx-driver)

* Ensure that you have installed MySQL and MySQL Connector/C++.
```
$ sudo apt install mysql-server
$ sudo apt install libmysqlcppconn-dev
```

* Run the following commands to install the required packages to build the RA code sample (this assumes you have installed the dependencies for the Intel SGX SDK and PSW package)
  
  * On CentOS 7.4
  ```bash
  $ yum install libcurl-devel
  ```

  * On Ubuntu 16.04
  ```bash
  $ apt-get install libcurl4-openssl-dev
  ```

* Run the following command to get your system's OpenSSL version. It must be
at least 1.1.0:
```bash
$ openssl version
```

  * If necessary, download the source for the latest release of OpenSSL 1.1.0, then build and install it into a _non-system directory_ such as /opt (note that both `--prefix` and `--openssldir` should be set when building OpenSSL 1.1.0). For example:

   ```bash
  $ wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
  $ tar xf openssl-1.1.0i.tar.gz
  $ cd openssl-1.1.0i
  $ ./config --prefix=/opt/openssl/1.1.0i --openssldir=/opt/openssl/1.1.0i
  $ make
  $ sudo make install
   ```

### Configure and compile
First, prepare the build system (GNU* automake and autoconf) by running `bootstrap`, and then configure the software package using the `configure` command. You'll need to specify the location of OpenSSL 1.1.0. See the build notes section for additional options to `configure`.

  ```
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  ```

Or you can also execute these 3 commands by executing following command:

```
$ source make.sh
```

Both `make clean` and `make distclean` are supported.

### User agent
In this project, libcurl is supported for SP as user agent on Linux to communicate with IAS. Using wget is not recommended, but if you want, you can change setting following Intel`s original RA sample's README.

## Usage
### Set up DB for secret data storing
There must be two tables within one database.

One is table named `userinfo`, which is for management of login info. The format of `userinfo` is following:

```
+-----------+----------+------+-----+---------+-------+
| Field     | Type     | Null | Key | Default | Extra |
+-----------+----------+------+-----+---------+-------+
| dataname  | text     | YES  |     | NULL    |       |
| owner     | text     | YES  |     | NULL    |       |
| data      | longblob | YES  |     | NULL    |       |
| cipherlen | int(11)  | YES  |     | NULL    |       |
+-----------+----------+------+-----+---------+-------+
```

And another is named `stored_data`, which is for storing secret data. The format of `stored_data` is following: 

```
+-----------+------+------+-----+---------+-------+
| Field     | Type | Null | Key | Default | Extra |
+-----------+------+------+-----+---------+-------+
| username  | text | YES  |     | NULL    |       |
| pass_hash | text | YES  |     | NULL    |       |
| privilege | text | YES  |     | NULL    |       |
+-----------+------+------+-----+---------+-------+
```

So ISV have to create above tables as aforementioned formats before start BI-SGX.

After started program, ISV must initialize DB login info. As default, this initialization will be done by following context:

``` C++
host = "localhost";
user = "BI-SGX";
password = "bisgx_sample";
database = "`BI-SGX`";
```
But hardcoded login context is extremely insecure, so you should edit `void BISGX_Database::initDB()` in `client.cpp` to manually enter login context using like `cout`. More secure login method will be impremented in the future.

### Start programs
You can run ISV (SGX server) code by entering command:
```bash
$ ./run-isv
```
To run SP (non-SGX client) code, enter command:
```bash
$ ./run-sp
```

Default IP address is `localhost` and default port is `7777`.
You can also use `./run-client` to start ISV and `./run-server` to start SP, but their names are inconsistent with their actual roles.

### Send data from SP to ISV
After complete RA, you can send your file to ISV from SP.

#### If you are data owner (use data storage feature)
Firstly, you have to prepare login context as `login.ini`. Username, password, and authority-type should be described like following:

``` bash
testuser # username 
testpass12345 # password
O # authority type. "O" for data owner and "R" for researcher.
```

Secondly, you have to prepare data to store to cloud server.
Currently 2 data types are acceptable; One is to be set of `int` or `double`, and another is to be set of `char`. The separator must be newline (`\n`).

After completing remote attestation, you will be required to input filename of dataset. Then cloud DB storing will be executed and the result status will be returned from cloud server.

#### If you are researcher (use interpreter feature)
Firstly, you have to prepare `login.ini` as with the case of data owner.
Note that authority type is `R` for researcher.

After completing remote attestation, you will be required to input filename of interpreter code. Then interpreter code will be executed at cloud's enclave and the result will be returned from cloud server.

## Specification/grammer of BI-SGX 
See at [BI-SGX's wiki](https://github.com/hello31337/BI-SGX) for interpreter's specifications and grammers.

## Implemented features
* Inverted client-server communication model
* Remote Attestation between SP and ISV
* Cryptographic features to send secret in secure
* Load secret into enclave
* DB storing feature for data owner
* Interpreter which runs inside enclave

## TODO
* Implement more built-in functions for interpreter

## LICENSE
All of these codes are developed and distributed under Intel Sample Source Code license. See the LICENSE file for detail.

And many of BI-SGX's interpreter implementation owe to following book:
ISBN978-4-7973-6881-9「明快入門 インタプリタ開発」
