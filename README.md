# Palo Alto Intermediate CA Certificate Fetch and Upload

This script takes a series of TLS servers in the form of **host:tcp_port**, checks their server TLS certificate's AIA section and uses the URL contained in it to retrieve the certificate issuer's CA certificate. If this CA certificate is found in the [Common CA Database](https://www.ccadb.org/)'s [list](https://wiki.mozilla.org/CA/Intermediate_Certificates) of **"non-revoked, non-expired Intermediate CA Certificates chaining up to roots in Mozilla's program with the Websites trust bit set"**, it is uploaded to the firewall or Panorama with the "Trusted Root CA" setting enabled.

This makes it easy to avoid the firewall presenting the [Forward Untrust Certificate](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/decryption/decryption-concepts/keys-and-certificates-for-decryption-policies) or blocking the connection altogether when performing Forward Proxy Decryption for broken websites that send an incomplete certificate chain. The firewall does not perform (as of 2023) AIA Fetching or Intermediate Preloading, and thus cannot complete the validation successfully with just the Root CA in its store.

The [file](https://ccadb-public.secure.force.com/mozilla/MozillaIntermediateCertsCSVReport) maintained by Mozilla is essentially what browsers use to perform [Intermediate CA Preloading](https://blog.mozilla.org/security/2020/11/13/preloading-intermediate-ca-certificates-into-firefox/), but as this contains hundreds of certificates it is impractical to upload all of them into the firewall's configuration and keep it up to date. With this script it is possible to more easily (or even automatically) import a necessary CA once warnings are noticed or logged.

The CSV file from CCADB is rather large and is only re-downloaded to the specified location once per day. **It is crucial to ensure that this file is stored securely** and is not altered between executions of the script; it determines which certificates will and will not be trusted by the firewall you are using the script on, for several tasks performed by the device.

The script supports uploading the certificate to a firewall or a Panorama template, in a Shared or Vsys location. A change preview and commit feature is implemented to avoid having to manually commit the configuration.

### Usage

```
usage: palo_subca_importer.py [-h] [-k] [-z] [-s] [-t TEMPLATE] [-v VSYS] [-f] [-y] [-d] [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}] device domain_port [domain_port ...]

positional arguments:
  device                Firewall or Panorama IP or FQDN
  domain_port           FQDN or IP and port of a TLS Server, e.g. example.com:443. Will use 443 as port if not specified.

optional arguments:
  -h, --help            show this help message and exit
  -k, --ignore-fw-certs
                        Do not validate the firewall or Panorama certificate when connecting to it. Default: False
  -z, --upload-dangerous
                        DANGEROUS: Upload the CA to the device even if it is not found in the Mozilla CCADB. This means it does not chain up to a publicly trusted root CA, it is expired/revoked, or it is not an intermediate CA. Default: False
  -s, --deprecated-tls  Enable checking sites using SSLv3, TLSv1.0, TLSv1.1. These may already work, depending on the version of the ssl library. Default: False
  -t TEMPLATE, --template TEMPLATE
                        Destination Panorama Template, must be set for Panoramas
  -v VSYS, --vsys VSYS  Destination Vsys, otherwise Shared
  -f, --upload-duplicates
                        Upload certificate to the firewall even if a certificate with the same name is already present. Default: False
  -y, --automatic       Start the commit without asking for confirmation. Default: False
  -d, --dry-run         Run the mechanism without changing anything on the firewall. Default: False
  -x {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --debug-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging message verbosity. Default: WARNING
```
```
Example:

  $ python3 palo_subca_importer.py -t Cert_Template -v vsys3 192.0.2.1 example.com 203.0.113.1:8443 example.org:10443
```

The script has been tested with PanOS 9.1, 10.1, 10.2.

### Requirements

- [pandas](https://pypi.org/project/pandas/) (install with ```pip3 install pandas```)

- [cryptography](https://pypi.org/project/cryptography/) (install with ```pip3 install cryptography```)

### License

This project is licensed under the [MIT License](LICENSE).
