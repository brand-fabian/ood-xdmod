# XDMoD OpenOnDemand App

An OpenOnDemand app to view XDMoD statistics.

---
**Caution:**

This app is quintessentially just a reverse proxy for an OpenXDMod Instance
running at a different server. It provides a functional interface by proxying
all requests to the XDMoD instance and changing request and response values.
Since it relies on a specific pattern in request and response files this may
not work with other versions of XDMoD and OpenOnDemand.

---
**Double Caution:**

To perform authentication with XDMoD this tool will MITM-Attack your SAML
authentication. This might have _severe_ security implications depending on
your environment.

---
**Resources:**

 * [OpenOnDemand](https://github.com/OSC/ondemand)
 * [Open XDMoD](https://github.com/ubccr/xdmod)
 * [Keycloak](https://www.keycloak.org)

## Setup

This app was built and tested against the following components:

 * OpenOnDemand v1.8.8
 * Open XDMoD v9.0
 * Keycloak

OpenOnDemand and XDMoD both have been set up with Keycloak as Identity Provider
through their respective configuration processes (SAML, OIDC). This is an important
prerequisite for this app.

Additionally, this app requires python v3.6. On CentOS 7, make sure you have the
scl `rh-python36` installed and configured your PU-NGINX to use this environment.

## Installation

1. Check out the repository to a valid ood app directory.

```bash
git clone <REPO_URL> /var/www/ood/apps/dev/<USER>/gateway/xdmod
```
2. Install the dependencies in a virtual environment:

```bash
bash setup.sh
```
3. Configure the application by setting all appropriate values at the
  top of app.py (Lines: 14-20)
4. Generate an X509 Certificate and paste the content of the private key and
  certificate in lines 19 and 20 respectively.
5. Change line 30 of static/login.js to point to your xdmod instance.

### Keycloak

Adjust your keycloak SAML settings to allow ClientID's originating from your
OpenOnDemand instance.

For example, if your Keycloak SAML Client ID line read:

```
https://xdmod.example.org/simplesaml/module.php/saml/sp/metadata.php/default-sp
```

change it to:

```
https://ood.example.org/pun/dev/xdmod/simplesaml/module.php/saml/sp/metadata.php/default-sp
```

Since this tool will change the `SAMLRequest` sent out from the backend xdmod
service, you must also disable checking request signatures in the keycloak
client configuration.

### XDMoD

Since this app will interfere with the SAML traffic, we have to allow the 
certificate of that we set in app.py in the simplesamlphp configuration.

To that end, change `/etc/xdmod/simplesamlphp/metadata/saml20-idp-remote.php`
to include the Certificate of this remote proxy as valid x509 signing cert.

Additionally, since the return url will point towards the OpenOnDemand instance,
add the url of your instance to the whitelist of valid Domains in your
`/etc/xdmod/simplesamlphp/config/config.php`.
