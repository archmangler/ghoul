# Ghoul Self-Blogging Platform

* A very simple blogging app in Python Flask. Not a ghost but a ghoul (this is an insider joke ;-))

## TLS/HTTPS Support

### The TLS Implementation

* Adds TLS configuration storage in the database
* Provides an admin interface to:
* Upload SSL/TLS certificate and private key
* Specify the FQDN
* Enable/disable TLS
* Validates certificates before accepting them
* Automatically switches between HTTP and HTTPS based on configuration
* Uses TLS 1.2 protocol
* Stores certificates securely in a separate directory
* Provides feedback about the current TLS status
* Maintains existing certificates when form is submitted without new ones

To use this:

* Obtain a valid SSL/TLS certificate and private key for your domain
* Access the admin panel and go to TLS configuration
* Upload your certificate and key
* Specify your domain name
* Enable TLS
* Restart the application
* The application will automatically start in HTTPS mode if TLS is properly configured.

