#ifndef __SETTINGS__H
#define __SETTINGS__H

/* Default API version to use when querying IAS */
#define IAS_API_DEF_VERSION     2

/*----------------------------------------------------------------------
 * CA Certificate Bundles
 *----------------------------------------------------------------------
 * The root CA bundle used to validate the IAS server certificate. The
 * default should be correct for Linux.
 *
 * Windows does not use a bundle file natively, but libcurl for Windows
 * does. If you installed libcurl somewhere other than the default
 * path then you will need to change this.
 */

/* Default CA bundle file on Linux Windows */
#define DEFAULT_CA_BUNDLE_LINUX	"/etc/ssl/certs/ca-certificates.crt"

/* Default CA bundle file on Windows */
#define DEFAULT_CA_BUNDLE_WIN32	"C:\\Program Files\\cURL\\bin\\curl-ca-bundle.crt"


#endif
