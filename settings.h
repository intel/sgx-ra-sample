#ifndef __SETTINGS__H
#define __SETTINGS__H

/*----------------------------------------------------------------------
 * IAS API version
 *----------------------------------------------------------------------
 * Default API version to use when querying IAS. 
 *
 * This can be overriden by the -r option to sp.
 */
#define IAS_API_DEF_VERSION    4

/*----------------------------------------------------------------------
 * CA Certificate Bundles
 *----------------------------------------------------------------------
 * The root CA bundle used to validate the IAS server certificate. The
 * default should be correct for Linux.
 *
 * Windows does not use a bundle file natively, but libcurl for Windows
 * does. If you installed libcurl somewhere other than the default
 * path then you will need to change this.
 *
 * These settings are overridden by the -B option to sp
 */

/* Default CA bundle file on Linux (auto-detected by default, comes from
 * config.h) */
#define DEFAULT_CA_BUNDLE_LINUX	DEFAULT_CA_BUNDLE_AUTO

/* Default CA bundle file on Windows */
#define DEFAULT_CA_BUNDLE_WIN32	"C:\\Program Files\\cURL\\bin\\curl-ca-bundle.crt"


#endif
