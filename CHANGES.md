## Release History

### v3.0

Release on 7/x/2019.

 * Switch from user certificate authentication to API subscription keys per
   the Attestation Service for Intel SGX API Documentation, version 5.

 * (Windows) Provide native client agent via WinHTTP, replacing libcurl.

 * Add Enclave verification policy checks for: MRSIGNER, ProdId, and ISVSVN.
   Also add option to reject enclaves that are built in Debug mode.

### v2.2.2

Released on 9/28/2018.

 * Verify that the report version matches the API version when
   retrieving attestation evidence. This applies to IAS API v3
   and later.

 * (Linux) Add basic signal-handling to the server to gracefully shutdown
   the listening socket on an interrupt. This should prevent "address already
   in use" errors if the server is interrupted and then restarted rapidly.

 * (Linux) Don't complain if OPENSSL_LIBDIR is not set in the wrapper scripts
   run-client and run-server.

### v2.2.1

Released on 9/18/2018.

 * Added verification of the enclave report by computing the SHA256
   hash of Ga || Gb || VK and comparing the result to the first
   32 bytes of quote.report\_body.report\_data. Also verify next 32
   bytes of report_data is a block of 0x00's

 * Created an ra_session_t data structure to separate session data
   from global configuration variables.

### v2.1

Released on 9/7/2018.

 * Added -X switch (--strict-trust-mode) so the service provider can choose
   whether or not to trust enclaves that result in a CONFIGURATION_NEEDED
   status from IAS. Previously, any result that was not OK resulted in a
   "not trusted" result.

 * Added Trusted_Complicated and NotTrusted_Complicated response codes.
   When a trust result is complicated, the client can be brought into
   full compliance by taking action that's reported in the Platform
   Information Block (PIB).

 * Added derivations of the MK and SK keys in the client and server so.

 * Added POLICY_STRICT_TRUST variable to settings files for both Linux
   and Windows (see -X, above)

 * Various tweaks to documentation and comments.
