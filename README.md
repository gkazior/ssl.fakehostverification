# ssl fakehostverification

   Fake host verification for ssl

   When Java establishes the ssl connection to host X it has to verify if
   the host in the certificate presented by host X matches the host X.
   If the host information does not match then this is a security breach or at least the certificate is not valid.

   In some situations (see the background) you may want to disable the verification.
   Remember about the risks. Never use it in production.

## Documentation

   The java agent will disable hostname verification for test purposes.
   Never use it in production!

   May be usefull when you have:

        javax.net.ssl.SSLHandshakeException: java.security.cert.CertificateException: No subject alternative names present
                at sun.security.ssl.Alerts.getSSLException(Alerts.java:192) ~[na:1.7.0_71]
                at sun.security.ssl.SSLSocketImpl.fatal(SSLSocketImpl.java:1884) ~[na:1.7.0_71]
                at sun.security.ssl.Handshaker.fatalSE(Handshaker.java:276) ~[na:1.7.0_71]
                at sun.security.ssl.Handshaker.fatalSE(Handshaker.java:270) ~[na:1.7.0_71]
                at sun.security.ssl.ClientHandshaker.serverCertificate(ClientHandshaker.java:1439) ~[na:1.7.0_71]
                at sun.security.ssl.ClientHandshaker.processMessage(ClientHandshaker.java:209) ~[na:1.7.0_71]
                at sun.security.ssl.Handshaker.processLoop(Handshaker.java:878) ~[na:1.7.0_71]
                at sun.security.ssl.Handshaker.process_record(Handshaker.java:814) ~[na:1.7.0_71]
                at sun.security.ssl.SSLSocketImpl.readRecord(SSLSocketImpl.java:1016) ~[na:1.7.0_71]
                at sun.security.ssl.SSLSocketImpl.performInitialHandshake(SSLSocketImpl.java:1312) ~[na:1.7.0_71]
                at sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:1339) ~[na:1.7.0_71]
                at sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:1323) ~[na:1.7.0_71]
        Caused by: java.security.cert.CertificateException: No subject alternative names present
                at sun.security.util.HostnameChecker.matchIP(HostnameChecker.java:142) ~[na:1.7.0_71]
                at sun.security.util.HostnameChecker.match(HostnameChecker.java:91) ~[na:1.7.0_71]
                at sun.security.ssl.X509TrustManagerImpl.checkIdentity(X509TrustManagerImpl.java:347) ~[na:1.7.0_71]
                at sun.security.ssl.X509TrustManagerImpl.checkTrusted(X509TrustManagerImpl.java:203) ~[na:1.7.0_71]
                at sun.security.ssl.X509TrustManagerImpl.checkServerTrusted(X509TrustManagerImpl.java:126) ~[na:1.7.0_71]
                at sun.security.ssl.ClientHandshaker.serverCertificate(ClientHandshaker.java:1421) ~[na:1.7.0_71]
                ... 62 common frames omitted

   The hack is based on Vadim Kopichenko comments on disabling hostname verification here:

   http://stackoverflow.com/questions/6031258/java-ssl-how-to-disable-hostname-verification


## Caution

   Replacing HostnameVerifier can be very dangerous, because a man-in-the-middle could intercept your traffic.

## Usage

   Suppose you are running:

        java -jar yourApp.jar

   then add the javaagent argument which disables the hostname verification.

        java -javaagent:fakehostverification.jar -jar yourApp.jar

   Usually it is enough to set JAVA_OPTS before running the java application, since many tools picks up the JAVA_OPTS variable:

        export JAVA_OPTS="-Djavax.net.ssl.trustStore=/tmp/app.truststore -Djavax.net.ssl.trustStorePassword=changeit -javaagent:/tmp/fakehostverification.jar"
        java $JAVA_OPTS -jar yourApp.jar


## Some background

   In http://tools.ietf.org/html/rfc6125

   1.7.2.  Out of Scope

   [...]
   Furthermore, IP addresses are not necessarily
   reliable identifiers for application services because of the
   existence of private internets [PRIVATE], host mobility, multiple
   interfaces on a given host, Network Address Translators (NATs)
   resulting in different addresses for a host from different
   locations on the network, the practice of grouping many hosts
   together behind a single IP address, etc.  Most fundamentally,
   most users find DNS domain names much easier to work with than IP
   addresses, which is why the domain name system was designed in the
   first place.  We prefer to define best practices for the much more
   common use case and not to complicate the rules in this
   specification.
   [...]

   B.2.  HTTP (2000)
   [...]
   In some cases, the URI is specified as an IP address rather than a
   hostname.  In this case, the iPAddress subjectAltName must be present
   in the certificate and must exactly match the IP in the URI.
   [...]

   3.1.3.2.  Comparison of IP Addresses
   [...]
   When the reference identity is an IP address, the identity MUST be
   converted to the "network byte order" octet string representation
   [IP] [IPv6].  For IP Version 4, as specified in RFC 791, the octet
   string will contain exactly four octets.  For IP Version 6, as
   specified in RFC 2460, the octet string will contain exactly sixteen
   octets.  This octet string is then compared against subjectAltName
   values of type iPAddress.  A match occurs if the reference identity
   octet string and value octet strings are identical.
   [...]


## Compilation

        javac FakeHostnameVerifierAgent.java
        jar cmf manifest.txt fakehostverification.jar *.class

## Some reading

   * http://www.crsr.net/Notes/SSL.html
   * http://apetec.com/support/GenerateSAN-CSR.htm

   * http://bugs.java.com/view_bug.do?bug_id=6766775
   * http://stackoverflow.com/questions/6031258/java-ssl-how-to-disable-hostname-verification
   * http://stackoverflow.com/questions/11898566/tutorials-about-javaagents
   * https://stackoverflow.com/questions/10423319/how-do-you-analyze-fatal-javaagent-errors

   * http://www.nakov.com/blog/2009/07/16/disable-certificate-validation-in-java-ssl-connections/
   * https://tersesystems.com/2014/03/23/fixing-hostname-verification/
   * http://serverfault.com/questions/109800/multiple-ssl-domains-on-the-same-ip-address-and-same-port
   * http://stackoverflow.com/questions/19540289/how-to-fix-the-java-security-cert-certificateexception-no-subject-alternative
   * http://stackoverflow.com/questions/10258101/sslhandshakeexception-no-subject-alternative-names-present
   * http://www.mkyong.com/webservices/jax-ws/how-to-bypass-certificate-checking-in-a-java-web-service-client/
   * http://stackoverflow.com/questions/8443081/how-are-ssl-certificate-server-names-resolved-can-i-add-alternative-names-using/8444863#8444863

   * https://wiki.jasig.org/display/CASUM/SSL+Troubleshooting+and+Reference+Guide#SSLTroubleshootingandReferenceGuide-ImportTrustedCertificate
   * https://holisticsecurity.wordpress.com/2011/02/19/web-sso-between-liferay-and-alfresco-with-cas-and-penrose-part-22/

##  Usefull options

        -Djavax.net.debug=all
        -Djavax.net.ssl.trustStore=/tmp/app.truststore
        -Djavax.net.ssl.trustStorePassword=changeit  # this is standard password for jks keystore/truststore
        -Dssl.debug=true
        -Dsun.security.ssl.allowUnsafeRenegotiation=true

