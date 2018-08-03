# LDAPS - LDAP over SSL/TLS

The Lightweight Directory Access Protocol (LDAP) is used to read from and write to Active Directory. 
By default, LDAP traffic is transmitted unsecured.

Make LDAP traffic confidential and secure by using Secure Sockets Layer (SSL) / Transport Layer Security (TLS) technology. 
Enable LDAP over SSL/TLS (LDAPS) by installing a properly formatted certificate from either a Microsoft certification authority (CA) or a non-Microsoft CA following the guidelines in [my blog article](https://kurtroggen.wordpress.com/2018/08/03/are-you-using-ldap-over-ssl-tls/) and related PowerShell functions from [my GitHub repository](https://github.com/roggenk/PowerShell/tree/master/LDAPS).
