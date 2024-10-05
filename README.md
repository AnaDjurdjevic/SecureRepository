<h1>Secure Repository</h1>    
Develop an application that serves as a secure repository for storing confidential documents. 
The application should allow for document storage for multiple users, ensuring that access to a particular document is granted only to its owner.    
Users log into the system in two steps. In the first step, they need to provide a digital certificate, which each user receives when creating their account.
If the certificate is valid, a form for entering the username and password is displayed. After successful login, the user is presented with a list of their documents through an interface implemented in any manner.    
The application allows users to download existing documents as well as upload new ones. Each new document, before being stored in the file system,
is divided into N segments (N ≥ 4, a randomly generated value), with each segment stored in a different directory to further enhance system security and reduce the risk of document theft. 
The confidentiality and integrity of each segment must be adequately protected so that only the user who owns the document can access and view its contents. 
The application should detect any unauthorized changes to the stored documents and notify the user of such changes when attempting to download those documents.    
The application assumes the existence of a public key infrastructure (PKI). All certificates must be issued by a CA (Certification Authority) that is established before the application begins operation.
It should be assumed that the CA certificate, CRL (Certificate Revocation List), certificates of all users, 
and the private key of the currently logged-in user will be located at an arbitrary location in the file system (there is no need to implement key exchange mechanisms).
User certificates should be restricted so that they can only be used for purposes required by the application. Additionally, the data in the certificate should be linked to the corresponding user information.    
User certificates are issued for a period of 6 months. Furthermore, if a user enters incorrect credentials three times during one login session,
their certificate will be automatically suspended, and the application will display an appropriate message. 
Afterward, the application offers the user the option to reactivate the certificate (if they provide correct credentials) or register a new account.
