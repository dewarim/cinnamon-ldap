# Cinnamon 4 LDAP Connector

Note: this module is not production ready since the Cinnamon CMS v4 Server is not yet finished.
The API will change.

## Introduction

The LDAPConnector implements the LoginProvider interface of the Cinnamon CMS.

        LoginResult connect(String username, String password);

## Configuration

See the example [ldap-config.xml](ldap-config.xml) 
as well as the commented [LdapConfig class](src/main/java/com/dewarim/cinnamon/ldap/LdapConfig.java).

## Usage (command line)

(with Java 8)

    # build with maven 3:
    mvn clean assembly:assembly
    
    # invoke:
    java -cp target/cinnamon-ldap-jar-with-dependencies.jar com.dewarim.cinnamon.ldap.LdapConnector $userName $userPassword

(with Java 9 - currently not enabled)
    
    # build with maven 3:
    mvn clean assembly:assembly
    
    # invoke:
    java -cp target/cinnamon-ldap-jar-with-dependencies.jar com.dewarim.cinnamon.ldap.LdapConnector $userName $userPassword

## License
 
To be determined.

## Dependencies

Directly depends on:

* UnboundID LDAP SDK under [LGPL 2.1 license](doc/unboundID-ldap-sdk-from-ldap.com-LICENSE-LGPLv2.1.txt).
* [Jackson-Dataformat-xml](https://github.com/FasterXML/jackson-dataformat-xml) - Apache 2.0 License
* [WoodStox Sax Parser](https://github.com/FasterXML/woodstox) Apache 2.0 License  
  (Note: the [License file for Jackson Dataformat and WoodStox](doc/jackson-and-woodstox-apache-license-file.txt) seems to be copypasta from an earlier project.)
* [Apache Log4j 2.x](https://logging.apache.org/log4j/2.x/) used under Apache 2.0 License 

## Author & Copyright

Ingo Wiarda / 2018

Mail: ingo_wiarda@dewarim.de