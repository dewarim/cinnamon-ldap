package com.dewarim.cinnamon.ldap;

import com.dewarim.cinnamon.api.login.GroupMapping;
import com.dewarim.cinnamon.api.login.LoginProvider;
import com.dewarim.cinnamon.api.login.LoginResult;
import com.dewarim.cinnamon.api.login.LoginUser;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.unboundid.ldap.sdk.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * LDAP connector using the UnboundId LDAP SDK licensed under LGPL 2.1
 * See: https://www.ldap.com/unboundid-ldap-sdk-for-java
 */
public class LdapConnector implements LoginProvider {

    private static final Logger log = LogManager.getLogger(LdapConnector.class);


    private LdapConfig ldapConfig;

    public LdapConnector(LdapConfig ldapConfig) {
        this.ldapConfig = ldapConfig;
    }

    public LdapResult connect(LoginUser user, String password) {
        String username = escapeUsername(user.getUsername());
        LDAPConnection conn = null;
        try {
            log.debug("Connecting to {}:{} with '{}' for user '{}'", 
                    ldapConfig.getHost(), ldapConfig.getPort(), getBaseDn(username), username);
            conn = new LDAPConnection(ldapConfig.getHost(), ldapConfig.getPort(), getBaseDn(username), password);
            log.debug("connection: " + conn);
            final LDAPConnection connection = conn;
            List<GroupMapping> groupMappings = ldapConfig.getGroupMappings().stream()
                    .filter(groupMapping -> searchForGroup(connection, groupMapping.getExternalGroup(), username))
                    .collect(Collectors.toList());

            return new LdapResult(!groupMappings.isEmpty(), groupMappings, ldapConfig.getDefaultLanguageCode());

        } catch (Exception e) {
            log.warn("Failed to connect with LDAP server", e);
            // ldap error message is 0 terminated, which upsets the XML serializer for LdapResult.
            String errorMessage = e.getMessage().replace('\u0000', ' ');
            return new LdapResult("Failed to connect with LDAP server: " + errorMessage);
        } finally {
            if (conn != null && conn.isConnected()) {
                conn.close();
            }
        }
    }

    private boolean searchForGroup(LDAPConnection connection, String ldapGroupName, String username) {
        try {
            SearchResultEntry searchResultEntry = connection.searchForEntry(getSearchBaseDn(ldapGroupName),
                    SearchScope.BASE, ldapConfig.getSearchFilter(), ldapConfig.getSearchAttribute());

            String[] attributeValues = searchResultEntry.getAttributeValues(ldapConfig.getSearchAttribute());
            log.debug("looking at group '{}' with attributeValues '{}' starting with 'CN={},'", ldapGroupName, attributeValues, username);
            return Arrays.stream(attributeValues).anyMatch(member -> member.startsWith("CN=" + username + ","));

        } catch (LDAPSearchException e) {
            log.debug(String.format("Failed to search for group %s for user %s", ldapGroupName, username), e);
            return false;
        }
    }

    private String getBaseDn(String username) {
        return String.format(ldapConfig.getBindDnFormatString(), username);
    }
    
    private String escapeUsername(String username){
        return username.replace(",","\\,");
    }

    private String getSearchBaseDn(String groupName) {
        return String.format(ldapConfig.getSearchBaseDnFormatString(), groupName);
    }

    public static void main(String[] args) throws IOException {
        final String username;
        final String password;
        if (args.length == 2) {
            username = args[0];
            password = args[1];
        }
        else{
            username = "John Doe";
            password = "Dohn.Joe_1"; 
        }
        XmlMapper mapper = new XmlMapper();
        LdapConfig ldapConfig = mapper.readValue(new File("ldap-config.xml"), LdapConfig.class);

        LdapConnector ldapConnector = new LdapConnector(ldapConfig);
        LoginUser loginUser = new LoginUser() {
            
            @Override
            public String getLoginType() {
                return "LDAP";
            }

            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public String getPasswordHash() {
                return null;
            }
        };
        LdapResult result = ldapConnector.connect(loginUser, password);
        mapper.writerWithDefaultPrettyPrinter().writeValue(System.out, result);
        System.out.println("\n");
    }

    @JacksonXmlRootElement(localName = "ldapResult")
    public static class LdapResult implements LoginResult {
        private String errorMessage;
        private boolean validUser;
        private List<GroupMapping> groupMappings = Collections.emptyList();
        private String defaultLanguageCode;

        public LdapResult(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public LdapResult(boolean validUser, List<GroupMapping> groupMappings, String defaultLanguageCode) {
            this.validUser = validUser;
            this.groupMappings = groupMappings;
            this.defaultLanguageCode = defaultLanguageCode;
        }

        public boolean isValidUser() {
            return validUser;
        }

        @Override
        public boolean groupMappingsImplemented() {
            return true;
        }

        public List<GroupMapping> getGroupMappings() {
            return groupMappings;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        @Override
        public String getUiLanguageCode() {
            return defaultLanguageCode;
        }

    }

    @Override
    public String getName() {
        return "LDAP";
    }
}
