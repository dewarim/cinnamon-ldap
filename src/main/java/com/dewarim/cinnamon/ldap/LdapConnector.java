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
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * LDAP connector using the UnboundId LDAP SDK licensed under LGPL 2.1
 * See: https://www.ldap.com/unboundid-ldap-sdk-for-java
 */
public class LdapConnector implements LoginProvider {

    private static final Logger log = LogManager.getLogger(LdapConnector.class);

    private final LdapConfig ldapConfig;

    public LdapConnector(LdapConfig ldapConfig) {
        this.ldapConfig = ldapConfig;
    }

    public LdapResult connect(LoginUser user, String password) {
        String         username = escapeUsername(user.getUsername());
        LDAPConnection conn     = null;

        String actualPassword = password;
        if (ldapConfig.useStaticBindPassword()) {
            actualPassword = ldapConfig.getStaticBindPassword();
        }

        try {
            log.debug("Connecting to {}:{} with '{}' for user '{}'",
                    ldapConfig.getHost(), ldapConfig.getPort(), getBaseDn(username), username);
            conn = new LDAPConnection(ldapConfig.getHost(), ldapConfig.getPort(), getBaseDn(username), actualPassword);
            log.debug("connection: " + conn);
            final LDAPConnection connection = conn;
            List<GroupMapping> groupMappings = ldapConfig.getGroupMappings().stream()
                    .filter(groupMapping -> searchForGroup(connection, groupMapping.getExternalGroup(), username))
                    .collect(Collectors.toList());

            if (!groupMappings.isEmpty()) {
                // get distinguished name and try to connect anew with the given user's password.
                log.debug("Found group mappings for user {}, now trying to extract DN", username);
                Optional<String> dnOpt = searchForDistinguishedName(connection, ldapConfig.getSearchAttributeForDn(), username);
                if (!dnOpt.isPresent()) {
                    return new LdapResult("Could not find distinguishedName for user.");
                }
                String distinguishedName = dnOpt.get();
                log.debug("Trying to login with the user {} and DN {}", username, distinguishedName);
                LDAPConnection dnConnection = new LDAPConnection(ldapConfig.getHost(), ldapConfig.getPort(), distinguishedName, password);
                if (dnConnection.isConnected()) {
                    return new LdapResult(true, groupMappings, ldapConfig.getDefaultLanguageCode());
                }
            }

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

    private Optional<String> searchForDistinguishedName(LDAPConnection connection, String ldapGroupName, String username) {
        try {
            String searchAttributeDn = ldapConfig.getSearchAttributeForDn();
            log.debug("found group {} for {}, now looking for DN with searchAttributeDn {}", ldapGroupName, username, searchAttributeDn);
            SearchResultEntry dnSearchResult = connection.searchForEntry(getSearchBaseDn(ldapGroupName),
                    SearchScope.BASE, ldapConfig.getSearchFilter(), searchAttributeDn);
            if(dnSearchResult == null){
                log.warn("No result found while searching for distinguishedName with {} for {}", ldapGroupName, username);
                return Optional.empty();
            }
            String[] dnAttributeValues = dnSearchResult.getAttributeValues(searchAttributeDn);
            switch (dnAttributeValues.length) {
                case 0:
                    log.info("Failed login - could not find DN for user {}", username);
                    return Optional.empty();

                case 1:
                    log.info("Success - Found DN '{}' for user {}", username);
                    return Optional.of(dnAttributeValues[0]);

                default:
                    log.info("Found more than one DN, will not proceed:\n {}", String.join("\n", dnAttributeValues));
                    return Optional.empty();
            }
        } catch (LDAPSearchException e) {
            log.debug(String.format("Failed to search for group %s for user %s", ldapGroupName, username), e);
            return Optional.empty();
        }
    }

    private boolean searchForGroup(LDAPConnection connection, String ldapGroupName, String username) {
        try {
            SearchResultEntry searchResultEntry = connection.searchForEntry(getSearchBaseDn(ldapGroupName),
                    SearchScope.BASE, ldapConfig.getSearchFilter(), ldapConfig.getSearchAttributeForGroup());
            if(searchResultEntry == null){
                log.warn("No result found while searching for group with {} for {}", ldapGroupName, username);
                return false;
            }
            String[] attributeValues = searchResultEntry.getAttributeValues(ldapConfig.getSearchAttributeForGroup());
            log.debug("looking at group '{}' with attributeValues '{}' starting with 'CN={},'", ldapGroupName, attributeValues, ldapGroupName);
            return Arrays.stream(attributeValues).anyMatch(member -> member.startsWith("CN=" + ldapGroupName + ","));
        } catch (LDAPSearchException e) {
            log.debug(String.format("Failed to search for group %s for user %s", ldapGroupName, username), e);
            return false;
        }
    }

    private String getBaseDn(String username) {
        return String.format(ldapConfig.getBindDnFormatString(), username);
    }

    private String escapeUsername(String username) {
        return username.replace(",", "\\,");
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
        } else {
            username = "John Doe";
            password = "Dohn.Joe_1";
        }
        XmlMapper  mapper     = new XmlMapper();
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
        private String             errorMessage;
        private boolean            validUser;
        private List<GroupMapping> groupMappings = Collections.emptyList();
        private String             defaultLanguageCode;

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
