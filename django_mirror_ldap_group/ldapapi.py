import ldap


# Python LDAP Resources
# https://blogs.oracle.com/marginNotes/entry/ldap_basics_with_python
# http://code.activestate.com/lists/python-list/603895/
class LDAPAPI(object):
    def __init__(self, ldap_uri, ldap_username, ldap_password, ldap_referrals=()):
        self.ldap_uri = ldap_uri
        self.ldap_username = ldap_username
        self.ldap_password = ldap_password
        self.ldap_referrals = ldap_referrals

    @property
    def ldap_uri(self):
        return self._ldap_uri

    @ldap_uri.setter
    def ldap_uri(self, value):
        if not value: raise ValueError(u"You must enter an LDAP URI!")
        self._ldap_uri = value

    @property
    def ldap_username(self):
        return self._ldap_username

    @ldap_username.setter
    def ldap_username(self, value):
        if not value: raise ValueError(u"You must enter an LDAP Username!")
        self._ldap_username = value

    @property
    def ldap_password(self):
        return self._ldap_password

    @ldap_password.setter
    def ldap_password(self, value):
        if not value: raise ValueError(u"You must enter an LDAP Password!")
        self._ldap_password = value

    @property
    def ldap_referrals(self):
        return self._ldap_referrals

    @ldap_referrals.setter
    def ldap_referrals(self, value):
        if value:
            error_msg = u"LDAP Referrals Must be an list of dictionaries with the keys uri, username, and password! " \
                        u"Example: [{'uri': 'ldap://mydomain.com', " \
                        u"'username': 'CN=MY_ACCOUNT,OU=Accounts,DC=mydomain,DC=com', " \
                        u"'password': 'mypassword'},]"
            if not isinstance(value, (tuple, list)): raise ValueError(error_msg)
        self._ldap_referrals = value

    @staticmethod
    def _connect(ldap_uri, ldap_username, ldap_password):
        """
        :param ldap_uri: The uri to the AD Domain
        :param ldap_username: The username of the bind account
        :param ldap_password: The password of the bind account
        :return: An secure ldap bind connection object

        Use this method to create an ldap connection object to run ldap commands
        """
        ldap_connection = ldap.initialize(ldap_uri)
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connection.start_tls_s()
        ldap_connection.bind_s(ldap_username, ldap_password)
        return ldap_connection

    @staticmethod
    def _ldap_disconnect(ldap_connection):
        """
        :param ldap_connection: Must be an instance of the _connect method

        Use to disconnect the ldap session
        Must use this after done using LDAPAPI or else might have some issue authenticating again
        """
        ldap_connection.unbind()  # Unbind connection

    def get_group_members(self, basedn="OU=Groups,OU=TDBFG,DC=TDBFG,DC=com", groupdn="CN=IDBD_SCE_Approver"):
        """
        :param basedn: A base dn is the point from where a server will search for groups. Example: 'dc=example,dc=com'.
        :param groupdn: The distinguished Name of the group to search for in Active Directory.
        :return: Tuple with status of True or False and a list of group members with dictionary of there properties or an error message
        """
        ldap_connection = {}
        group_members = []

        try:
            ldap_connection = self._connect(self.ldap_uri, self.ldap_username, self.ldap_password)
            groupdn_result = ldap_connection.search_s("{groupdn},{basedn}".format(groupdn=groupdn, basedn=basedn),
                                                      ldap.SCOPE_BASE)
        except ldap.LDAPError, error:
            return False, u"LDAP lookup failed. {LDAP_ERROR}".format(LDAP_ERROR=error)
        except:
            return False, u"Unknown LDAP error has occurred."

        if groupdn_result:
            groupdn_result = groupdn_result[0][1]

            if groupdn_result.get('member'):
                for member in groupdn_result.get('member'):
                    status, user = self.get_user_attributes(userdn=member)
                    if status and user:
                        if 'sAMAccountName' and 'givenName' and 'sn' and 'mail' in user:
                            group_members.append({'username': user['sAMAccountName'][0].lower(),
                                                  'first_name': user['givenName'][0],
                                                  'last_name': user['sn'][0],
                                                  'mail': user['mail'][0]})
         # Disconnect current LDAP session
        if ldap_connection:
            self._ldap_disconnect(ldap_connection)

        if group_members:
            return True, group_members
        else:
            return False, u"LDAP lookup failed to find AD group members."

    def get_user_attributes(self, userdn):
        """
        :param userdn: A distinguished name of a user in Active Directory
        :return: A tuple with status of True or False, and a dictionary of the users Active Directory attributes
        """
        ldap_connection = None
        user_search_result = {}

        try:
            ldap_connection = self._connect(ldap_uri=self.ldap_uri,
                                            ldap_username=self.ldap_username,
                                            ldap_password=self.ldap_password)
            user_search_result = ldap_connection.search_s(userdn, ldap.SCOPE_SUBTREE)
        except ldap.LDAPError, error:
            for ldap_referral in self.ldap_referrals:
                try:
                    ldap_connection = self._connect(ldap_uri=ldap_referral.get('uri'),
                                                    ldap_username=ldap_referral.get('username'),
                                                    ldap_password=ldap_referral.get('password'))
                    user_search_result = ldap_connection.search_s(userdn, ldap.SCOPE_SUBTREE)
                    break
                except ldap.LDAPError, error:
                    return False, u"LDAP user lookup failed. {LDAP_ERROR}".format(LDAP_ERROR=error)
                except:
                    return False, u"Unknown LDAP error has occurred while getting user attributes."
            else:
                return False, u"LDAP user lookup failed. {LDAP_ERROR}".format(LDAP_ERROR=error)
        except:
            return False, u"Unknown LDAP error has occurred while getting user attributes."

        # Disconnect current LDAP session
        if ldap_connection:
            self._ldap_disconnect(ldap_connection)

        if user_search_result:
            user_dictionary = user_search_result[0][1]  # [0] = List of results; [1] = Dict of attributes
            return True, user_dictionary
        else:
            return False, {}