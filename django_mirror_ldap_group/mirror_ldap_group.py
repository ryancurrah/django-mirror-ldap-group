from django.contrib.auth.models import User, Group
from django.core.mail import EmailMessage
from django_mirror_ldap_group import ldapapi


class MirrorLDAPGroup():
    """
    Django specific class that will mirror Active Directory group membership to Django group membership
    This class can check against multiple AD domains

    Once the init parameters have been passed
    Call the function 'django_mirror_ldap_group' to perform the mirroring it will return the status and a message
    """
    def __init__(self,
                 ldap_group_base_dn,
                 ldap_uri,
                 ldap_username,
                 ldap_password,
                 ldap_group_name,
                 ldap_referrals=(),
                 notify_new_user_added=False,
                 notify_to_email_addresses=None,
                 notify_from_email_address=None,
                 notify_portal_name=None,
                 notify_portal_link=None,
                 notify_custom_message=u''):
        """
        :param ldap_group_base_dn: A base dn is the point from where a server will search for groups. Example: 'dc=example,dc=com'.
        :param ldap_uri: The uri to the AD Domain where the group exists.
        :param ldap_username: The username of the bind account where the group exists.
        :param ldap_password: The password of the bind account where the group exists.
        :param ldap_group_name: The name of the group to search for in Active Directory.
        :param ldap_referrals: A list with dictionary(s) containing connection information for any AD Domain Controllers you wish to check. Example: [{'uri': '', 'username': '', 'password': ''},].
        :param notify_new_user_added: True or False sends emails to selected email addresses notifying of new users.
        :param notify_to_email_addresses: Required if notify_new_user_added True. List of String email addresses.
        :param notify_from_email_address: Required if notify_new_user_added True. Sting email address.
        :param notify_portal_name: Required if notify_new_user_added True. Name of the portal.
        :param notify_portal_link: Required if notify_new_user_added True. Link to the portal.
        :param notify_custom_message: Optional if notify_new_user_added True. String message.
        :return: Nothing
        """
        # Required options
        self.ldap_group_base_dn = ldap_group_base_dn
        self.ldap_uri = ldap_uri
        self.ldap_username = ldap_username
        self.ldap_password = ldap_password
        self.ldap_group_name = ldap_group_name
        self.ldap_referrals = ldap_referrals
        # Optional options
        self.notify_new_user_added = notify_new_user_added
        if self.notify_new_user_added:
            self.notify_to_email_addresses = notify_to_email_addresses
            self.notify_from_email_address = notify_from_email_address
            self.notify_portal_name = notify_portal_name
            self.notify_portal_link = notify_portal_link
            self.notify_custom_message = notify_custom_message

    @property
    def ldap_group_base_dn(self):
        return self._ldap_group_base_dn

    @ldap_group_base_dn.setter
    def ldap_group_base_dn(self, value):
        if not value: raise ValueError(u"Must enter an ldap_group_base_dn as a string! "
                                       u"Example: 'OU=Groups,OU=TDBFG,DC=TDBFG,DC=com'")
        self._ldap_group_base_dn = value

    @property
    def ldap_uri(self):
        return self._ldap_uri

    @ldap_uri.setter
    def ldap_uri(self, value):
        if not value: raise ValueError(u"Must enter an ldap_uri as a string! "
                                       u"Example: 'ldap://CORP.TDSECURITIES.com'")
        self._ldap_uri = value

    @property
    def ldap_username(self):
        return self._ldap_username

    @ldap_username.setter
    def ldap_username(self, value):
        if not value: raise ValueError(u"Must enter an ldap_username as a string!")
        self._ldap_username = value

    @property
    def ldap_password(self):
        return self._ldap_password

    @ldap_password.setter
    def ldap_password(self, value):
        if not value: raise ValueError(u"Must enter an ldap_password as a string!")
        self._ldap_password = value

    @property
    def ldap_group_name(self):
        return self._ldap_group_name

    @ldap_group_name.setter
    def ldap_group_name(self, value):
        if not value: raise ValueError(u"Must enter an ldap_group_name asa string! "
                                       u"Example: 'IDBD_SCE_Approvers'")
        self._ldap_group_name = value

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

    @property
    def notify_to_email_addresses(self):
        return self._notify_to_email_addresses

    @notify_to_email_addresses.setter
    def notify_to_email_addresses(self, value):
        if not value: raise ValueError(u"Must enter an notify_new_user_added_email_list!")
        if not isinstance(value, list): raise ValueError(u"Email addresses must be in a list!")
        self._notify_to_email_addresses = value

    @property
    def notify_from_email_address(self):
        return self._notify_from_email_address

    @notify_from_email_address.setter
    def notify_from_email_address(self, value):
        if not value: raise ValueError(u"Must enter an notify_from_email_address as a string! "
                                       u"Example: 'ryan.currah@td.com'")
        self._notify_from_email_address = value

    @property
    def notify_portal_name(self):
        return self._notify_portal_name

    @notify_portal_name.setter
    def notify_portal_name(self, value):
        if not value: raise ValueError(u"Must enter an notify_portal_name as a string! "
                                       u"Example: 'PORTAL NAME'")
        self._notify_portal_name = value

    @property
    def notify_portal_link(self):
        return self._notify_portal_link

    @notify_portal_link.setter
    def notify_portal_link(self, value):
        if not value: raise ValueError(u"Must enter an notify_portal_link as a string! "
                                       u"Example: 'http://myportal.com'")
        self._notify_portal_link = value

    def mirror_ldap_group(self):
        """
        :return: Tuple with status of True or False and a message

        This function is to be executed after init parameters are passed
        What this functions does:
        1. Gets group membership user information from ldapapi
        2. Creates the group if it doesnt already exists in Django
        3. Adds or updates users in Django from AD and associates them to the corresponding group
        4. Removes users from Django group that no longer exist in AD
        5. Returns the status True or False and a message
        """
        groupdn = "CN={GROUP_NAME}".format(GROUP_NAME=self.ldap_group_name)

        ldap = ldapapi.LDAPAPI(ldap_uri=self.ldap_uri,
                               ldap_username=self.ldap_username,
                               ldap_password=self.ldap_password,
                               ldap_referrals=self.ldap_referrals)

        ldap_status, ldap_group_members = ldap.get_group_members(basedn=self.ldap_group_base_dn, groupdn=groupdn)

        # To view the returned values uncomment below
        #print ldap_group_members

        if ldap_status:
            group_object = self._get_or_create_group()
            self._add_or_update_users(ldap_group_members=ldap_group_members, group_object=group_object)
            self._remove_non_existing_users(ldap_group_members=ldap_group_members, group_object=group_object)
            return True, u"{GROUP_NAME} Mirrored Successfully!".format(GROUP_NAME=self.ldap_group_name)
        else:
            return False, u"{GROUP_NAME} Mirroring Failed! {ERROR_MESSAGE}".format(GROUP_NAME=self.ldap_group_name,
                                                                                   ERROR_MESSAGE=ldap_group_members)

    def _get_or_create_group(self):
        group, created = Group.objects.get_or_create(name=self.ldap_group_name)
        return group

    def _add_or_update_users(self, ldap_group_members, group_object):
        """
        :param ldap_group_members: A list of users with properties in a dictionary {'username', 'first_name', 'last_name', 'mail'}
        :param group_object: An model object instance of a Django group
        :return: Nothing

        Add or update AD group members
        """
        new_users = []
        for member in ldap_group_members:
            user, created = User.objects.get_or_create(username=member.get('username'),
                                                       first_name=member.get('first_name'),
                                                       last_name=member.get('last_name'),
                                                       email=member.get('mail'))
            if user not in group_object.user_set.all():
                group_object.user_set.add(user)
                new_users.append(u'{0} {1} ({2})'.format(user.first_name, user.last_name, user.username))

        if self.notify_new_user_added and new_users:
            self._notify_new_user_added_function(usernames=new_users,
                                                 groupname=self.ldap_group_name)

    def _remove_non_existing_users(self, ldap_group_members, group_object):
        """
        :param ldap_group_members: A list of users with properties in a dictionary {'username', 'first_name', 'last_name', 'mail'}
        :param group_object: An model object instance of a Django group
        :return: Nothing
        """
        users = User.objects.filter(groups__name=self.ldap_group_name)
        for user in users:
            for member in ldap_group_members:
                if str(user.username) == str(member.get('username')):
                    break
            else:
                group_object.user_set.remove(user)

    def _notify_new_user_added_function(self, usernames, groupname):
        """
        :param usernames: Should be a list of usernames from Active Directory
        :param groupname: Should be a string of groupname in Django
        :return: Nothing

        This function should be called when a new user has been added to a django group if notify_new_user_added=True
        """
        if len(usernames) > 1:
            # Pluralize user
            user = 'Users'
        else:
            user = 'User'

        subject = u'{PORTAL_TITLE}: {PUSER} Added to Group {GROUPNAME}'.format(PORTAL_TITLE=self.notify_portal_name,
                                                                               PUSER=user,
                                                                               GROUPNAME=groupname)
        html_content = u'<h2>{PORTAL_TITLE}</h2>' \
                       u'<p>' \
                       u'New {PUSER} <b>{USERNAME}</b> has been assigned to Group {GROUPNAME}.' \
                       u'<br /><br />' \
                       u'{CUSTOM_MESSAGE}' \
                       u'<br /><br />' \
                       u'<a href="{LINK}">{LINK}</a>' \
                       u'<br /><br />' \
                       u'</p>'.format(PORTAL_TITLE=self.notify_portal_name,
                                      PUSER=user,
                                      USERNAME=unicode(usernames).strip('[]'),
                                      GROUPNAME=groupname,
                                      CUSTOM_MESSAGE=self.notify_custom_message,
                                      LINK=self.notify_portal_link,)
        msg = EmailMessage(subject, html_content, self.notify_from_email_address, self.notify_to_email_addresses)
        msg.content_subtype = "html"  # Main content is now text/html
        msg.send()