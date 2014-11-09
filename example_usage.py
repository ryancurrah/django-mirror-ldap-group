def mirror_approvers():
    """
    :return: A tuple with Status True or False, and a result message as Unicode

    Mirrors the VM Approvers AD Group to the VM Approvers Django group
    Sends email to portal administrators on new user added to Django group
    """
    notify_to_email_addresses = []
    admins = User.objects.filter(groups__name=settings.ADMIN_GROUP)
    for admin in admins:
        notify_to_email_addresses.append(admin.email)

    ldap_referrals = [
        {'uri': settings.AUTH_LDAP_2_SERVER_URI,
         'username': settings.AUTH_LDAP_2_BIND_DN,
         'password': settings.AUTH_LDAP_2_BIND_PASSWORD},
    ]

    # If admin notifications is on send emails
    if email_notification_settings.administrator_notification:
        notify_new_user_added = True
    else:
        notify_new_user_added = False

    mirror = mirror_ldap_group.MirrorLDAPGroup(ldap_group_base_dn='OU=Groups,DC=ACME,DC=com',
                                               ldap_uri=settings.AUTH_LDAP_1_SERVER_URI,
                                               ldap_username=settings.AUTH_LDAP_1_BIND_DN,
                                               ldap_password=settings.AUTH_LDAP_1_BIND_PASSWORD,
                                               ldap_group_name=settings.VM_APPROVER_GROUP,
                                               ldap_referrals=ldap_referrals,
                                               notify_new_user_added=notify_new_user_added,
                                               notify_to_email_addresses=notify_to_email_addresses,
                                               notify_from_email_address=settings.PORTAL_EMAIL_ADDRESS,
                                               notify_portal_name=settings.PORTAL_TITLE,
                                               notify_portal_link=settings.SITE_URL)
    status, message = mirror.mirror_ldap_group()
    return status, message
