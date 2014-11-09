Django mirror LDAP group
========================

This module was created to easily mirror the users in active directory security groups to django groups.

Supports multiple domains for user lookups.

Schedule this function to run every x ammount of time. You can create a django managment command and run with cron or create a celery task.
