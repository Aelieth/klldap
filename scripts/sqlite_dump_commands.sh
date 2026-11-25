#! /bin/bash

# left out: metadata sqlite_sequence totp_steps mfa_used_proofs used_registration_starts
# totp_steps, mfa_used_proofs and used_registration_starts: their rows live minutes; a moved
# database starts without them
# server tables: jwt_refresh_storage jwt_storage password_reset_tokens

tables=("users" "policies" "ou_policies" "kerberos_policies" "kerberos_realm" "kerberos_principals" "login_lockouts" "user_activity" "mfa_windows" "groups" "memberships" "jwt_refresh_storage" "jwt_storage" "password_reset_tokens" "group_attribute_schema" "group_attributes" "user_object_classes" "group_object_classes" "system_config" "logs")
echo ".header on"

for table in "${tables[@]}"; do
    echo ".mode insert $table"
    echo "select * from $table;"
done

echo ".mode insert user_attribute_schema"
echo "select * from user_attribute_schema where user_attribute_schema_name not in ('first_name', 'last_name', 'avatar');"

echo ".mode insert user_attributes"
echo "select * from user_attributes;"
