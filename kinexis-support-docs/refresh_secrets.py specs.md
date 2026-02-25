python app which reads 1password values from the 'RUTA IT' vault. if collects these items and writes them to env files.

There are multiple env files; e.g. one for dev and one for staging, one for prod.

the env files are self-describing. There are header properties the specify the list of items to read from the vault. for example, the env-staging file might have a header called 'items'. THe value of items might be something like 'db-staging, cache-redis, django-default' which would name the items to access in the vault. refresh-secrets.py should also generate a timestamp for when it is run. it should also contain a message digest of the contents of all the names and values that are included. this would ensure the values are not tampered with.

Consequently, when it is run, at the beginning if should read in the values and check the message digest and check that it is the same as the value stored.