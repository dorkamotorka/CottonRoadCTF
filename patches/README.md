# Patches

This directory provides appropriate patches to fix the intended vulnerabilities affecting the flag stores of your service: 

* `**webshop/sqli.patch**` - Patches vulnerability 1 in Flag store 1
* `**webshop/jwt_algo_confusion.patch**` - Patches vulnerability 2 in Flag store 1
* `**webshop/oauth.patch**` - Patches vulnerability 3 in Flag store 1
* `**file_server/path_traversal.patch**` - Patches vulnerability 1 in Flag store 2
* `**webshop/ssrf.patch**` - Patches vulnerability 2 in Flag store 2

For a more detailed description o a separate vulnerability, take a look at the root `README.md`.

## How to create patch

To create a patch file using the diff command, duplicate the file you are changing and give the new file a new name. 

Apply the patch the new file. Then use:

	diff -Naur <original_file> <new_file> > <patch_filename>.patch

Store the `.patch` file in the relevant directory.
