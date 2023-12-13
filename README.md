AWS Role Credential Plugin
---

This AAP plugin is intended to allow a credential attached to a job to assume an AWS IAM role using STS.

To install the plugin:

1.  Copy the files from this repo onto the AAP controller nodes.
2.  From a terminal session on each AAP controller node, cd to the folder you've copied the code to.
3.  Install the Python code in the AAP virtualenv on *each* controller node:

```shell
awx-python -m pip install .
```

4.  From *any* AAP controller node, run this command to register the plugin:

```shell
awx-manage setup_managed_credential_types
```

5.  Restart the AAP services:

```shell
automation-controller-service restart
```

