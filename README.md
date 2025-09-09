# Cellmate

Automating browser tasks with agents can be risky. Secure your browser session with Cellmate, a lightweight sandboxing framework for browser use agents.

## Features

- Lightweight sandboxing
- Easy integration with browser use agents (BUAs)
- Configurable security policies

## Installation

Cellmate is conprised of two components: an enforcement broswser extension and a client Python package. Here is how to install them:

### Package Installation

Cellmate uses a Python client package to setup policies and control the enforcement process.

Install the cellmate client package in edit mode (ensure working directory is at the outermost `cellmate/` directory):

```bash
pip install -e .
```

Make sure you have Python 3.8 or higher installed on your system before running these commands.

### Extension Installation

Cellmate relies on browser extension for policy enforcement. Currently our implementation of the policy enforcement extension supports only chromium based browsers.

The manifest file and the service worker script of the extension is located in directory `DNR_enforcer`.

To install our extension on your chromium browser, navigate to `chrome://extensions/`, click the "Load unpacked" button located on the top left, then select the `DNR_enforcer` directory. You should see an extension named "DNR Policy Enforcer" appear on the page.

## Quick Start

For detailed description of `Cellmate` and its methods, please refer to the subsequent Documentation section.

```bash
# Example usage
from cellmate.interface import Cellmate

# Define the paths and other parameters
TASK = "Respond to the first issue on the current Gitlab repo with 'I am working on it'."
STORAGE_PATH = "/path/to/your/storage/directory"
RESOURCE_PATH = "/path/to/your/resources/directory"
EXTENSION_PATH = "/path/to/your/extension/directory"

# Instantiate an instance of the Cellmate class
cellmate = Cellmate(
    storage_dir_path=STORAGE_PATH,
    resource_dir_path=RESOURCE_PATH,
    extention_dir_path=EXTENSION_PATH
)

# Have a browser instance running with the policy enforcer extension active by this point of time
# Otherwise methods from cellmate will block until the extension received the messages sent by the client

# Initialize policies or modify existing policies for your task (Skippable if you are satisfied with exisiting policies)
# Ensure that you've setup your Anthropic API key as an environment variable
cellmate.policy_setup(task=TASK)

# Signal the browser extension to start enforcing current policies
cellmate.start_enforcement()

# Envoke the BUA here
# ENSURE that the BUA is operating on the browser instance with the extension active!

# Signal the browser extension to stop policy enforcement
cellmate.end_enforcement()
```

## Documentation

The `Cellmate` class from Cellmate's client packages allows users to setup/modify their policies and control the browser extension to start or stop policy enforcement at will.

### Methods of `Cellmate`

#### `__init__(storage_dir_path, resource_dir_path, extention_dir_path, interface_mode, listener_port)`

The `Cellmate` class constructor.

**Parameters**:

- `storage_dir_path`: The file path to the storage directory that stores user-defined policies for their repective domains.
- `resource_dir_path`: The file path to the resource directory. Within in this directory Cellmate expects sub-directories named after domains, with each directory required to contain the following:
  - `policy.json`: a default policy template for this domain.
  - `sitemap.json`: The sitemap of this domain that contains definition of its API endpoints.
  - `rules`: a directory containing rules supplied by the developers of this domain that users use to compose their policies.
- `interface_mode`: The type of interface used during policy setup. Only supports "GUI" and "CLI" modes, defaults to "GUI".
- `listener_port`: An optional integer for the listener port from which the extension receives the policy. Defaults to 12354.

#### `policy_setup(task)`

Setup a new set of policies for a given task intended for a BUA. This process is assisted by predictions from an LLM on the relevant domains for this task and a reasonable policy for the selected domains. A browser instance with the extension active should be running, as this method will be attempting to transmit the new policies to the extension once the setup phase is complete.

**Parameters**:

- `task`: A string defining the task to setup a new sets of policy for.

#### `start_enforcement()`

Signals the extension to start enforcing the current policies. A browser instance with the extension active should be running, and the extension should be initialized with some policies from a call of `policy_setup` made previously. Note that a call to `policy_setup` from a previous cellmate session is applicable, as policies received by the extension is persistent.

#### `end_enforcement()`

Signals the extension to stop enforcing the current policies. A browser instance with the extension active should be running, and the extension should be in enforcement mode from a previous call to `start_enforcement`.

## Policy Specifications

Policy defines how the sandboxing is going to be performed on a domain. A simple policy for gitlab.com could look something like this:

```
{
    "name": "gitlab_policy",
    "default": "allow_public",
    "domain": [
        "gitlab.com"
    ],
    "rules": [
        {
            "effect": "allow",
            "match": {
                "tags": [
                    "project",
                    "issue"
                ]
            },
            "description": "Allow read/write access to project issues."
        }
    ]
}

```

The `"name"` field defines the name of this policy. 

The `"domain"` field specifies the domain that this policy will be applied on. 

The `"default"` field decides what to do when the agent attempts to access an unauthorized part of this domain as specified in this policy. If this field is set to `"allow_public"`, it means that the agent will be able to access this unauthorized part, but in a way that all credentials as stripped away, as if the user has not logged in. And if this field is set to "deny", access to this part of the domain will be completely blocked.

Finally, the `"rules"` field contains a list of rules that determines how the sandboxing is going to be done on this domain, or more specifically, deciding which parts of the domains should be accessible to the agent. To make such a decision, rules in a policy needs to be matched agains the agent sitemap of the domain. 

The agent sitemap of a domain attributes semantic meaning to that domain's HTTP endpoints using `"tags"`. Below is few entries in an example sitemap we created for gitlab.

```
[    
    {
        "semantic_action": "Create new issue note",
        "url": "https://gitlab.com/api/graphql",
        "method": "POST",
        "body": {
            "operationName": "createWorkItemNote",
        },
        "tags": [
            "project",
            "issue",
            "note",
            "create"
        ]
    },
    {
        "semantic_action": "Create a personal access token for a user",
        "url": "https://gitlab.com/-/user_settings/personal_access_tokens*",
        "method": "POST",
        "body": {},
        "tags": [
            "user",
            "personal_access_token",
            "create"
        ]
   },
  ...
]
```

If the tags of an endpoint could satisfy all the tags of a rule, then this endpoint is matched by this rule, and would take the effect of the matched rule. For example, both the "project" and "issue" tags of the example policy's only rule can be found within the `"tags"` field of the first sitemap entry. This means that the entry is matched and its HTTP endpoint will be treated according to the effect of the matched rule, which will be "allowed".

For more detailed explaination on Cellmate's policy specification, please refer to [here](cellmate/policy/README.md).

## Citation

TODO
