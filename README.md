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

#### `__init__(storage_dir_path, resource_dir_path, extention_dir_path, interface_mode="GUI", listener_port=12354)`

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

TODO

## Citation

TODO
