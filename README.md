# Cellmate

## Features

- Lightweight sandboxing
- Easy integration with BUA
- Configurable security policies

## Installation

Cellmate requires some Python packages that do not come natively with Python. Please install them using pip:

```bash
pip install tk
pip install ttkbootstrap
pip install playwright
```

Install cellmate in edit mode (inside `Cellmate/` folder):

```bash
pip install -e .
```

Make sure you have Python installed on your system before running these commands.

## Usage

### Extension Installation

Cellmate relies on browser extension for policy enforcement. The manifest file and the service worker script of the extension is located in directory `DNR_enforcer`.

Currently our implementation of the policy enforcement extension supports only chromium based browsers.

To install our extension on your chromium browser, navigate to `chrome://extensions/`, click the "Load unpacked" button located on the top left, then select the `DNR_enforcer` directory. You should see an extension named "DNR Policy Enforcer" appear on the page.

### The Cellmate Package

After the extension is properly installed on your chromium browser, the next step is to import Cellmate to your BUA program and instantiate it with the required parameters. The Cellmate packages allows users to setup their policies, and subsequently transfers these policies to the browser extension for policy enforcement at the browser level.

#### Parameters

The Cellmate class constructor takes the following arguments:

- `task`: A string defining the task intended for the BUA.
- `domain_list_path`: The file path to the a json file containing a list of domains that the BUA is expected to operate on.
- `storage_dir_path`: The file path to the storage directory. Within this directory Cellmate expects sub-directories named after each domain defined in the aforementioned domain list, with each directory contain user-defined policy for its repective domain.
- `resource_dir_path`: The file path to the resource directory. Within in this directory Cellmate expects sub-directories named after domains, with each directory containing the following:
  - `policy.json`: a default policy template for this domain.
  - `sitemap.json`: The sitemap of this domain that contains definition of its API endpoints.
  - `rules`: a directory containing rules supplied by the developers of this domain that users use to compose their policies.
- `listener_port`: An optional integer for the listener port from which the extension receives the policy. Defaults to 12354.
- `enforcer_type`: An optional string for the enforcer type, currently only supports "DNR". Defaults to "DNR".

```bash
# Example usage
from Cellmate.cellmate import Cellmate

# Define the paths and other parameters
TASK = "Respond to the first issue on the current Gitlab repo with 'I am working on it'."
STORAGE_PATH = "/path/to/your/storage"
DOMAIN_LIST_PATH = "/path/to/your/domains.json"
RESOURCE_PATH = "/path/to/your/resources"

# Instantiate the Cellmate class
cellmate = Cellmate(
    task=TASK,
    storage_dir_path=STORAGE_PATH,
    domain_list_path=DOMAIN_LIST_PATH,
    resource_dir_path=RESOURCE_PATH
)

# Run the cellmate instance
cellmate.run()

# Have a browser instance running with the policy enforcer extension active by this point of time
# Otherwise cellmate.run() will block until the extension has received the user defined policy

# Envoke the BUA here
# ENSURE that the BUA is operating on the browser instance with the extension active!

```
