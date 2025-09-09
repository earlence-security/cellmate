from tkinter import *
import ttkbootstrap as tb
from ttkbootstrap.scrolled import ScrolledFrame
from InquirerPy import inquirer
from InquirerPy.base.control import Choice

import os
import json
import re
import threading
from typing import Literal
from flask import Flask, request, jsonify
import logging
from anthropic import Anthropic
from anthropic.types import TextBlock

from cellmate.policy.policy import Policy, Action, Sitemap

content_script_template = """const originalFetch = fetch;
const defaultAction = '{defaultAction}';
const disallowedOperations = {disallowedOperations}

fetch = function(...args) {{
    const url = typeof args[0] === 'string' ? args[0] : args[0].url;

    console.log("Fetch called with URL:", url);

    if (url.endsWith('graphql')) {{
        console.groupCollapsed("GraphQL Interceptor: Found a request");
        console.log("Full URL:", url);

        const currentFrameUrl = window.location.href;
        console.log("Current Frame URL:", currentFrameUrl);

        const init = args[1] || {{}};

        console.log("Method:", init.method || 'GET');

        if (init.headers) {{
            console.log("Headers:", init.headers);
        }}

        if (init.body) {{
            console.log("Body:", init.body);
            if (typeof init.body === 'string') {{
                try {{
                    console.log("Parsed Body:", JSON.parse(init.body));
                }} catch (e) {{
                }}
            }}
        }}
        
        let isOperationDisallowed = false;
        if (init.body && typeof init.body === 'string') {{
            try {{
                const parsedBody = JSON.parse(init.body);
                console.log("Parsed Body:", parsedBody);

                if (parsedBody.operationName && disallowedOperations.includes(parsedBody.operationName)) {{
                    isOperationDisallowed = true;
                    console.log(`Disallowed GraphQL operation detected: ${{parsedBody.operationName}}`);
                }}
            }} catch (e) {{
                // Do nothing if parsing fails, it's not a JSON body.
            }}
        }}
    
        console.groupEnd();
        
        if (isOperationDisallowed) {{
            if (defaultAction === "deny") {{
                console.warn("Blocking GraphQL request as per default action.");
                return Promise.reject(new Error("Blocked GraphQL request by Cellmate DNR Enforcer."));
            }}
            else if (defaultAction === "allow_public") {{
                console.warn("Removing credentials of GraphQL requests as per default action.");
                return originalFetch.apply(this, [url, {{
                    ...init,
                    credentials: 'omit',
                }}]);
            }}
        }}
    }}

    return originalFetch.apply(this, args);
}};

console.log("Fetch Interceptor for GraphQL is active!");

"""

class Selector:

    class GUIItemSelector:
        def __init__(self):
            self.message = ""
            self.items = []
            self.initial_selection = []
            self.recommended_items = []
            self.vars = []
            self.root = None 
            
        def create_ui(self):
            if self.root is None or not self.root.winfo_exists():
                self.root = tb.Window(themename="superhero")
                self.root.title("Item Selector")
                self.root.geometry('400x375')
            
            for widget in self.root.winfo_children():
                widget.destroy()

            label = tb.Label(master=self.root, text=self.message, font=("Helvetica",18), wraplength=375)
            label.pack(pady=10)

            frame = ScrolledFrame(master=self.root, autohide=False)
            frame.pack(padx=15, pady=10, fill=BOTH, expand=YES)
            
            self.vars = []
            for item in self.items:
                var = IntVar(value=int(item in self.initial_selection))
                self.vars.append(var)
                check_button = tb.Checkbutton(master=frame, bootstyle="success, round-toggle",
                    text=("* " + item + " *" if item in self.recommended_items else item),
                    variable=var,
                    onvalue=1,
                    offvalue=0,
                )
                check_button.pack(pady=10, padx=10, anchor=W)

            button = tb.Button(master=self.root, text="Confirm", bootstyle="success", command=self.submit)
            button.pack(pady=20)
            
        def submit(self):
            if self.root is not None:
                self.root.quit() 

        def run(self, message: str, items: list[str], initial_selection: list[str] = [], recommended_items: list[str] = []) -> list[str]:
            self.message = message
            self.items = items
            self.initial_selection = initial_selection
            self.recommended_items = recommended_items
            self.create_ui()

            if self.root is not None:
                self.root.deiconify()
                self.root.mainloop()

            result = []
            for i, selected in enumerate(self.vars):
                if selected.get():
                    result.append(self.items[i])
            
            if self.root is not None:
                self.root.withdraw()
            
            return result
    
    class CLIItemSelector:
        def __init__(self):
            pass

        def run(self, message: str, items: list[str], initial_selection: list[str] = [], recommended_items: list[str] = []) -> list[str]:
            try:
                choices = [Choice(value=item, 
                           name=("* " + item + " *" if item in recommended_items else item), 
                           enabled=(item in initial_selection)) 
                           for item in items]
                
                result = inquirer.checkbox(
                    message=message,
                    choices=choices,
                    default=initial_selection,
                    instruction="(Press <space> to toggle, <enter> to submit)",
                ).execute()
            except KeyboardInterrupt:
                print("\nSelection aborted.")
                return []
            
            return result

    def __init__(self, interface_mode: Literal["GUI", "CLI"]):
        if interface_mode == "GUI":
            self.selector = self.GUIItemSelector()
        elif interface_mode == "CLI":
            self.selector = self.CLIItemSelector()

    def run(self, message: str, items: list[str], initial_selection: list[str] = [], recommended_items: list[str] = []) -> list[str]:
        return self.selector.run(message, items, initial_selection, recommended_items)

class BinaryChoice:

    class CLIBinaryChoice:
        def __init__(self):
            pass

        def run(self, message: str, choices: list[str]):
            try:
                result = inquirer.select(
                    message=message,
                    choices=choices,
                    instruction="(Use arrow keys to navigate, <enter> to confirm)"
                ).execute()

            except KeyboardInterrupt:
                print("\nSelection aborted.")
                return []

            return result

    class GUIBinaryChoice:
        def __init__(self):
            self.message = ""
            self.choices = []
            self.root = None
            self.value = None

        def create_UI(self):
            if self.root is None or not self.root.winfo_exists():
                self.root = tb.Toplevel()
                self.root.title("Setup")
                self.root.geometry('350x200')
            
            for widget in self.root.winfo_children():
                widget.destroy()

            label = tb.Label(master=self.root, text=self.message, font=("Helvetica",18))
            label.pack(pady=10)

            button_1 = tb.Button(master=self.root, text=self.choices[0], bootstyle="success", command=self.button_1_clicked)
            button_1.pack(pady=10)

            button_2 = tb.Button(master=self.root, text=self.choices[1], bootstyle="success", command=self.button_2_clicked)
            button_2.pack(pady=10)

        def button_1_clicked(self):
            self.value = self.choices[0]
            if self.root is not None:
                self.root.quit() 
        
        def button_2_clicked(self):
            self.value = self.choices[1]
            if self.root is not None:
                self.root.quit() 
        
        def run(self, message: str, choices: list[str]):
            self.message = message
            self.choices = choices
            self.create_UI()

            if self.root is not None:
                self.root.deiconify()
                self.root.mainloop()

            return self.value
    
    def __init__(self, interface_mode: Literal["GUI", "CLI"]):
        if interface_mode == "GUI":
            self.binary_choice = self.GUIBinaryChoice()
        elif interface_mode == "CLI":
            self.binary_choice = self.CLIBinaryChoice()
    
    def run(self, message: str, choices: list[str]):
        return self.binary_choice.run(message, choices)
    

def deduplicate_rules(rules):
    """
    Removes duplicate rules from a ruleset.
    A duplicate is defined as a rule with the same urlFilter, requestMethods, action type, and requestHeaders.
    """
    seen = set()
    unique_rules = []

    for rule in rules:
        # Create a tuple representing the rule’s "behavior"
        key = (
            rule.get("condition", {}).get("urlFilter"),
            tuple(rule.get("condition", {}).get("requestMethods", [])),
            rule.get("action", {}).get("type"),
            tuple(
                (h.get("header"), h.get("operation"), h.get("value"))
                for h in rule.get("action", {}).get("requestHeaders", [])
            )
        )

        if key not in seen:
            seen.add(key)
            unique_rules.append(rule)
    
    # Reassign IDs sequentially from 1
    for idx, rule in enumerate(unique_rules, start=1):
        rule["id"] = idx

    return unique_rules


class Cellmate:

    class TransmissionServer:
        """
        Manages a Flask server for inter-process communication with a Chrome extension.

        This class runs a Flask server in a background thread and uses a shared state
        to communicate an "operation" and "rules" to a client. It blocks until a "/done"
        signal is received, allowing for a synchronous workflow.
        """
        def __init__(self, listener_port: int):
            """
            Initializes the server and starts it in a background thread.

            Args:
                listener_port: The port on which the Flask server will listen.
            """
            self.listener_port = listener_port
            self.done_event = threading.Event()
            self.current_operation = "null"
            self.current_rules = []
            self.last_status_success = False
            self.last_failure_message = ""

            self.app = Flask(__name__)

            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)

            self.app.add_url_rule("/ping", "ping", self._ping, methods=["get"])
            self.app.add_url_rule("/done", "done", self._done, methods=["post"])
            
            server_thread = threading.Thread(target=self._run_server)
            server_thread.daemon = True
            server_thread.start()
            
            print("Server starting in the background...")

        def _ping(self):
            """Handles the /ping endpoint, returning a response based on the current state."""
            if self.current_operation != "null":
                print(f"Received ping. Transmitting current operation: {self.current_operation}.")
            
            # Return the operation and rules if the operation is "setup".
            if self.current_operation == "setup":
                return jsonify({
                    "operation": self.current_operation,
                    "rules": self.current_rules
                })
            
            # Otherwise, just return the operation.
            return jsonify({"operation": self.current_operation})

        def _done(self):
            """
            Handles the /done endpoint. Signals the main thread to unblock
            and resets the server state.
            """
            print("Done signal received from extension. Resetting state.")
            
            # Get the status from the request body.
            data = request.get_json()
            self.last_status_success = data and data.get("status") == "success"
            if not self.last_status_success:
                self.last_failure_message = data.get("message")
            
            # Signal the event to unblock the waiting method.
            self.done_event.set()
            
            # Reset the server state for the next command.
            self.current_operation = "null"
            self.current_rules = []

            return jsonify({"message": "ok"})

        def _run_server(self):
            """Internal method to run the Flask server."""
            self.app.run(host="127.0.0.1", port=self.listener_port)
        
        def setup(self, rules: list[dict]):
            """
            Prepares the server to transmit a list of rules and blocks
            until a done signal is received.

            Args:
                rules: The list of rules to be sent to the extension.
            
            Returns:
                bool: True if the operation succeeded, False otherwise.
            """
            print("\nPreparing to transmit rules.")
            self.current_operation = "setup"
            self.current_rules = rules
            self.done_event.wait()
            self.done_event.clear()
            
            if self.last_status_success:
                print("Rules transmitted successfully.")
            else:
                print(f"Rules transmission failed: {self.last_failure_message}")
            
            return self.last_status_success

        def start(self):
            """
            Sets the operation to 'start' and blocks until a done signal is received.
            
            Returns:
                bool: True if the operation succeeded, False otherwise.
            """
            print("Setting operation to 'start'.")
            self.current_operation = "start"
            self.done_event.wait()
            self.done_event.clear()

            if self.last_status_success:
                print("Operation 'start' completed successfully.")
            else:
                print(f"Operation 'start' failed: {self.last_failure_message}")
                
            return self.last_status_success
            
        def finish(self):
            """
            Sets the operation to 'finish' and blocks until a done signal is received.
            
            Returns:
                bool: True if the operation succeeded, False otherwise.
            """
            print("Setting operation to 'finish'.")
            self.current_operation = "finish"
            self.done_event.wait()
            self.done_event.clear()

            if self.last_status_success:
                print("Operation 'finish' completed successfully.")
            else:
                print(f"Operation 'finish' failed: {self.last_failure_message}")
                
            return self.last_status_success

    def __init__(
            self, 
            task: str, 
            storage_dir_path: str, 
            resource_dir_path: str, 
            extention_dir_path: str,
            interface_mode: Literal["GUI", "CLI"] = "GUI", 
            listener_port: int = 12354, 
    ):
        
        self.task = task
        self.storage_dir_path = storage_dir_path
        self.listener_port = listener_port
        self.resource_dir_path = resource_dir_path
        self.extension_dir_path = extention_dir_path

        self.selector = Selector(interface_mode)
        self.binary_choice = BinaryChoice(interface_mode)

        self.server = self.TransmissionServer(listener_port=listener_port)

        self.domain_list_file_path = self.storage_dir_path + "/domains.json"
        if os.path.exists(self.domain_list_file_path) and os.path.isfile(self.domain_list_file_path):
            with open(self.domain_list_file_path, "r") as f:
                self.domain_list = json.load(f)
        else:
            self.domain_list = []
        
        self.policy_setup()

    def compile_DNR_rule(self, url: str, method: str, id: int, default_action: Literal["deny", "allow_public"], priority: int = 2, resource_types: list[str] = [], regex: str = '') -> dict:
        if default_action == "deny":
            action = { "type": "block" }
        elif default_action == "allow_public":
            action = {
                        "type": "modifyHeaders",
                        "requestHeaders": [{ "header": "cookie", "operation": "remove" }]
                        }  

        rule = {
            "id": id,
            "priority": priority,
            "action": action,
            "condition": {
                "urlFilter": '|' + re.sub(r"\{.+?\}", "*", url),
                "requestMethods": [method.lower()]
            }
        }

        # To block get request to documents the "main_frame" and "sub_frame" resource types need to be explicitly declared
        if resource_types != []:
            rule["condition"]["resourceTypes"] = resource_types
        else:
            # rule["condition"]["resourceTypes"] = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "webtransport", "webbundle", "other"]
            rule["condition"]["resourceTypes"] = ["main_frame", "sub_frame", "xmlhttprequest"]

        if regex != '':
            rule["condition"].pop("urlFilter", None)
            rule["condition"]["regexFilter"] = regex
        return rule
    
    def domain_predictor(self, task: str):
        client = Anthropic()

        prompt = """
        Extract the relevant domains mentioned in this task description and output them in JSON list format. Output only the JSON and nothing else.

        "{task}"

        Here is an example:
        Example task = "Find a deal for widescreen TV on amazon for me."
        Example output = ["amazon.com"]
        """

        message = client.messages.create(
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": prompt.format(task=task)
            }],
            model="claude-sonnet-4-20250514"
        ).content[0]

        if type(message) == TextBlock:
            output = message.text
        else:
            print("Response from the domain predictor is not of type TextBlock as expected, disgarding prediction.")
            return []

        try:
            domains = json.loads(output)
        except Exception as e:
            print(f"Parsing response from the domain predictor failed, disgarding prediction: {e}")
            return []
            
        return domains
    
    def policy_predictor(self, task: str, rules: dict[str, str]):
        client = Anthropic()

        prompt = """
        Here is a dictionary mapping permissions to their corresponding descriptions.

        {dictionary}

        Given this dictionary of permissions, I want you to select the appropriate permissions needed to complete the following task:

        {task}

        Aim to select the least privileged set of permissions.

        Output a JSON list containing the permissions you selected. Output only the JSON list and nothing else.

        """

        message = client.messages.create(
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": prompt.format(task=task, dictionary=str(rules))
            }],
            model="claude-sonnet-4-20250514"
        ).content[0]

        if type(message) == TextBlock:
            output = message.text
        else:
            print("Response from the policy predictor is not of type TextBlock as expected, disgarding prediction.")
            return []

        try:
            predicted_rules = json.loads(output)
        except Exception as e:
            print(f"Parsing response from the policy predictor failed, disgarding prediction: {e}")
            return []

        return predicted_rules

    def policy_setup(self):

        predicted_domains = self.domain_predictor(self.task)

        all_domains = predicted_domains + list(set(self.domain_list) - set(predicted_domains))

        selected_domains = self.selector.run(
            message="Select the relevant domains for your task (selected domains are AI suggested)",
            items=all_domains,
            initial_selection=predicted_domains
        )

        if len(selected_domains) == 0:
            print("No domain selected.\nDefaulting to allow public only mode.")
            
            self.server.setup([{
                "id": 1,
                "priority": 1,
                "action": {
                    "type": "modifyHeaders",
                    "requestHeaders": [{ "header": "cookie", "operation": "remove" }]
                },
                "condition": {
                    "urlFilter": "*",
                },
            }])

            return True
        else:
            domains_to_initialize = []
            for domain in selected_domains:
                policy_path = f"{self.storage_dir_path}/{domain}/policy.json"

                if not os.path.exists(policy_path):
                    domains_to_initialize.append(domain)
                    #TODO add logic for case when resource is not found
                    with open(f"{self.resource_dir_path}/{domain}/policy.json") as f:
                        policy = json.load(f)
                    
                    os.makedirs(f"{self.storage_dir_path}/{domain}", exist_ok=True)
                    with open(policy_path, "w") as f:
                        json.dump(policy, f)

            domains_to_setup = self.selector.run(
                message="Select existing domain-specific policies that you wish to edit.",
                items=list(set(selected_domains) - set(domains_to_initialize))
            )

            domains_to_setup.extend(domains_to_initialize)
            
        id_ctr = 1
        ruleset = []
        allowed_domains = []

        for domain in selected_domains:
            policy_path = f"{self.storage_dir_path}/{domain}/policy.json"

            with open(policy_path) as f:
                policy = json.load(f)

            default = policy["default"]
            
            allowed_domains.extend(policy["allowed_domains"])
            allowed_domains.extend(policy["domains"])

            if "allowed_requests" in policy:
                for allowed_request in policy["allowed_requests"]:
                    rule = {
                        "id": id_ctr,
                        "priority": 3,
                        "action": { "type": "allow" },
                        "condition": {
                            "urlFilter": '|' + allowed_request["url"],
                            "resourceTypes": ["main_frame", "sub_frame"]
                        }
                    }
                    if "method" in allowed_request:
                        rule["condition"]["requestMethods"] = [allowed_request["method"].lower()]
                    ruleset.append(rule)
                    id_ctr += 1
            
            if default != "allow_public" and default != "deny": 
                print("Invalid default value for policy!")
                return False

            # policy setup            
            if domain in domains_to_setup:
                rule_path = f"{self.resource_dir_path}/{domain}/rules"

                rule_dict = {}
                for file_name in os.listdir(rule_path):
                    with open(rule_path + "/" + file_name) as f:
                        rule_json = json.load(f)
                    rule_dict[file_name.split(".")[0]] = rule_json

                predicted_rule_names = self.policy_predictor(self.task, {rule_name:rule["description"] for rule_name, rule in rule_dict.items()})

                previously_selected_rules_names = [rule["name"] for rule in policy["rules"]]

                rule_names = [file_name.split(".")[0] for file_name in os.listdir(rule_path)]

                selected_rule_names = self.selector.run(
                    message=f"Select the relevant permissions to enable on your policy for {domain}.\nAI recommended permissions are highlighted.",
                    items=rule_names,
                    initial_selection=previously_selected_rules_names,
                    recommended_items=predicted_rule_names
                )

                rules = []
                for rule_name in selected_rule_names:
                    rule = rule_dict[rule_name]
                    rule["name"] = rule_name
                    rules.append(rule)

                policy["rules"] = rules

                with open(policy_path, "w") as f:
                    json.dump(policy, f)

            # retrieve current domain's sitemap
            with open(f"{self.resource_dir_path}/{domain}/sitemap.json") as f:
                sitemap = json.load(f)

            policy = Policy.from_json(json.dumps(policy))
            sitemap_ = Sitemap(sitemap)

            disallowedGraphqlOperations = []

            # functionality based rule: deny/allow_public endpoints enumerated in the sitemap based on rules from user policy
            for endpoint in sitemap:
                evaluation_result = policy.evaluate(Action.from_endpoint(url=endpoint["url"], method=endpoint["method"], sitemap=sitemap_))
                print(f"Policy evaluation for {endpoint['method']} {endpoint['url']}: {evaluation_result}")
                if evaluation_result != "allow":
                    if "graphql" in endpoint['url']:
                        disallowedGraphqlOperations.append(endpoint['body']['operationName'])
                    else:
                        ruleset.append(self.compile_DNR_rule(endpoint["url"], endpoint["method"], id_ctr, default, resource_types=endpoint.get("resource_types", []), regex=endpoint.get("regex", ''), priority=endpoint.get("priority", 2)))
                        id_ctr += 1

                    for child in endpoint["children"]:
                        if "graphql" in child['url']:
                            disallowedGraphqlOperations.append(child['body']['operationName'])
                        else:
                            ruleset.append(self.compile_DNR_rule(child["url"], child["method"], id_ctr, default))
                            id_ctr += 1

        # navigation based rule: Disallow all requests to domains not included in policy
        ruleset.append({
            "id": id_ctr,
            "priority": 1,
            "action": { "type": "block" },
            "condition": {
                "urlFilter": "*",
                "excludedRequestDomains": list(set(allowed_domains)),
                # "resourceTypes": ["main_frame", "sub_frame"]
            }
        })
        id_ctr += 1

        # Update domain list file for when policy is initialized for new domain
        with open(self.domain_list_file_path, "w") as f:
            json.dump(list(set(self.domain_list + selected_domains)), f)

        # Deduplicating rules
        unique_ruleset = deduplicate_rules(ruleset)
        disallowedGraphqlOperations = list(set(disallowedGraphqlOperations))

        # Setup content script w.r.t the ruleset selected
        with open(self.extension_dir_path + "/content.js", "w") as f:
            f.write(content_script_template.format(defaultAction=default, disallowedOperations=str(disallowedGraphqlOperations)))
        
        # pass compiled rules to extension
        self.server.setup(unique_ruleset)

        print("Policy successfully relayed to enforcer extension.")
        return True
    
    def start_enforcement(self):
        self.server.start()

    def end_enforcement(self):
        self.server.finish()


# Example usage

# First set your Anthropic API key as a environment variable/

# if __name__ == "__main__":
#     # Initialize cellmate, policy_setup() is automatically called here to have the user config the policy then relay it to the extension
#     # At this point the extension has the policy available but have not yet started enforcing it.
#     cellmate = Cellmate(
#         task="read newest issue from gitlab", 
#         storage_dir_path="/home/henry/Research/CUA/bua-sandboxing/Cellmate/local", 
#         resource_dir_path="/home/henry/Research/CUA/bua-sandboxing/policy-demo/gitlab-demo",
#         extention_dir_path="/home/henry/Research/CUA/bua-sandboxing/Cellmate/DNR_enforcer",
#         interface_mode="CLI"
#     )

#     # Signaling the extension to start enforcing the policy
#     cellmate.start_enforcement()

#     # Agent runs here 

#     # Signaling the extension to stop enforcing the policy
#     cellmate.end_enforcement()

#     # User could use the browser unobstructed at this point of time

