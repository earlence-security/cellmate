import asyncio
import requests
from browser_use import Agent
from browser_use.browser import BrowserSession
from browser_use.llm import ChatAnthropic
from cellmate.interface import Cellmate

from dotenv import load_dotenv
load_dotenv()

task = """
Go to https://gitlab.com/macaroon777sweet-group/macaroon777sweet-project/-/issues/2 and comment that "we are working on it".
"""

# Define the paths and other parameters
TASK = task
STORAGE_PATH = "./local"
DOMAIN_LIST_PATH = "./local/domains.json"
RESOURCE_PATH = "./resource"

def main():
    # Instantiate the Cellmate class
    cellmate = Cellmate(
        task=TASK,
        storage_dir_path=STORAGE_PATH,
        domain_list_path=DOMAIN_LIST_PATH,
        resource_dir_path=RESOURCE_PATH,
        interface_mode='CLI'
    )

    # Run the cellmate instance
    cellmate.run()

    # Have a browser instance running with the policy enforcer extension active by this point of time
    # Otherwise cellmate.run() will block until the extension has received the user defined policy

    # Envoke the BUA here
    # ENSURE that the BUA is operating on the browser instance with the extension active!

    asyncio.run(run_agent())

def get_cdp_ws_url(port: int = 9222) -> str:
    resp = requests.get(f"http://localhost:{port}/json/version").json()
    return resp["webSocketDebuggerUrl"]

async def run_agent():
    agent = Agent(
        task=task,
        llm=ChatAnthropic(
            model="claude-sonnet-4-0",
            temperature=0.0,
            timeout=100,  # Increase for complex tasks
        ),
        browser_session=BrowserSession(cdp_url=get_cdp_ws_url(9222)),
    )
    await agent.run(max_steps=20)

main()
