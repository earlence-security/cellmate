import asyncio
import requests
from browser_use import Agent
from browser_use.browser import BrowserSession
from browser_use.llm import ChatAnthropic
import cellmate
from cellmate.interface import Cellmate

from dotenv import load_dotenv
load_dotenv()

task = """
Go to https://gitlab.com/macaroon777sweet-group/macaroon777sweet-project/-/issues/2 and comment that "we are working on it".
"""

# Define the paths and other parameters
TASK = task
STORAGE_PATH = "../local"
RESOURCE_PATH = "../resource"
EXTENSION_PATH = "../../../cellmate/DNR_enforcer"

def main():
    # Instantiate Cellmate
    cellmate = Cellmate(
        storage_dir_path=STORAGE_PATH,
        resource_dir_path=RESOURCE_PATH,
        interface_mode='CLI'
    )

    # Run the cellmate instance
    cellmate.policy_setup(task=TASK)
    # Signal the browser extension to start enforcing current policies
    cellmate.start_enforcement()

    # Start Browser-Use agent
    asyncio.run(run_agent())

    # Signal the browser extension to stop policy enforcement
    cellmate.end_enforcement()


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

if __name__ == "__main__":
    main()
