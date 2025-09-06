import asyncio
import requests
from browser_use import Agent
from browser_use.browser import BrowserSession
from browser_use.llm import ChatAnthropic

from dotenv import load_dotenv
load_dotenv()

task = """
Go to https://gitlab.com/macaroon777sweet-group/macaroon777sweet-project/-/issues/2 and comment that "we are working on it".
"""

def main():
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
