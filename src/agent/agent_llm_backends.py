"""
LLM backend adapters for the agent loop: Ollama and Anthropic chat/generate
calls, with native tool-calling support where available.
"""

import logging
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class LLMBackend:
    """Wraps Ollama / Anthropic chat & generate calls used by the agent loop."""

    def __init__(
        self,
        provider,
        tools,
        ollama_model,
        ollama_endpoint,
        anthropic_key,
        anthropic_model,
        timeout,
    ):
        self.provider = provider
        self.tools = tools
        self.ollama_model = ollama_model
        self.ollama_endpoint = ollama_endpoint
        self.anthropic_key = anthropic_key
        self.anthropic_model = anthropic_model
        self.timeout = timeout

    async def chat_with_tools(
        self, messages: List[Dict],
    ) -> Optional[Any]:
        """Call the LLM with a messages list and available tools.

        Supports both Ollama /api/chat and Anthropic /v1/messages.
        Returns raw response text/dict or None on failure.
        """
        tools_json = self.tools.get_tools_for_llm()

        if self.provider == 'ollama':
            return await self.ollama_chat(messages, tools_json)
        else:
            return await self.anthropic_chat(messages, tools_json)

    async def call_llm_text(self, prompt: str) -> Optional[str]:
        """Simple single-prompt call returning plain text (for summaries)."""
        if self.provider == 'ollama':
            return await self.ollama_generate(prompt)
        else:
            return await self.anthropic_generate(prompt)

    # ---- Ollama ---- #

    async def ollama_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Ollama /api/chat with optional tool definitions.

        IMPORTANT: ``format: "json"`` is intentionally NOT used when tools
        are provided because it prevents Ollama from generating native
        ``tool_calls`` in its response.  JSON-mode is only enabled for
        tool-less requests where we need structured text output.
        """
        try:
            # Convert tools to Ollama format
            ollama_tools = []
            for t in tools:
                func = t.get("function", t)
                ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": func.get("name", ""),
                        "description": func.get("description", ""),
                        "parameters": func.get("parameters", {}),
                    },
                })

            payload: Dict[str, Any] = {
                "model": self.ollama_model,
                "messages": messages,
                "stream": False,
            }

            if ollama_tools:
                # When tools are available, let the model decide to use
                # tool_calls OR respond with JSON text.  Do NOT force
                # format: json – it suppresses native tool calling.
                payload["tools"] = ollama_tools
            else:
                # No tools → force JSON for structured answers
                payload["format"] = "json"

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/chat", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()

                    # Check for tool_calls in response
                    msg = data.get("message", {})
                    if msg.get("tool_calls"):
                        return {"tool_calls": msg["tool_calls"]}

                    # Plain content
                    content = msg.get("content", "")
                    return content

        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama chat failed: {exc}", exc_info=True)
            return None

    async def ollama_generate(self, prompt: str) -> Optional[str]:
        """Ollama /api/generate for plain text responses."""
        try:
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{self.ollama_endpoint}/api/generate", json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Ollama generate error {resp.status}: {body[:200]}")
                        return None
                    data = await resp.json()
                    return data.get("response", "")
        except aiohttp.ClientConnectorError:
            logger.error(
                f"[AGENT] Cannot connect to Ollama at {self.ollama_endpoint}. "
                "Is Ollama running? Start it with: ollama serve"
            )
            return None
        except Exception as exc:
            logger.error(f"[AGENT] Ollama generate failed: {exc}")
            return None

    # ---- Anthropic ---- #

    async def anthropic_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        """Anthropic /v1/messages with tool_use support."""
        if not self.anthropic_key:
            logger.warning("[AGENT] No Anthropic API key configured")
            return None

        try:
            # Convert tools to Anthropic format
            anthropic_tools = []
            for t in tools:
                func = t.get("function", t)
                anthropic_tools.append({
                    "name": func.get("name", ""),
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {}),
                })

            # Extract system message and user messages
            system_text = ""
            api_messages = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role == "system":
                    system_text = content
                else:
                    api_messages.append({"role": role, "content": content})

            if not api_messages:
                # If everything was in "user" role, use as-is
                api_messages = [{"role": "user", "content": messages[0].get("content", "")}]

            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }

            payload: Dict[str, Any] = {
                "model": self.anthropic_model,
                "max_tokens": 4096,
                "messages": api_messages,
            }
            if system_text:
                payload["system"] = system_text
            if anthropic_tools:
                payload["tools"] = anthropic_tools

            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error(f"[AGENT] Anthropic chat error {resp.status}: {body[:300]}")
                        return None

                    data = await resp.json()
                    content_blocks = data.get("content", [])

                    # Check for tool_use blocks
                    tool_calls = []
                    text_parts = []
                    for block in content_blocks:
                        if block.get("type") == "tool_use":
                            tool_calls.append({
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": block.get("input", {}),
                                },
                            })
                        elif block.get("type") == "text":
                            text_parts.append(block.get("text", ""))

                    if tool_calls:
                        return {"tool_calls": tool_calls}

                    return "\n".join(text_parts)

        except Exception as exc:
            logger.error(f"[AGENT] Anthropic chat failed: {exc}", exc_info=True)
            return None

    async def anthropic_generate(self, prompt: str) -> Optional[str]:
        """Anthropic /v1/messages for plain text responses."""
        if not self.anthropic_key:
            return None

        try:
            headers = {
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": self.anthropic_key,
            }
            payload = {
                "model": self.anthropic_model,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            }
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    content = data.get("content", [])
                    if content and content[0].get("type") == "text":
                        return content[0].get("text", "")
                    return None
        except Exception as exc:
            logger.error(f"[AGENT] Anthropic generate failed: {exc}")
            return None
