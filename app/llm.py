import math
import json
from typing import Dict, List, Optional, Union, Any

import tiktoken
from openai import (
    APIError,
    AsyncAzureOpenAI,
    AsyncOpenAI,
    AuthenticationError,
    OpenAIError,
    RateLimitError,
)
from openai.types.chat import ChatCompletion, ChatCompletionMessage
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from app.bedrock import BedrockClient
from app.config import LLMSettings, config
from app.exceptions import TokenLimitExceeded
from app.logger import logger  # Assuming a logger is set up in your app
from app.schema import (
    ROLE_VALUES,
    TOOL_CHOICE_TYPE,
    TOOL_CHOICE_VALUES,
    Message,
    ToolChoice,
)


REASONING_MODELS = ["o1", "o3-mini"]
MULTIMODAL_MODELS = [
    "gpt-4-vision-preview",
    "gpt-4o",
    "gpt-4o-mini",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
]

# DeepSeek models
DEEPSEEK_MODELS = [
    "deepseek-chat",
    "deepseek-coder",
    "deepseek-reasoner",
]


class TokenCounter:
    # Token constants
    BASE_MESSAGE_TOKENS = 4
    FORMAT_TOKENS = 2
    LOW_DETAIL_IMAGE_TOKENS = 85
    HIGH_DETAIL_TILE_TOKENS = 170

    # Image processing constants
    MAX_SIZE = 2048
    HIGH_DETAIL_TARGET_SHORT_SIDE = 768
    TILE_SIZE = 512

    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def count_text(self, text: str) -> int:
        """Calculate tokens for a text string"""
        return 0 if not text else len(self.tokenizer.encode(text))

    def count_image(self, image_item: dict) -> int:
        """
        Calculate tokens for an image based on detail level and dimensions

        For "low" detail: fixed 85 tokens
        For "high" detail:
        1. Scale to fit in 2048x2048 square
        2. Scale shortest side to 768px
        3. Count 512px tiles (170 tokens each)
        4. Add 85 tokens
        """
        detail = image_item.get("detail", "medium")

        # For low detail, always return fixed token count
        if detail == "low":
            return self.LOW_DETAIL_IMAGE_TOKENS

        # For medium detail (default in OpenAI), use high detail calculation
        # OpenAI doesn't specify a separate calculation for medium

        # For high detail, calculate based on dimensions if available
        if detail == "high" or detail == "medium":
            # If dimensions are provided in the image_item
            if "dimensions" in image_item:
                width, height = image_item["dimensions"]
                return self._calculate_high_detail_tokens(width, height)

        return (
            self._calculate_high_detail_tokens(1024, 1024) if detail == "high" else 1024
        )

    def _calculate_high_detail_tokens(self, width: int, height: int) -> int:
        """Calculate tokens for high detail images based on dimensions"""
        # Step 1: Scale to fit in MAX_SIZE x MAX_SIZE square
        if width > self.MAX_SIZE or height > self.MAX_SIZE:
            scale = self.MAX_SIZE / max(width, height)
            width = int(width * scale)
            height = int(height * scale)

        # Step 2: Scale so shortest side is HIGH_DETAIL_TARGET_SHORT_SIDE
        scale = self.HIGH_DETAIL_TARGET_SHORT_SIDE / min(width, height)
        scaled_width = int(width * scale)
        scaled_height = int(height * scale)

        # Step 3: Count number of 512px tiles
        tiles_x = math.ceil(scaled_width / self.TILE_SIZE)
        tiles_y = math.ceil(scaled_height / self.TILE_SIZE)
        total_tiles = tiles_x * tiles_y

        # Step 4: Calculate final token count
        return (
            total_tiles * self.HIGH_DETAIL_TILE_TOKENS
        ) + self.LOW_DETAIL_IMAGE_TOKENS

    def count_content(self, content: Union[str, List[Union[str, dict]]]) -> int:
        """Calculate tokens for message content"""
        if not content:
            return 0

        if isinstance(content, str):
            return self.count_text(content)

        token_count = 0
        for item in content:
            if isinstance(item, str):
                token_count += self.count_text(item)
            elif isinstance(item, dict):
                if "text" in item:
                    token_count += self.count_text(item["text"])
                elif "image_url" in item:
                    token_count += self.count_image(item)
        return token_count

    def count_tool_calls(self, tool_calls: List[dict]) -> int:
        """Calculate tokens for tool calls"""
        token_count = 0
        for tool_call in tool_calls:
            if "function" in tool_call:
                function = tool_call["function"]
                token_count += self.count_text(function.get("name", ""))
                token_count += self.count_text(function.get("arguments", ""))
        return token_count

    def count_message_tokens(self, messages: List[dict]) -> int:
        """Calculate the total number of tokens in a message list"""
        total_tokens = self.FORMAT_TOKENS  # Base format tokens

        for message in messages:
            tokens = self.BASE_MESSAGE_TOKENS  # Base tokens per message

            # Add role tokens
            tokens += self.count_text(message.get("role", ""))

            # Add content tokens
            if "content" in message:
                tokens += self.count_content(message["content"])

            # Add tool calls tokens
            if "tool_calls" in message:
                tokens += self.count_tool_calls(message["tool_calls"])

            # Add name and tool_call_id tokens
            tokens += self.count_text(message.get("name", ""))
            tokens += self.count_text(message.get("tool_call_id", ""))

            total_tokens += tokens

        return total_tokens


class LLM:
    _instances: Dict[str, "LLM"] = {}

    def __new__(
        cls, config_name: str = "default", llm_config: Optional[LLMSettings] = None
    ):
        if config_name not in cls._instances:
            instance = super().__new__(cls)
            instance.__init__(config_name, llm_config) # type: ignore
            cls._instances[config_name] = instance
        return cls._instances[config_name]

    def __init__(
        self, config_name: str = "default", llm_config: Optional[LLMSettings] = None
    ):
        if not hasattr(self, "client"):  # Only initialize if not already initialized
            if llm_config is None:
                llm_settings_dict = config.llm.model_dump()  # Use .model_dump() for Pydantic v2
                config_data = llm_settings_dict.get(config_name, llm_settings_dict.get("default", {}))
                llm_config = LLMSettings(**config_data) # Create LLMSettings instance
            elif isinstance(llm_config, dict): # Handle if a dict is passed
                config_data = llm_config.get(config_name, list(llm_config.values())[0] if llm_config else {})
                llm_config = LLMSettings(**config_data) # Create LLMSettings instance

            self.model = llm_config.model
            self.max_tokens = llm_config.max_tokens
            self.temperature = llm_config.temperature
            self.api_type = llm_config.api_type
            self.api_key = llm_config.api_key.get_secret_value() if llm_config.api_key else None # type: ignore
            self.api_version = llm_config.api_version
            self.base_url = str(llm_config.base_url) if llm_config.base_url else None # type: ignore

            # Add token counting related attributes
            self.total_input_tokens = 0
            self.total_completion_tokens = 0
            
            # Usar getattr para buscar max_input_tokens, default para 65536 se não existir
            # Esta é a parte crucial da correção:
            llm_config_max_tokens = getattr(llm_config, "max_input_tokens", 65536)
            if llm_config_max_tokens is None: # Cobrir o caso de o atributo existir mas ser None
                self.max_input_tokens = 65536
            else:
                self.max_input_tokens = llm_config_max_tokens

            # Initialize tokenizer
            try:
                self.tokenizer = tiktoken.encoding_for_model(self.model)
            except KeyError:
                # If the model is not in tiktoken's presets, use cl100k_base as default
                self.tokenizer = tiktoken.get_encoding("cl100k_base")

            if self.api_type == "azure":
                self.client = AsyncAzureOpenAI(
                    base_url=self.base_url, # type: ignore
                    api_key=self.api_key,
                    api_version=self.api_version,
                )
            elif self.api_type == "aws":
                self.client = BedrockClient() # type: ignore
            elif self.api_type == "deepseek":
                # DeepSeek uses OpenAI-compatible API
                self.client = AsyncOpenAI(
                    api_key=self.api_key, 
                    base_url=self.base_url or "https://api.deepseek.com"
                )
            else:
                self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url) # type: ignore

            self.token_counter = TokenCounter(self.tokenizer)

    def count_text(self, text: str) -> int:
        """Calculate the number of tokens in a text"""
        if not text:
            return 0
        return len(self.tokenizer.encode(text))

    def count_message_tokens(self, messages: List[dict]) -> int:
        return self.token_counter.count_message_tokens(messages)

    def update_token_count(self, input_tokens: int, completion_tokens: int = 0) -> None:
        """Update token counts"""
        # Only track tokens if max_input_tokens is set
        self.total_input_tokens += input_tokens
        self.total_completion_tokens += completion_tokens
        logger.info(
            f"Token usage: Input={input_tokens}, Completion={completion_tokens}, "
            f"Cumulative Input={self.total_input_tokens}, Cumulative Completion={self.total_completion_tokens}, "
            f"Total={input_tokens + completion_tokens}, Cumulative Total={self.total_input_tokens + self.total_completion_tokens}"
        )

    def check_token_limit(self, input_tokens: int) -> bool:
        """Check if token limits are exceeded"""
        if self.max_input_tokens is not None:
            return (self.total_input_tokens + input_tokens) <= self.max_input_tokens
        # If max_input_tokens is not set, always return True
        return True

    def get_limit_error_message(self, input_tokens: int) -> str:
        """Generate error message for token limit exceeded"""
        if (
            self.max_input_tokens is not None
            and (self.total_input_tokens + input_tokens) > self.max_input_tokens
        ):
            return f"Request may exceed input token limit (Current: {self.total_input_tokens}, Needed: {input_tokens}, Max: {self.max_input_tokens})"

        return "Token limit exceeded"

    @staticmethod
    def format_messages(
        messages: List[Union[dict, Message]], supports_images: bool = False
    ) -> List[dict]:
        """
        Format messages for LLM by converting them to OpenAI message format.

        Args:
            messages: List of messages that can be either dict or Message objects
            supports_images: Flag indicating if the target model supports image inputs

        Returns:
            List[dict]: List of formatted messages in OpenAI format

        Raises:
            ValueError: If messages are invalid or missing required fields
            TypeError: If unsupported message types are provided

        Examples:
            >>> msgs = [
            ...     Message.system_message("You are a helpful assistant"),
            ...     {"role": "user", "content": "Hello"},
            ...     Message.user_message("How are you?")
            ... ]
            >>> formatted = LLM.format_messages(msgs)
        """
        formatted_messages = []

        for message in messages:
            # Convert Message objects to dictionaries
            if isinstance(message, Message):
                message = message.to_dict()

            if isinstance(message, dict):
                # If message is a dict, ensure it has required fields
                if "role" not in message:
                    raise ValueError("Message dict must contain 'role' field")

                # Process base64 images if present and model supports images
                if supports_images and message.get("base64_image"):
                    # Initialize or convert content to appropriate format
                    if not message.get("content"):
                        message["content"] = []
                    elif isinstance(message["content"], str):
                        message["content"] = [
                            {"type": "text", "text": message["content"]}
                        ]
                    elif isinstance(message["content"], list):
                        # Convert string items to proper text objects
                        message["content"] = [
                            (
                                {"type": "text", "text": item}
                                if isinstance(item, str)
                                else item
                            )
                            for item in message["content"]
                        ]

                    # Add the image to content
                    message["content"].append(
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{message['base64_image']}"
                            },
                        }
                    )

                    # Remove the base64_image field
                    del message["base64_image"]
                # If model doesn't support images but message has base64_image, handle gracefully
                elif not supports_images and message.get("base64_image"):
                    # Just remove the base64_image field and keep the text content
                    del message["base64_image"]

                if "content" in message or "tool_calls" in message:
                    formatted_messages.append(message)
                # else: do not include the message
            else:
                raise TypeError(f"Unsupported message type: {type(message)}")

        # Validate all messages have required fields
        for msg in formatted_messages:
            if msg["role"] not in ROLE_VALUES:
                raise ValueError(f"Invalid role: {msg['role']}")

        return formatted_messages

    def validate_token_limits(self, messages: List[Union[dict, Message]],
                             system_msgs: Optional[List[Union[dict, Message]]] = None) -> bool:
        """
        Validate that messages fit within token limits before sending to API.

        Args:
            messages: List of conversation messages
            system_msgs: Optional system messages

        Returns:
            bool: True if within limits, False otherwise
        """
        try:
            # FIX: Se max_input_tokens não estiver configurado (é None),
            # não há limite para validar aqui. A validação real de estouro
            # ocorrerá mais tarde, ou é considerado que não há limite.
            if self.max_input_tokens is None:
                return True # Não há limite de tokens de entrada configurado.

            # Format messages
            formatted_messages = self.format_messages(messages)

            # Add system messages if provided
            if system_msgs:
                formatted_system = self.format_messages(system_msgs)
                all_messages = formatted_system + formatted_messages
            else:
                all_messages = formatted_messages

            # Calculate total tokens
            total_tokens = self.count_message_tokens(all_messages)

            # Check against limit (leave room for response)
            # Esta linha (originalmente 410) agora é segura porque já garantimos que
            # self.max_input_tokens não é None se chegamos até aqui.
            max_allowed = self.max_input_tokens - self.max_tokens # type: ignore

            if total_tokens > max_allowed:
                logger.warning(f"Token limit validation failed: {total_tokens} tokens > {max_allowed} limit")
                return False

            return True

        except Exception as e:
            logger.error(f"Error in token validation: {e}")
            return False

    def get_safe_chunk_size(self) -> int:
        """Get a safe chunk size for content splitting"""
        # Use 70% of max input tokens, leaving room for prompts and response
        if self.max_input_tokens is None:
            # Default to a reasonable chunk size if max_input_tokens is not set
            return 4096 # type: ignore
        return int(self.max_input_tokens * 0.7)


    @retry(
        wait=wait_random_exponential(min=1, max=60),
        stop=stop_after_attempt(6),
        retry=retry_if_exception_type(
            (OpenAIError, Exception, ValueError)
        ),  # Don't retry TokenLimitExceeded
    )
    async def ask_simple(self, prompt: str, temperature: Optional[float] = None) -> str:
        """
        Send a simple text prompt to the LLM and get the response.
        Automatically uses chunking if prompt is too large.

        Args:
            prompt (str): The text prompt to send
            temperature (float): Sampling temperature for the response

        Returns:
            str: The generated response
        """
        messages = [{"role": "user", "content": prompt}]

        # Check if prompt fits within token limits
        if self.validate_token_limits(messages): # type: ignore
            return await self.ask(messages, temperature=temperature) # type: ignore
        else:
            # Use chunked processing for large prompts
            logger.info("Prompt too large, using chunked processing")
            return await self.ask_chunked(
                content=prompt,
                system_prompt="You are a helpful AI assistant analyzing security data.",
                chunk_prompt_template="Analyze the following data and provide key insights:

{chunk}",
                summary_prompt="Combine the following analyses into a comprehensive summary:"
            )

    async def ask(
        self,
        messages: List[Union[dict, Message]],
        system_msgs: Optional[List[Union[dict, Message]]] = None,
        stream: bool = True,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Send a prompt to the LLM and get the response.

        Args:
            messages: List of conversation messages
            system_msgs: Optional system messages to prepend
            stream (bool): Whether to stream the response
            temperature (float): Sampling temperature for the response

        Returns:
            str: The generated response

        Raises:
            TokenLimitExceeded: If token limits are exceeded
            ValueError: If messages are invalid or response is empty
            OpenAIError: If API call fails after retries
            Exception: For unexpected errors
        """
        try:
            # Check if the model supports images
            supports_images = self.model in MULTIMODAL_MODELS

            # Format system and user messages with image support check
            if system_msgs:
                system_msgs = self.format_messages(system_msgs, supports_images) # type: ignore
                messages = system_msgs + self.format_messages(messages, supports_images) # type: ignore
            else:
                messages = self.format_messages(messages, supports_images) # type: ignore

            # Calculate input token count
            input_tokens = self.count_message_tokens(messages) # type: ignore

            # Check if token limits are exceeded
            if not self.check_token_limit(input_tokens):
                error_message = self.get_limit_error_message(input_tokens)
                # Raise a special exception that won't be retried
                raise TokenLimitExceeded(error_message)

            params: Dict[str, Any] = { # type: ignore
                "model": self.model,
                "messages": messages,
            }

            if self.model in REASONING_MODELS:
                params["max_completion_tokens"] = self.max_tokens
            else:
                params["max_tokens"] = self.max_tokens
                params["temperature"] = (
                    temperature if temperature is not None else self.temperature
                )

            if not stream:
                # Non-streaming request
                response: ChatCompletion = await self.client.chat.completions.create( # type: ignore
                    **params, stream=False
                )

                if not response.choices or not response.choices[0].message.content:
                    raise ValueError("Empty or invalid response from LLM")

                # Update token counts
                self.update_token_count(
                    response.usage.prompt_tokens, response.usage.completion_tokens # type: ignore
                )

                return response.choices[0].message.content # type: ignore

            # Streaming request, For streaming, update estimated token count before making the request
            self.update_token_count(input_tokens)

            response = await self.client.chat.completions.create(**params, stream=True) # type: ignore

            collected_messages = []
            completion_text = ""
            async for chunk in response: # type: ignore
                chunk_message = chunk.choices[0].delta.content or ""
                collected_messages.append(chunk_message)
                completion_text += chunk_message
                print(chunk_message, end="", flush=True)

            print()  # Newline after streaming
            full_response = "".join(collected_messages).strip()
            if not full_response:
                raise ValueError("Empty response from streaming LLM")

            # estimate completion tokens for streaming response
            completion_tokens = self.count_text(completion_text)
            logger.info(
                f"Estimated completion tokens for streaming response: {completion_tokens}"
            )
            self.total_completion_tokens += completion_tokens

            return full_response

        except TokenLimitExceeded:
            # Re-raise token limit errors without logging
            raise
        except ValueError:
            logger.exception(f"Validation error")
            raise
        except OpenAIError as oe:
            logger.exception(f"OpenAI API error")
            if isinstance(oe, AuthenticationError):
                logger.error("Authentication failed. Check API key.")
            elif isinstance(oe, RateLimitError):
                logger.error("Rate limit exceeded. Consider increasing retry attempts.")
            elif isinstance(oe, APIError):
                logger.error(f"API error: {oe}")
            raise
        except Exception:
            logger.exception(f"Unexpected error in ask")
            raise

    @retry(
        wait=wait_random_exponential(min=1, max=60),
        stop=stop_after_attempt(6),
        retry=retry_if_exception_type(
            (OpenAIError, Exception, ValueError)
        ),  # Don't retry TokenLimitExceeded
    )
    async def ask_with_images(
        self,
        messages: List[Union[dict, Message]],
        images: List[Union[str, dict]],
        system_msgs: Optional[List[Union[dict, Message]]] = None,
        stream: bool = False,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Send a prompt with images to the LLM and get the response.

        Args:
            messages: List of conversation messages
            images: List of image URLs or image data dictionaries
            system_msgs: Optional system messages to prepend
            stream (bool): Whether to stream the response
            temperature (float): Sampling temperature for the response

        Returns:
            str: The generated response

        Raises:
            TokenLimitExceeded: If token limits are exceeded
            ValueError: If messages are invalid or response is empty
            OpenAIError: If API call fails after retries
            Exception: For unexpected errors
        """
        try:
            # For ask_with_images, we always set supports_images to True because
            # this method should only be called with models that support images
            if self.model not in MULTIMODAL_MODELS:
                raise ValueError(
                    f"Model {self.model} does not support images. Use a model from {MULTIMODAL_MODELS}"
                )

            # Format messages with image support
            formatted_messages = self.format_messages(messages, supports_images=True) # type: ignore

            # Ensure the last message is from the user to attach images
            if not formatted_messages or formatted_messages[-1]["role"] != "user":
                raise ValueError(
                    "The last message must be from the user to attach images"
                )

            # Process the last user message to include images
            last_message = formatted_messages[-1]

            # Convert content to multimodal format if needed
            content = last_message["content"]
            multimodal_content: List[Dict[str, Any]] = ( # type: ignore
                [{"type": "text", "text": content}]
                if isinstance(content, str)
                else content # type: ignore
                if isinstance(content, list)
                else []
            )

            # Add images to content
            for image in images:
                if isinstance(image, str):
                    multimodal_content.append(
                        {"type": "image_url", "image_url": {"url": image}}
                    )
                elif isinstance(image, dict) and "url" in image:
                    multimodal_content.append({"type": "image_url", "image_url": image}) # type: ignore
                elif isinstance(image, dict) and "image_url" in image:
                    multimodal_content.append(image) # type: ignore
                else:
                    raise ValueError(f"Unsupported image format: {image}")

            # Update the message with multimodal content
            last_message["content"] = multimodal_content

            # Add system messages if provided
            if system_msgs:
                all_messages = (
                    self.format_messages(system_msgs, supports_images=True) # type: ignore
                    + formatted_messages
                )
            else:
                all_messages = formatted_messages

            # Calculate tokens and check limits
            input_tokens = self.count_message_tokens(all_messages) # type: ignore
            if not self.check_token_limit(input_tokens):
                raise TokenLimitExceeded(self.get_limit_error_message(input_tokens))

            # Set up API parameters
            params: Dict[str, Any] = { # type: ignore
                "model": self.model,
                "messages": all_messages,
                "stream": stream,
            }

            # Add model-specific parameters
            if self.model in REASONING_MODELS:
                params["max_completion_tokens"] = self.max_tokens
            else:
                params["max_tokens"] = self.max_tokens
                params["temperature"] = (
                    temperature if temperature is not None else self.temperature
                )

            # Handle non-streaming request
            if not stream:
                response: ChatCompletion = await self.client.chat.completions.create(**params) # type: ignore

                if not response.choices or not response.choices[0].message.content:
                    raise ValueError("Empty or invalid response from LLM")

                self.update_token_count(response.usage.prompt_tokens) # type: ignore
                return response.choices[0].message.content # type: ignore

            # Handle streaming request
            self.update_token_count(input_tokens)
            response = await self.client.chat.completions.create(**params) # type: ignore

            collected_messages = []
            async for chunk in response: # type: ignore
                chunk_message = chunk.choices[0].delta.content or ""
                collected_messages.append(chunk_message)
                print(chunk_message, end="", flush=True)

            print()  # Newline after streaming
            full_response = "".join(collected_messages).strip()

            if not full_response:
                raise ValueError("Empty response from streaming LLM")

            return full_response

        except TokenLimitExceeded:
            raise
        except ValueError as ve:
            logger.error(f"Validation error in ask_with_images: {ve}")
            raise
        except OpenAIError as oe:
            logger.error(f"OpenAI API error: {oe}")
            if isinstance(oe, AuthenticationError):
                logger.error("Authentication failed. Check API key.")
            elif isinstance(oe, RateLimitError):
                logger.error("Rate limit exceeded. Consider increasing retry attempts.")
            elif isinstance(oe, APIError):
                logger.error(f"API error: {oe}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in ask_with_images: {e}")
            raise

    @retry(
        wait=wait_random_exponential(min=1, max=60),
        stop=stop_after_attempt(6),
        retry=retry_if_exception_type(
            (OpenAIError, Exception, ValueError)
        ),  # Don't retry TokenLimitExceeded
    )
    async def ask_tool(
        self,
        messages: List[Union[dict, Message]],
        system_msgs: Optional[List[Union[dict, Message]]] = None,
        timeout: int = 300,
        tools: Optional[List[dict]] = None,
        tool_choice: TOOL_CHOICE_TYPE = ToolChoice.AUTO,  # type: ignore
        temperature: Optional[float] = None,
        **kwargs,
    ) -> ChatCompletionMessage | None:
        """
        Ask LLM using functions/tools and return the response.

        Args:
            messages: List of conversation messages
            system_msgs: Optional system messages to prepend
            timeout: Request timeout in seconds
            tools: List of tools to use
            tool_choice: Tool choice strategy
            temperature: Sampling temperature for the response
            **kwargs: Additional completion arguments

        Returns:
            ChatCompletionMessage: The model's response

        Raises:
            TokenLimitExceeded: If token limits are exceeded
            ValueError: If tools, tool_choice, or messages are invalid
            OpenAIError: If API call fails after retries
            Exception: For unexpected errors
        """
        try:
            # Validate tool_choice
            if tool_choice not in TOOL_CHOICE_VALUES: # type: ignore
                raise ValueError(f"Invalid tool_choice: {tool_choice}")

            # Check if the model supports images
            supports_images = self.model in MULTIMODAL_MODELS

            # Format messages
            if system_msgs:
                system_msgs = self.format_messages(system_msgs, supports_images) # type: ignore
                messages = system_msgs + self.format_messages(messages, supports_images) # type: ignore
            else:
                messages = self.format_messages(messages, supports_images) # type: ignore

            # Calculate input token count
            input_tokens = self.count_message_tokens(messages) # type: ignore

            # If there are tools, calculate token count for tool descriptions
            tools_tokens = 0
            if tools:
                for tool in tools:
                    tools_tokens += self.count_text(str(tool))

            input_tokens += tools_tokens

            # Check if token limits are exceeded
            if not self.check_token_limit(input_tokens):
                error_message = self.get_limit_error_message(input_tokens)
                # Raise a special exception that won't be retried
                raise TokenLimitExceeded(error_message)

            # Validate tools if provided
            if tools:
                for tool in tools:
                    if not isinstance(tool, dict) or "type" not in tool:
                        raise ValueError("Each tool must be a dict with 'type' field")

            # Set up the completion request
            params: Dict[str, Any] = { # type: ignore
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": tool_choice,
                "timeout": timeout,
                **kwargs,
            }

            if self.model in REASONING_MODELS:
                params["max_completion_tokens"] = self.max_tokens
            else:
                params["max_tokens"] = self.max_tokens
                params["temperature"] = (
                    temperature if temperature is not None else self.temperature
                )

            params["stream"] = False  # Always use non-streaming for tool requests
            response: ChatCompletion = await self.client.chat.completions.create( # type: ignore
                **params
            )

            # Check if response is valid
            if not response.choices or not response.choices[0].message:
                print(response)
                # raise ValueError("Invalid or empty response from LLM")
                return None

            # Update token counts
            self.update_token_count(
                response.usage.prompt_tokens, response.usage.completion_tokens # type: ignore
            )

            return response.choices[0].message

        except TokenLimitExceeded:
            # Re-raise token limit errors without logging
            raise
        except ValueError as ve:
            logger.error(f"Validation error in ask_tool: {ve}")
            raise
        except OpenAIError as oe:
            logger.error(f"OpenAI API error: {oe}")
            if isinstance(oe, AuthenticationError):
                logger.error("Authentication failed. Check API key.")
            elif isinstance(oe, RateLimitError):
                logger.error("Rate limit exceeded. Consider increasing retry attempts.")
            elif isinstance(oe, APIError):
                logger.error(f"API error: {oe}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in ask_tool: {e}")
            raise

    def chunk_content(self, content: str, max_tokens: int = None) -> List[str]: # type: ignore
        """
        Split content into chunks that fit within token limits.

        Args:
            content: The content to chunk
            max_tokens: Maximum tokens per chunk (defaults to 80% of model limit)

        Returns:
            List of content chunks
        """
        if max_tokens is None:
            # Use 80% of model limit to leave room for prompt and response
            if self.max_input_tokens is None:
                 # Default to a reasonable chunk size if max_input_tokens is not set
                max_tokens = 3276 # type: ignore
            else:
                max_tokens = int(self.max_input_tokens * 0.8)


        # If content fits in one chunk, return as is
        content_tokens = self.count_text(content)
        if content_tokens <= max_tokens: # type: ignore
            return [content]

        # Split content into smaller chunks
        chunks = []
        lines = content.split('
')
        current_chunk = ""
        current_tokens = 0

        for line in lines:
            line_tokens = self.count_text(line + '
')

            # If adding this line would exceed limit, save current chunk
            if current_tokens + line_tokens > max_tokens and current_chunk: # type: ignore
                chunks.append(current_chunk.strip())
                current_chunk = line + '
'
                current_tokens = line_tokens
            else:
                current_chunk += line + '
'
                current_tokens += line_tokens

        # Add the last chunk if it has content
        if current_chunk.strip():
            chunks.append(current_chunk.strip())

        return chunks

    def chunk_json_data(self, data: Dict[str, Any], max_tokens: int = None) -> List[Dict[str, Any]]: # type: ignore
        """
        Split JSON data into chunks that fit within token limits.

        Args:
            data: The JSON data to chunk
            max_tokens: Maximum tokens per chunk

        Returns:
            List of data chunks
        """
        if max_tokens is None:
            if self.max_input_tokens is None:
                # Default to a reasonable chunk size if max_input_tokens is not set
                max_tokens = 3276 # type: ignore
            else:
                max_tokens = int(self.max_input_tokens * 0.8)


        # Convert to JSON string to check size
        json_str = json.dumps(data, indent=2)
        total_tokens = self.count_text(json_str)

        # If data fits in one chunk, return as is
        if total_tokens <= max_tokens: # type: ignore
            return [data]

        # Split by top-level keys
        chunks = []
        current_chunk = {}
        current_tokens = 0

        for key, value in data.items():
            # Calculate tokens for this key-value pair
            item_str = json.dumps({key: value}, indent=2)
            item_tokens = self.count_text(item_str)

            # If this single item is too large, try to split it further
            if item_tokens > max_tokens: # type: ignore
                if isinstance(value, dict):
                    # Recursively chunk nested dictionaries
                    sub_chunks = self.chunk_json_data(value, max_tokens) # type: ignore
                    for i, sub_chunk in enumerate(sub_chunks):
                        chunk_key = f"{key}_part_{i+1}" if len(sub_chunks) > 1 else key
                        chunks.append({chunk_key: sub_chunk})
                elif isinstance(value, list) and len(value) > 1:
                    # Split large lists
                    mid = len(value) // 2
                    chunks.append({f"{key}_part_1": value[:mid]})
                    chunks.append({f"{key}_part_2": value[mid:]})
                else:
                    # Single large item - truncate if necessary
                    if isinstance(value, str):
                        truncated = value[:max_tokens//4]  # Rough estimate # type: ignore
                        chunks.append({f"{key}_truncated": truncated})
                    else:
                        chunks.append({key: value})
                continue

            # If adding this item would exceed limit, save current chunk
            if current_tokens + item_tokens > max_tokens and current_chunk: # type: ignore
                chunks.append(current_chunk)
                current_chunk = {key: value}
                current_tokens = item_tokens
            else:
                current_chunk[key] = value
                current_tokens += item_tokens

        # Add the last chunk if it has content
        if current_chunk:
            chunks.append(current_chunk)

        return chunks

    async def ask_chunked(self, 
                         content: str, 
                         system_prompt: str = "",
                         chunk_prompt_template: str = None, # type: ignore
                         summary_prompt: str = None) -> str: # type: ignore
        """
        Process large content by chunking it and summarizing results.

        Args:
            content: Large content to process
            system_prompt: System prompt for context
            chunk_prompt_template: Template for chunk processing (use {chunk} placeholder)
            summary_prompt: Prompt for final summary

        Returns:
            Final processed result
        """
        if chunk_prompt_template is None:
            chunk_prompt_template = "Analyze the following data:

{chunk}

Provide a concise analysis."

        if summary_prompt is None:
            summary_prompt = "Combine and summarize the following analyses into a comprehensive report:"

        # Chunk the content
        chunks = self.chunk_content(content)

        if len(chunks) == 1:
            # Content fits in one request
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": chunk_prompt_template.format(chunk=content)}) # type: ignore
            return await self.ask(messages) # type: ignore

        # Process each chunk
        chunk_results = []
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{len(chunks)}")

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": chunk_prompt_template.format(chunk=chunk)}) # type: ignore

            try:
                result = await self.ask(messages) # type: ignore
                chunk_results.append(f"Chunk {i+1} Analysis:
{result}")
            except Exception as e:
                logger.error(f"Error processing chunk {i+1}: {e}")
                chunk_results.append(f"Chunk {i+1}: Error - {str(e)}")

        # Combine results
        combined_results = "

".join(chunk_results)

        # Generate final summary
        final_messages = []
        if system_prompt:
            final_messages.append({"role": "system", "content": system_prompt})
        final_messages.append({"role": "user", "content": f"{summary_prompt}

{combined_results}"}) # type: ignore

        return await self.ask(final_messages) # type: ignore
