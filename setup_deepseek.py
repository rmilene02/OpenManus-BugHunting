#!/usr/bin/env python3
"""
Setup script for DeepSeek.ai integration with OpenManus-BugHunting
"""

import os
import sys
from pathlib import Path

def setup_deepseek_config(api_key: str, model: str = "deepseek-chat"):
    """
    Setup DeepSeek configuration
    
    Args:
        api_key: Your DeepSeek API key
        model: Model to use (deepseek-chat, deepseek-coder, deepseek-reasoner)
    """
    
    config_content = f"""# DeepSeek Configuration for OpenManus-BugHunting
# Generated automatically

[llm.deepseek]
model = "{model}"
base_url = "https://api.deepseek.com"
api_key = "{api_key}"
max_tokens = 4096
max_input_tokens = 100000
temperature = 0.7
api_type = "deepseek"
api_version = "v1"

[search]
engine = "Google"
fallback_engines = ["DuckDuckGo", "Baidu", "Bing"]
retry_delay = 60
max_retries = 3
lang = "en"
country = "us"

[browser]
headless = false
disable_security = true
max_content_length = 2000

[sandbox]
use_sandbox = false
image = "python:3.12-slim"
work_dir = "/workspace"
memory_limit = "512m"
cpu_limit = 1.0
timeout = 300
network_enabled = false
"""
    
    # Write config file
    config_path = Path("config.toml")
    with open(config_path, "w") as f:
        f.write(config_content)
    
    print(f"✅ DeepSeek configuration created: {config_path}")
    print(f"🤖 Model: {model}")
    print(f"🔑 API Key: {api_key[:8]}...{api_key[-4:]}")
    
    return config_path

def test_deepseek_connection(api_key: str, model: str = "deepseek-chat"):
    """Test DeepSeek API connection"""
    try:
        import asyncio
        from openai import AsyncOpenAI
        
        async def test_api():
            client = AsyncOpenAI(
                api_key=api_key,
                base_url="https://api.deepseek.com"
            )
            
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Hello! Can you confirm you're working?"}],
                max_tokens=50
            )
            
            return response.choices[0].message.content
        
        result = asyncio.run(test_api())
        print(f"✅ DeepSeek API test successful!")
        print(f"📝 Response: {result}")
        return True
        
    except Exception as e:
        print(f"❌ DeepSeek API test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 OpenManus-BugHunting DeepSeek Setup")
    print("=" * 50)
    
    # Get API key
    api_key = input("Enter your DeepSeek API key: ").strip()
    if not api_key:
        print("❌ API key is required!")
        sys.exit(1)
    
    # Get model choice
    models = ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"]
    print("\nAvailable models:")
    for i, model in enumerate(models, 1):
        print(f"  {i}. {model}")
    
    choice = input(f"Choose model (1-{len(models)}) [1]: ").strip()
    if not choice:
        choice = "1"
    
    try:
        model = models[int(choice) - 1]
    except (ValueError, IndexError):
        print("❌ Invalid choice, using deepseek-chat")
        model = "deepseek-chat"
    
    # Setup configuration
    config_path = setup_deepseek_config(api_key, model)
    
    # Test connection
    print("\n🔍 Testing API connection...")
    if test_deepseek_connection(api_key, model):
        print("\n🎉 Setup completed successfully!")
        print("\nYou can now run:")
        print(f"  python main.py --target example.com --mode comprehensive --llm-config deepseek")
    else:
        print("\n⚠️  Setup completed but API test failed.")
        print("Please check your API key and try again.")

if __name__ == "__main__":
    main()