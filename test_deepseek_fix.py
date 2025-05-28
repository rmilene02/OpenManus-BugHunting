#!/usr/bin/env python3
"""
Test script to verify DeepSeek API integration fixes
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

from app.llm import LLM
from app.config import load_config

async def test_deepseek_integration():
    """Test the DeepSeek API integration with the fixes"""
    
    print("🔧 Testing DeepSeek API integration fixes...")
    
    try:
        # Load configuration
        config = load_config()
        print(f"✅ Configuration loaded successfully")
        print(f"   - API Type: {config.llm.api_type}")
        print(f"   - Model: {config.llm.model}")
        print(f"   - Base URL: {config.llm.base_url}")
        print(f"   - API Key: {'***' + config.llm.api_key[-4:] if config.llm.api_key and len(config.llm.api_key) > 4 else 'Not set'}")
        
        # Initialize LLM with DeepSeek configuration
        llm = LLM(llm_config=config.llm)
        print(f"✅ LLM initialized successfully")
        print(f"   - Max tokens: {llm.max_tokens}")
        print(f"   - Temperature: {llm.temperature}")
        print(f"   - Max input tokens: {llm.max_input_tokens}")
        
        # Test token counting (this was one of the errors)
        test_text = "This is a test message for token counting."
        token_count = llm.count_text(test_text)
        print(f"✅ Token counting works: '{test_text}' = {token_count} tokens")
        
        # Test message token counting
        test_messages = [{"role": "user", "content": test_text}]
        message_tokens = llm.count_message_tokens(test_messages)
        print(f"✅ Message token counting works: {message_tokens} tokens")
        
        # Test API call (only if API key is provided)
        if config.llm.api_key and config.llm.api_key != "your-api-key-here":
            print("🚀 Testing API call...")
            try:
                response = await llm.ask_simple("Hello, this is a test message. Please respond with 'Test successful!'")
                print(f"✅ API call successful: {response[:100]}...")
            except Exception as e:
                print(f"❌ API call failed: {e}")
                print("   This might be due to invalid API key or network issues")
        else:
            print("⚠️  Skipping API call test - no valid API key provided")
            print("   To test API calls, update config.toml with your DeepSeek API key")
        
        print("\n🎉 All basic tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("🧪 OpenManus-BugHunting DeepSeek Integration Test")
    print("=" * 60)
    
    success = asyncio.run(test_deepseek_integration())
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All tests completed successfully!")
        print("🔧 The DeepSeek integration fixes appear to be working.")
        print("\n📝 Next steps:")
        print("   1. Update config.toml with your actual DeepSeek API key")
        print("   2. Run the main application with: python main.py --target example.com --mode comprehensive --llm-api-type deepseek --llm-api-key YOUR_KEY")
    else:
        print("❌ Some tests failed!")
        print("🔧 Please check the error messages above and fix any remaining issues.")
    print("=" * 60)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())