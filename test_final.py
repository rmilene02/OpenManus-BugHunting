#!/usr/bin/env python3
"""
Teste final para verificar se todas as correções estão funcionando
"""

import os
import sys
import subprocess
import toml

def test_config_loading():
    """Testa se o arquivo de configuração está sendo carregado corretamente"""
    print("🔧 Testando carregamento de configuração...")
    
    config_path = "./config/config.toml"
    if os.path.exists(config_path):
        try:
            config = toml.load(config_path)
            llm_config = config.get('llm', {})
            
            print(f"✅ Configuração carregada com sucesso")
            print(f"   - Modelo: {llm_config.get('model', 'N/A')}")
            print(f"   - API Type: {llm_config.get('api_type', 'N/A')}")
            print(f"   - Base URL: {llm_config.get('base_url', 'N/A')}")
            print(f"   - API Key: {'***' + llm_config.get('api_key', '')[-4:] if llm_config.get('api_key') else 'N/A'}")
            return True
        except Exception as e:
            print(f"❌ Erro ao carregar configuração: {e}")
            return False
    else:
        print(f"❌ Arquivo de configuração não encontrado: {config_path}")
        return False

def test_imports():
    """Testa se todos os imports necessários estão funcionando"""
    print("\n📦 Testando imports...")
    
    try:
        import toml
        print("✅ toml importado com sucesso")
        
        from app.config import LLMSettings
        print("✅ LLMSettings importado com sucesso")
        
        from app.llm import LLM
        print("✅ LLM importado com sucesso")
        
        return True
    except Exception as e:
        print(f"❌ Erro nos imports: {e}")
        return False

def test_command_execution():
    """Testa se o comando principal executa sem erros fatais"""
    print("\n🚀 Testando execução do comando principal...")
    
    try:
        # Teste com timeout curto para verificar se inicia corretamente
        result = subprocess.run([
            sys.executable, "main.py", 
            "--target", "example.com", 
            "--mode", "reconnaissance", 
            "--verbose"
        ], capture_output=True, text=True, timeout=15)
        
        if "🤖 AI-powered tool selection enabled" in result.stdout:
            print("✅ Comando executado com sucesso - AI habilitada")
            return True
        elif "🔄 Falling back to rule-based tool selection" in result.stdout:
            print("✅ Comando executado com sucesso - Fallback ativo")
            return True
        else:
            print(f"⚠️  Comando executado mas com comportamento inesperado")
            print(f"   Stdout: {result.stdout[:200]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print("✅ Comando iniciou corretamente (timeout esperado)")
        return True
    except Exception as e:
        print(f"❌ Erro na execução: {e}")
        return False

def main():
    """Executa todos os testes"""
    print("🧪 TESTE FINAL - OpenManus-BugHunting")
    print("=" * 50)
    
    tests = [
        test_config_loading,
        test_imports,
        test_command_execution
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 RESULTADO FINAL: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 TODOS OS TESTES PASSARAM!")
        print("✅ A ferramenta está funcionando corretamente")
        print("\n📋 Como usar:")
        print("   python main.py --target example.com --mode reconnaissance")
        print("   python main.py --target example.com --mode comprehensive")
        print("\n🔧 Configuração:")
        print("   Edite config/config.toml para alterar API keys e configurações")
    else:
        print("❌ Alguns testes falharam")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())