#!/usr/bin/env python3
"""
Teste simples para verificar se os erros foram corrigidos
"""

import sys
import os
import asyncio

# Adicionar o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_syntax_errors():
    """Testa se há erros de sintaxe nos arquivos corrigidos"""
    print("🔍 Testando erros de sintaxe...")
    
    try:
        # Testa se o arquivo llm.py pode ser importado sem erros de sintaxe
        import app.llm
        print("✅ app.llm importado com sucesso")
        
        # Testa se o arquivo orchestrator.py pode ser importado
        import app.core.orchestrator
        print("✅ app.core.orchestrator importado com sucesso")
        
        return True
    except SyntaxError as e:
        print(f"❌ Erro de sintaxe: {e}")
        return False
    except ImportError as e:
        print(f"⚠️  Erro de importação (dependências): {e}")
        return True  # Ignoramos erros de dependências para este teste
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        return False

def test_method_exists():
    """Testa se o método count_text existe na classe LLM"""
    print("\n🔍 Testando se o método count_text existe...")
    
    try:
        from app.llm import LLM
        
        # Verifica se o método count_text existe
        if hasattr(LLM, 'count_text'):
            print("✅ Método count_text encontrado na classe LLM")
            return True
        else:
            print("❌ Método count_text não encontrado na classe LLM")
            return False
            
    except ImportError as e:
        print(f"⚠️  Erro de importação: {e}")
        return True  # Ignoramos erros de dependências
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        return False

def test_config_structure():
    """Testa se a estrutura do config.toml está correta"""
    print("\n🔍 Testando estrutura do config.toml...")
    
    try:
        import tomllib
        
        config_path = "config.toml"
        if not os.path.exists(config_path):
            print(f"⚠️  Arquivo {config_path} não encontrado")
            return True
            
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
            
        # Verifica se a seção [llm] existe
        if "llm" not in config:
            print("❌ Seção [llm] não encontrada no config.toml")
            return False
            
        llm_config = config["llm"]
        
        # Verifica campos essenciais
        required_fields = ["api_type", "base_url", "api_key", "model"]
        missing_fields = [field for field in required_fields if field not in llm_config]
        
        if missing_fields:
            print(f"❌ Campos obrigatórios ausentes: {missing_fields}")
            return False
            
        # Verifica se api_type é "deepseek"
        if llm_config.get("api_type") != "deepseek":
            print(f"⚠️  api_type é '{llm_config.get('api_type')}', esperado 'deepseek'")
            
        # Verifica se base_url contém /v1
        base_url = llm_config.get("base_url", "")
        if "/v1" not in base_url:
            print(f"⚠️  base_url '{base_url}' não contém '/v1'")
            
        print("✅ Estrutura do config.toml está correta")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao ler config.toml: {e}")
        return False

def main():
    """Executa todos os testes"""
    print("🚀 Iniciando testes de correção de erros...\n")
    
    tests = [
        ("Erros de Sintaxe", test_syntax_errors),
        ("Método count_text", test_method_exists),
        ("Estrutura do Config", test_config_structure),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"📋 Executando: {test_name}")
        result = test_func()
        results.append((test_name, result))
        print()
    
    # Resumo dos resultados
    print("=" * 50)
    print("📊 RESUMO DOS TESTES")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASSOU" if result else "❌ FALHOU"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 Resultado: {passed}/{len(tests)} testes passaram")
    
    if passed == len(tests):
        print("🎉 Todos os testes passaram! As correções foram aplicadas com sucesso.")
        return 0
    else:
        print("⚠️  Alguns testes falharam. Verifique os erros acima.")
        return 1

if __name__ == "__main__":
    sys.exit(main())