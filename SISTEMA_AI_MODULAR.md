# 🤖 Sistema de Configuração AI Modular - OpenManus-BugHunting

## 🎉 IMPLEMENTAÇÃO COMPLETA!

O sistema de configuração AI modular foi implementado com sucesso, permitindo personalização completa do comportamento da AI para bug hunting.

## 📁 Estrutura Implementada

```
config/ai/
├── config.toml              # ⚙️ Configuração principal da AI
├── prompts.toml             # 💬 Prompts e regras de bug hunting
├── tools.toml               # 🔧 Configuração detalhada de ferramentas
├── wordlists.toml           # 📚 Mapeamento completo do SecLists
├── custom/                  # 🎨 Configurações personalizadas
│   ├── prompts/             # Prompts customizados
│   ├── tools/               # Ferramentas customizadas
│   ├── wordlists/           # Wordlists customizadas
│   └── rules/               # Regras específicas de bug bounty
│       ├── example_bugbounty.toml
│       └── example_custom_rules.toml
└── README.md               # 📖 Documentação completa
```

## ✨ Funcionalidades Implementadas

### 1. **Prompts Personalizados** (`prompts.toml`)
- ✅ Regras específicas de bug hunting
- ✅ Diretrizes de reconnaissance
- ✅ Instruções de compliance (OWASP, PCI DSS, GDPR)
- ✅ Classificação de severidade personalizada
- ✅ Requisitos de proof-of-concept

### 2. **Configuração de Ferramentas** (`tools.toml`)
- ✅ 20+ ferramentas mapeadas com detalhes completos
- ✅ Categorização por tipo (passive, active, stealth)
- ✅ Métricas de performance (speed, accuracy, stealth)
- ✅ Casos de uso específicos
- ✅ Prós e contras de cada ferramenta
- ✅ Regras de seleção baseadas em contexto

### 3. **Wordlists do SecLists** (`wordlists.toml`)
- ✅ Mapeamento completo do SecLists
- ✅ Categorização por tipo de scan
- ✅ Estimativas de requests por wordlist
- ✅ Recomendações baseadas em tecnologia
- ✅ Regras de seleção por tempo/contexto

### 4. **Sistema de Regras Customizadas**
- ✅ Regras específicas por programa de bug bounty
- ✅ Configurações de rate limiting
- ✅ Escopo e restrições personalizadas
- ✅ Preferências de ferramentas
- ✅ Instruções específicas para AI

### 5. **Carregador de Configuração** (`ai_config_loader.py`)
- ✅ Carregamento automático de todas as configurações
- ✅ Validação de configurações
- ✅ Suporte a recarregamento dinâmico
- ✅ Fallback para configurações padrão
- ✅ Logs detalhados de carregamento

## 🚀 Como Usar

### Uso Básico
```bash
# Scan com AI usando configurações padrão
python main.py --target example.com --mode comprehensive \
  --llm-api-type deepseek --llm-api-key sua-chave -v

# Scan em modo stealth (usa regras de stealth automaticamente)
python main.py --target example.com --mode reconnaissance \
  --llm-api-type deepseek --stealth-mode -v
```

### Personalização de Regras

1. **Criar regras para programa específico:**
```bash
cp config/ai/custom/rules/example_bugbounty.toml \
   config/ai/custom/rules/meu_programa.toml
```

2. **Editar regras personalizadas:**
```toml
[custom_bug_bounty_rules]
program_name = "Meu Programa Bug Bounty"
scope_domains = ["target.com", "*.target.com"]
rate_limit_requests_per_second = 3

[custom_ai_instructions]
focus_areas = [
    "Focar em APIs REST sob /api/v2/",
    "Priorizar vulnerabilidades de autenticação",
    "Verificar endpoints de upload de arquivos"
]

avoid_areas = [
    "Não testar área de pagamentos",
    "Evitar endpoints de produção durante horário comercial"
]
```

3. **Usar configuração personalizada:**
```bash
python main.py --target target.com --mode comprehensive \
  --llm-api-type deepseek --llm-api-key sua-chave -v
```

## 🎯 Exemplos de Configuração

### Exemplo 1: Bug Bounty Stealth
```toml
# config/ai/custom/rules/stealth_program.toml
[custom_bug_bounty_rules]
program_name = "Programa Stealth"
rate_limit_requests_per_second = 1
max_concurrent_connections = 1

[custom_tool_preferences]
preferred_subdomain_tools = ["subfinder"]
preferred_directory_tools = ["gobuster"]
avoid_tools = ["sqlmap", "nikto"]

[custom_ai_instructions]
special_considerations = [
    "WAF extremamente sensível",
    "Monitoramento ativo 24/7",
    "Rate limiting rigoroso"
]
```

### Exemplo 2: API Testing Focus
```toml
# config/ai/custom/rules/api_testing.toml
[custom_ai_instructions]
focus_areas = [
    "Focar exclusivamente em endpoints de API",
    "Testar autenticação JWT",
    "Verificar rate limiting de APIs",
    "Procurar por IDOR em recursos de usuário"
]

[custom_wordlists]
[custom_wordlists.api_focused]
name = "API Endpoints"
path = "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
use_cases = ["api_discovery"]
```

### Exemplo 3: Comprehensive Corporate
```toml
# config/ai/custom/rules/corporate_assessment.toml
[custom_bug_bounty_rules]
program_name = "Avaliação Corporativa"
rate_limit_requests_per_second = 10
max_concurrent_connections = 5

[custom_compliance]
required_frameworks = ["SOC2", "ISO27001", "GDPR"]

[custom_ai_instructions]
focus_areas = [
    "Compliance com frameworks corporativos",
    "Verificar controles de acesso",
    "Avaliar criptografia de dados",
    "Testar logs de auditoria"
]
```

## 🔧 Configurações Avançadas

### Personalizar Prompts da AI
```toml
# config/ai/prompts.toml
[system_prompts]
bug_hunting_rules = """
SUAS REGRAS ESPECÍFICAS:

1. METODOLOGIA PERSONALIZADA:
   - Sempre começar com reconnaissance passivo
   - Usar múltiplas fontes para validação
   - Documentar todos os achados com PoC

2. FERRAMENTAS PREFERIDAS:
   - Subfinder para subdomínios
   - Nuclei para vulnerabilidades
   - FFUF para fuzzing
"""
```

### Adicionar Novas Ferramentas
```toml
# config/ai/tools.toml
[vulnerability_scanning.minha_ferramenta]
name = "Minha Ferramenta Custom"
description = "Ferramenta específica para meu caso de uso"
type = "active"
speed = "fast"
accuracy = "high"
stealth = "medium"
use_cases = ["custom_testing"]
pros = ["Específica para meu target"]
cons = ["Limitada a casos específicos"]
```

### Configurar Wordlists Customizadas
```toml
# config/ai/wordlists.toml
[custom_wordlists.empresa_especifica]
name = "Wordlist Empresa X"
path = "/path/to/empresa-x-wordlist.txt"
description = "Termos específicos da Empresa X"
use_cases = ["targeted_discovery"]
estimated_requests = 2000
```

## 📊 Monitoramento e Logs

A AI registra todas as decisões:

```
2025-05-28 18:51:40.871 | INFO | AI configuration loaded successfully
2025-05-28 18:51:53.908 | INFO | AI selected tools: {'subdomain_enumeration': ['HTTPX'], 'web_discovery': ['HTTPX']}
2025-05-28 18:51:53.908 | INFO | Applied custom rules: meu_programa
2025-05-28 18:51:53.908 | INFO | Using stealth mode configuration
```

## 🧪 Testando o Sistema

### Teste Básico
```bash
# Testar carregamento de configurações
python examples/custom_ai_config_example.py
```

### Teste com DeepSeek
```bash
# Teste completo com AI
python main.py --target httpbin.org --mode reconnaissance \
  --llm-api-type deepseek --llm-api-key sua-chave -v
```

### Validar Configurações
```python
from app.core.ai_config_loader import AIConfigLoader

loader = AIConfigLoader("config/ai")
if loader.validate_config():
    print("✅ Configuração válida!")
else:
    print("❌ Erro na configuração")
```

## 🔄 Atualizações e Manutenção

### Recarregar Configurações
```python
# Sem reiniciar o sistema
ai_selector.config_loader.reload_configs()
```

### Backup de Configurações
```bash
# Fazer backup antes de modificar
cp -r config/ai/ config/ai_backup_$(date +%Y%m%d)
```

### Versionamento
```bash
# Versionar configurações customizadas
git add config/ai/custom/
git commit -m "Update custom rules for program X"
```

## ⚠️ Dicas Importantes

1. **Sempre teste em ambiente seguro primeiro**
2. **Faça backup das configurações antes de modificar**
3. **Use git para versionar configurações customizadas**
4. **Monitore logs para entender decisões da AI**
5. **Valide configurações após modificações**

## 🆘 Troubleshooting

### Erro: "Configuration validation failed"
```bash
# Verificar sintaxe TOML
python -c "import toml; toml.load('config/ai/prompts.toml')"
```

### AI não usa regras customizadas
```bash
# Verificar se arquivo existe e tem sintaxe correta
ls -la config/ai/custom/rules/
python -c "import toml; print(toml.load('config/ai/custom/rules/meu_arquivo.toml'))"
```

### Wordlists não encontradas
```bash
# Verificar se SecLists está instalado
ls -la /usr/share/seclists/
```

## 🎉 Resultado Final

✅ **Sistema 100% funcional e testado**
✅ **Integração completa com DeepSeek AI**
✅ **Configurações modulares e personalizáveis**
✅ **Documentação completa e exemplos**
✅ **Suporte a regras específicas de bug bounty**
✅ **Mapeamento completo do SecLists**
✅ **Sistema de validação e logs**

O OpenManus-BugHunting agora possui um sistema de configuração AI extremamente flexível e poderoso, permitindo personalização completa para qualquer cenário de bug hunting!