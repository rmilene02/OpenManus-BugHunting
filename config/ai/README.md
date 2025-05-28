# OpenManus-BugHunting AI Configuration System

Este sistema permite personalizar completamente o comportamento da AI para seleção de ferramentas, prompts e regras de bug hunting.

## 📁 Estrutura de Arquivos

```
config/ai/
├── config.toml          # Configuração principal da AI
├── prompts.toml         # Prompts e instruções personalizadas
├── tools.toml           # Configuração de ferramentas disponíveis
├── wordlists.toml       # Configuração de wordlists e SecLists
├── custom/              # Configurações personalizadas do usuário
│   ├── prompts/         # Prompts customizados
│   ├── tools/           # Configurações de ferramentas customizadas
│   ├── wordlists/       # Wordlists customizadas
│   └── rules/           # Regras específicas de bug bounty
└── README.md           # Este arquivo
```

## 🚀 Como Usar

### 1. Configuração Básica

O arquivo `config.toml` controla o comportamento geral da AI:

```toml
[ai_settings]
enabled = true
model_preference = "deepseek-chat"
temperature = 0.1
fallback_to_rules = true

[tool_selection]
selection_strategy = "intelligent"  # conservative, balanced, intelligent, aggressive
max_tools_per_category = 3
prefer_passive_tools = false
```

### 2. Personalizando Prompts

Edite `prompts.toml` para adicionar suas regras específicas de bug hunting:

```toml
[system_prompts]
bug_hunting_rules = """
SUAS REGRAS PERSONALIZADAS AQUI:

1. SCOPE COMPLIANCE:
   - Sempre respeitar o escopo do programa de bug bounty
   - Nunca testar domínios fora do escopo
   
2. RATE LIMITING:
   - Usar rate limits conservadores
   - Implementar delays entre requests
"""
```

### 3. Configurando Ferramentas

O arquivo `tools.toml` define todas as ferramentas disponíveis:

```toml
[subdomain_enumeration.subfinder]
name = "Subfinder"
description = "Fast passive subdomain discovery tool"
type = "passive"
speed = "fast"
accuracy = "high"
stealth = "high"
use_cases = ["passive_recon", "subdomain_discovery"]
pros = ["Fast execution", "Multiple data sources"]
cons = ["Passive only", "May miss some subdomains"]
```

### 4. Configurando Wordlists

O arquivo `wordlists.toml` mapeia todas as wordlists do SecLists:

```toml
[directory_wordlists.common]
name = "Common Directories"
path = "/usr/share/seclists/Discovery/Web-Content/common.txt"
size = "small"
description = "Most common web directories and files"
use_cases = ["quick_scan", "initial_discovery"]
estimated_requests = 4614
```

### 5. Regras Customizadas

Crie arquivos em `custom/rules/` para regras específicas:

```toml
# custom/rules/meu_programa_bugbounty.toml
[custom_bug_bounty_rules]
program_name = "Meu Programa"
scope_domains = ["example.com", "*.example.com"]
out_of_scope = ["admin.example.com"]

[custom_ai_instructions]
focus_areas = [
    "Procurar por vulnerabilidades de lógica de negócio",
    "Focar em endpoints de API",
    "Priorizar falhas de autenticação"
]

avoid_areas = [
    "Não testar endpoints de pagamento",
    "Evitar testar fluxos de registro"
]
```

## 🎯 Exemplos de Uso

### Exemplo 1: Bug Bounty Stealth Mode

```bash
python main.py --target example.com --mode reconnaissance \
  --llm-api-type deepseek --stealth-mode -v
```

A AI automaticamente:
- Selecionará apenas ferramentas passivas
- Aplicará rate limits conservadores
- Usará wordlists menores
- Seguirá regras de stealth do `tools.toml`

### Exemplo 2: Scan Rápido

```bash
python main.py --target api.example.com --mode comprehensive \
  --llm-api-type deepseek --time-constraint fast -v
```

A AI automaticamente:
- Priorizará ferramentas rápidas
- Usará wordlists otimizadas para APIs
- Limitará o número de requests
- Focará em vulnerabilidades de alto impacto

### Exemplo 3: Scan Abrangente

```bash
python main.py --target webapp.example.com --mode comprehensive \
  --llm-api-type deepseek --time-constraint thorough -v
```

A AI automaticamente:
- Usará ferramentas mais completas
- Aplicará wordlists extensas
- Executará verificações detalhadas
- Incluirá testes de tecnologias específicas

## 🔧 Personalização Avançada

### Adicionando Novas Ferramentas

1. Edite `tools.toml` e adicione sua ferramenta:

```toml
[vulnerability_scanning.minha_ferramenta]
name = "Minha Ferramenta"
description = "Descrição da ferramenta"
type = "active"
speed = "medium"
accuracy = "high"
stealth = "medium"
command = "minha-ferramenta {url}"
use_cases = ["web_testing", "api_testing"]
pros = ["Vantagem 1", "Vantagem 2"]
cons = ["Desvantagem 1"]
```

### Adicionando Wordlists Customizadas

1. Edite `wordlists.toml`:

```toml
[custom_wordlists.minha_wordlist]
name = "Minha Wordlist"
path = "/path/to/minha-wordlist.txt"
description = "Wordlist específica para meu target"
use_cases = ["targeted_discovery"]
estimated_requests = 5000
```

### Criando Regras Específicas

1. Crie um arquivo em `custom/rules/`:

```toml
# custom/rules/programa_especifico.toml
[custom_bug_bounty_rules]
program_name = "Programa Específico"
rate_limit_requests_per_second = 2
max_concurrent_connections = 1

[custom_ai_instructions]
focus_areas = [
    "Este target usa tecnologia X",
    "Focar em vulnerabilidade Y",
    "Priorizar endpoint Z"
]

special_considerations = [
    "WAF muito sensível",
    "Rate limiting rigoroso",
    "Monitoramento ativo"
]
```

## 📊 Monitoramento e Logs

A AI registra todas as decisões nos logs:

```
2025-05-28 10:36:42.235 | INFO | AI tool selection for target: https://example.com
2025-05-28 10:36:42.235 | INFO | Applied custom rules: programa_especifico
2025-05-28 10:36:42.235 | INFO | Selected tools based on stealth_mode configuration
```

## 🔄 Recarregando Configurações

Para recarregar configurações sem reiniciar:

```python
# No código Python
ai_selector.config_loader.reload_configs()
```

## ⚠️ Dicas Importantes

1. **Backup**: Sempre faça backup das configurações antes de modificar
2. **Validação**: Use `validate_config()` para verificar configurações
3. **Logs**: Monitore os logs para entender as decisões da AI
4. **Testes**: Teste configurações em ambientes seguros primeiro
5. **Versionamento**: Use git para versionar suas configurações customizadas

## 🆘 Troubleshooting

### Erro: "Configuration validation failed"
- Verifique a sintaxe TOML dos arquivos
- Certifique-se de que seções obrigatórias existem
- Verifique paths de wordlists

### AI não está usando regras customizadas
- Verifique se o arquivo está em `custom/rules/`
- Confirme que a sintaxe TOML está correta
- Verifique os logs para mensagens de erro

### Wordlists não encontradas
- Verifique se o SecLists está instalado
- Confirme os paths em `wordlists.toml`
- Teste com paths absolutos

## 📚 Referências

- [TOML Specification](https://toml.io/)
- [SecLists Repository](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)