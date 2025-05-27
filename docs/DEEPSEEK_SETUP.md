# 🤖 DeepSeek.ai Integration Guide

Este guia mostra como configurar e usar a API da DeepSeek.ai com o OpenManus-BugHunting.

## 📋 Pré-requisitos

1. **Conta DeepSeek**: Crie uma conta em [platform.deepseek.com](https://platform.deepseek.com/)
2. **API Key**: Gere sua chave API no painel da DeepSeek
3. **Créditos**: Certifique-se de ter créditos suficientes na sua conta

## 🚀 Configuração Rápida

### Método 1: Script Automático

```bash
# Execute o script de configuração
python setup_deepseek.py
```

O script irá:
- Solicitar sua chave API
- Permitir escolher o modelo
- Criar o arquivo de configuração
- Testar a conexão

### Método 2: Configuração Manual

1. **Copie o arquivo de configuração:**
```bash
cp config/deepseek_config.toml config.toml
```

2. **Edite o arquivo `config.toml`:**
```toml
[llm.deepseek]
model = "deepseek-chat"
base_url = "https://api.deepseek.com"
api_key = "SUA_CHAVE_API_AQUI"
max_tokens = 4096
max_input_tokens = 100000
temperature = 0.7
api_type = "deepseek"
api_version = "v1"
```

3. **Defina a variável de ambiente (opcional):**
```bash
export DEEPSEEK_API_KEY="sua_chave_api_aqui"
```

## 🎯 Uso

### Comando Básico
```bash
python main.py --target example.com --mode comprehensive --llm-api-type deepseek --llm-api-key "sua_chave"
```

### Com Variável de Ambiente
```bash
export DEEPSEEK_API_KEY="sua_chave_api"
python main.py --target example.com --mode comprehensive --llm-api-type deepseek
```

### Modelos Disponíveis

| Modelo | Descrição | Uso Recomendado |
|--------|-----------|-----------------|
| `deepseek-chat` | Modelo geral de conversação | Análise geral, relatórios |
| `deepseek-coder` | Especializado em código | Análise de vulnerabilidades de código |
| `deepseek-reasoner` | Focado em raciocínio | Análise complexa, correlações |

### Exemplos de Uso

#### 1. Reconhecimento com DeepSeek Chat
```bash
python main.py \
  --target example.com \
  --mode reconnaissance \
  --llm-api-type deepseek \
  --llm-model deepseek-chat \
  --llm-api-key "sua_chave"
```

#### 2. Análise de Código com DeepSeek Coder
```bash
python main.py \
  --target https://github.com/user/repo \
  --mode comprehensive \
  --llm-api-type deepseek \
  --llm-model deepseek-coder \
  --llm-api-key "sua_chave"
```

#### 3. Análise Complexa com DeepSeek Reasoner
```bash
python main.py \
  --target example.com \
  --mode comprehensive \
  --llm-api-type deepseek \
  --llm-model deepseek-reasoner \
  --llm-api-key "sua_chave" \
  --ai-temperature 0.3
```

## ⚙️ Configurações Avançadas

### Ajuste de Temperatura
- `0.0-0.3`: Respostas mais determinísticas e focadas
- `0.4-0.7`: Balanceado (recomendado)
- `0.8-1.0`: Mais criativo e variado

### Limites de Token
```toml
[llm.deepseek]
max_tokens = 4096          # Tokens por resposta
max_input_tokens = 100000  # Limite total de entrada
```

### Base URL Personalizada
Se você usar um proxy ou endpoint personalizado:
```bash
python main.py \
  --target example.com \
  --llm-api-type deepseek \
  --llm-base-url "https://seu-proxy.com/v1" \
  --llm-api-key "sua_chave"
```

## 🔍 Verificação e Teste

### Teste de Conexão
```python
import asyncio
from openai import AsyncOpenAI

async def test_deepseek():
    client = AsyncOpenAI(
        api_key="sua_chave_api",
        base_url="https://api.deepseek.com"
    )
    
    response = await client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": "Hello!"}],
        max_tokens=50
    )
    
    print(response.choices[0].message.content)

asyncio.run(test_deepseek())
```

### Verificar Configuração
```bash
# Teste rápido sem executar scan completo
python main.py --target example.com --mode reconnaissance --llm-api-type deepseek --dry-run
```

## 💰 Custos e Limites

### Preços Aproximados (consulte o site oficial)
- **deepseek-chat**: ~$0.14/1M tokens de entrada, ~$0.28/1M tokens de saída
- **deepseek-coder**: ~$0.14/1M tokens de entrada, ~$0.28/1M tokens de saída
- **deepseek-reasoner**: Preços podem variar

### Otimização de Custos
1. **Use temperatura baixa** para respostas mais diretas
2. **Limite max_tokens** para respostas concisas
3. **Configure max_input_tokens** para controlar uso total
4. **Use modo fallback** quando AI não for crítica

## 🛠️ Troubleshooting

### Erro 401 - Unauthorized
```
❌ Error: 401 - Incorrect API key provided
```
**Solução**: Verifique se sua chave API está correta e ativa.

### Erro 429 - Rate Limit
```
❌ Error: 429 - Rate limit exceeded
```
**Solução**: Aguarde alguns minutos ou verifique seus limites de API.

### Erro 402 - Insufficient Credits
```
❌ Error: 402 - Insufficient credits
```
**Solução**: Adicione créditos à sua conta DeepSeek.

### Conexão Falha
```
❌ DeepSeek API test failed: Connection error
```
**Soluções**:
1. Verifique sua conexão com internet
2. Confirme se a URL base está correta
3. Verifique se não há firewall bloqueando

## 📊 Comparação com OpenAI

| Aspecto | DeepSeek | OpenAI GPT-4 |
|---------|----------|--------------|
| **Custo** | Mais barato | Mais caro |
| **Velocidade** | Rápido | Moderado |
| **Qualidade** | Boa | Excelente |
| **Especialização** | Código/Raciocínio | Geral |
| **Disponibilidade** | Boa | Excelente |

## 🔗 Links Úteis

- [DeepSeek Platform](https://platform.deepseek.com/)
- [Documentação da API](https://platform.deepseek.com/api-docs/)
- [Preços Atualizados](https://platform.deepseek.com/pricing)
- [Status da API](https://status.deepseek.com/)

## 📝 Exemplo Completo

```bash
# 1. Configure a chave API
export DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 2. Execute um scan completo
python main.py \
  --target example.com \
  --mode comprehensive \
  --llm-api-type deepseek \
  --llm-model deepseek-chat \
  --ai-temperature 0.7 \
  --output ./results \
  --format json \
  --verbose

# 3. Verifique os resultados
ls -la ./results/
```

## 🎉 Pronto!

Agora você pode usar a DeepSeek.ai com o OpenManus-BugHunting para análises de segurança mais inteligentes e econômicas!