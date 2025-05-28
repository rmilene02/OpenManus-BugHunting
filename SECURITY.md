# 🔒 Security Guidelines - OpenManus-BugHunting

## ⚠️ IMPORTANTE: Proteção de Dados Sensíveis

### 🚨 NUNCA Commite:
- ❌ API Keys (DeepSeek, OpenAI, Shodan, etc.)
- ❌ Tokens de autenticação
- ❌ Senhas ou credenciais
- ❌ Chaves privadas (.key, .pem)
- ❌ Certificados (.p12, .pfx)
- ❌ Resultados de scans com dados sensíveis
- ❌ Informações de targets reais

### ✅ Configuração Segura

#### 1. Usando Variáveis de Ambiente
```bash
# Copie o arquivo de exemplo
cp .env.example .env

# Edite com suas chaves reais
nano .env

# Use no comando
export DEEPSEEK_API_KEY="sua_chave_aqui"
python main.py --target example.com --mode reconnaissance --llm-api-type deepseek
```

#### 2. Configuração via Linha de Comando
```bash
# Sempre use --llm-api-key na linha de comando
python main.py --target example.com \
  --llm-api-type deepseek \
  --llm-api-key "sua_chave_aqui" \
  --mode comprehensive
```

#### 3. Arquivo de Configuração Local
```bash
# Crie um arquivo local (não versionado)
cp config/config.toml config_local.toml

# Edite suas chaves
nano config_local.toml

# Use o arquivo local
python main.py --config config_local.toml --target example.com
```

### 🛡️ Boas Práticas de Segurança

#### Para Desenvolvedores:
1. **Sempre verifique antes de commitar:**
   ```bash
   git diff --cached | grep -i "api\|key\|token\|password"
   ```

2. **Use git-secrets para proteção automática:**
   ```bash
   git secrets --install
   git secrets --register-aws
   ```

3. **Revise o histórico do git:**
   ```bash
   git log --oneline | head -10
   git show --name-only
   ```

#### Para Bug Hunters:
1. **Mantenha chaves seguras:**
   - Use gerenciadores de senha
   - Rotacione chaves regularmente
   - Não compartilhe chaves em screenshots

2. **Proteja resultados de scans:**
   - Não commite resultados com dados reais
   - Use targets de teste (httpbin.org, example.com)
   - Anonimize dados antes de compartilhar

3. **Configuração por programa:**
   ```bash
   # Crie configurações específicas
   cp config/ai/custom/rules/example_bugbounty.toml \
      config/ai/custom/rules/programa_xyz.toml
   ```

### 🔍 Verificação de Segurança

#### Verificar se há dados sensíveis:
```bash
# Procurar por possíveis chaves
grep -r "sk-" . --exclude-dir=.git
grep -r "api.*key" . --exclude-dir=.git --exclude="*.md"
grep -r "token" . --exclude-dir=.git --exclude="*.md"

# Verificar arquivos de configuração
find . -name "*.toml" -exec grep -l "api_key\|token\|password" {} \;
```

#### Limpar histórico se necessário:
```bash
# Se você commitou dados sensíveis acidentalmente
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch arquivo_com_dados_sensíveis' \
  --prune-empty --tag-name-filter cat -- --all
```

### 📋 Checklist de Segurança

Antes de cada commit:
- [ ] Verificou se não há API keys no código
- [ ] Confirmou que .env não está sendo commitado
- [ ] Revisou arquivos de configuração
- [ ] Testou com dados não sensíveis
- [ ] Verificou se resultados de scans estão no .gitignore

Antes de cada push:
- [ ] Revisou todos os commits
- [ ] Confirmou que não há dados sensíveis
- [ ] Testou a configuração em ambiente limpo
- [ ] Documentou mudanças de segurança

### 🆘 Em Caso de Exposição Acidental

Se você commitou dados sensíveis:

1. **Imediatamente:**
   ```bash
   # Revogue a chave exposta
   # Gere uma nova chave
   # Atualize suas configurações locais
   ```

2. **Limpe o repositório:**
   ```bash
   # Use BFG Repo-Cleaner ou git filter-branch
   # Force push para limpar o histórico
   git push --force-with-lease origin branch-name
   ```

3. **Notifique:**
   - Informe outros desenvolvedores
   - Atualize documentação se necessário
   - Monitore por uso indevido

### 📞 Contato de Segurança

Para reportar problemas de segurança:
- Crie uma issue privada no GitHub
- Use o template de security issue
- Inclua detalhes sobre a vulnerabilidade
- Aguarde resposta antes de divulgar publicamente

### 🔗 Recursos Adicionais

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Git Secrets Tool](https://github.com/awslabs/git-secrets)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)

---

**Lembre-se: A segurança é responsabilidade de todos! 🔒**