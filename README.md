# Security Assessment

MVP desenvolvido em um projeto de extensão do curso de Engenharia de Software, alinhado ao ODS 8 (Trabalho Decente e Crescimento Econômico). O app mede o nível de maturidade em segurança digital de uma pequena empresa e gera um relatório com **nota geral de 0 a 100**, **nota por área** e um **plano de ação priorizado**. Repetir a avaliação depois das melhorias mostra a evolução (antes × depois).

## Como funciona

1. **Questionário (60% da nota):** 22 perguntas respondidas com a equipe, divididas em 6 áreas: contas e senhas, gestão de acessos, phishing e conscientização, dispositivos e rede, sites e hospedagem, backup e incidentes.
2. **Verificação técnica do domínio (40% da nota, opcional):** checagens **passivas** do domínio da própria empresa:
   - **Site:** HTTPS, redirecionamento de http para https, cabeçalhos de segurança (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), versão de servidor exposta e WordPress desatualizado;
   - **Certificado:** confiança, vencimento e versão do TLS;
   - **E-mail:** SPF (inclusive registros malformados), DMARC e DKIM.
3. **Relatório:** pode ser impresso ou salvo em PDF para entregar à empresa.

Cada item tem peso de 1 a 3. "Sim" ou OK vale 100%, "Em parte" ou Atenção vale 50%, e "Não", "Não sei" ou Falha valem 0%.

## Uso responsável

- As verificações só leem informações **públicas** (página inicial, certificado e DNS). Não há varredura de portas, força bruta nem testes de invasão.
- Use apenas **com autorização do responsável pelo domínio**. O formulário exige essa confirmação.
- Domínios que apontam para endereços internos (localhost, rede local) são bloqueados.
- O app não pede nem guarda senhas.

## Como rodar

Requisitos: Ruby 3.3 e SQLite.

```bash
bundle install
bin/rails db:prepare
bin/rails server -p 3100
```

Depois acesse http://localhost:3100.

## Testes

```bash
bin/rails test
bin/rubocop
```

## Estrutura

| Caminho | O que faz |
|---|---|
| `app/models/survey.rb` | Perguntas, pesos e recomendações |
| `app/models/scoring.rb` | Cálculo das notas e do plano de ação |
| `app/models/assessment.rb` | Avaliação salva (respostas, verificações e resultado) |
| `app/services/checks/` | Verificações passivas: `web`, `tls`, `email` e `domain` |
| `app/views/assessments/` | Formulário, lista e relatório |

> Observação: o Gemfile exige `openssl >= 3.3`. A versão 3.2.0, que vem com o Ruby 3.3, falha ao validar certificados com OpenSSL 3.4 ou mais novo ("unable to get certificate CRL") e geraria falsos alertas de certificado.
