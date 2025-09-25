# Consultoria – Desafio Final – Módulo II

**Aluno:** Lucas Ribeiro  
**Cliente:** Loja Sales  
**Data:** 26-09-2025

---

## 1. Sumário

A Loja Sales, um e-commerce em expansão hospedado em infraestrutura IaaS, enfrenta desafios crescentes de segurança, especialmente relacionados a ataques de SQL injection (SQLi), Cross-Site Scripting (XSS) e tentativas de força bruta em endpoints sensíveis. Com um time enxuto e orçamento limitado, a empresa precisa de uma abordagem prática, de rápida implementação e cobertura eficaz dos principais vetores de ataque.

### Riscos-chave identificados:

* Ataques persistentes à camada de aplicação (SQLi, XSS);
* Tentativas de acesso não autorizado por força bruta no `/login`;
* Logs descentralizados, dificultando a detecção e resposta;
* Backups realizados sem testes de restauração, aumenta o risco de perda de dados.

### Solução definitiva: Segurança em Camadas

A segurança em camadas significa proteger o sistema com várias barreiras, como uma cebola com várias cascas. Cada camada ajuda a bloquear um tipo diferente de ataque, tornando mais difícil para um hacker conseguir atingir o objetivo.

1.  **Perímetro (WAF):** Imagine uma cerca ao redor do site. O **WAF** (Web Application Firewall) é como essa cerca, que impede que ataques comuns (como tentar roubar dados ou causar falhas) cheguem até ele.
2.  **Identidade (IAM):** Isso é como garantir que somente as pessoas certas possam entrar no sistema. **IAM** (Identity and Access Management) é um sistema que gerencia quem pode acessar o quê no seu site ou banco de dados, como se fosse um controle de quem pode entrar em um prédio.
3.  **Monitoramento Centralizado (SIEM):** É como ter câmeras de segurança em todos os cantos da sua casa, monitorando tudo o que acontece. O **SIEM** coleta todos os "registros" (ou logs) do seu sistema e os coloca em um lugar único, facilitando a detecção de problemas e ataques.
4.  **Hardening:** É o processo de "fortificar" o sistema, tirando coisas desnecessárias e deixando apenas o que é realmente necessário para o funcionamento. Como tirar as brechas de uma casa para que ladrões não entrem.
5.  **Controle de Acesso:** Se refere a garantir que apenas as pessoas certas (como funcionários ou usuários) tenham acesso a informações sensíveis. Por exemplo, apenas você tem a chave do cofre.
6.  **Runbooks Simplificados de Resposta a Incidentes:** São instruções claras de como reagir rapidamente quando algo de errado acontece. Como um manual que você segue quando a casa pega fogo, para saber o que fazer para minimizar os danos.

### Ganhos Esperados durante o processo

1.  **Redução do Tempo de Detecção e Resposta (MTTD/MTTR):** Significa que, quando algo errado acontece, conseguimos perceber mais rapidamente e agir para corrigir. Ou seja, detectar e resolver problemas mais rápido.
2.  **Aumento da Proteção Contra Ataques Automatizados:** Hackers usam ferramentas automáticas para atacar sistemas. Com as camadas de segurança, aumentamos as chances de impedir esses ataques automáticos antes que eles causem danos.
3.  **Melhoria na Postura de Segurança com Ações Viáveis em Até 30 Dias:** Vamos melhorar a segurança de maneira simples e rápida, em um prazo de 30 dias, implementando as ações que trazem resultados reais no curto prazo.
4.  **Maior Controle, Rastreabilidade e Visibilidade de Incidentes:** Vai ser mais fácil ver tudo o que acontece no sistema e entender o que há de errado, ajudando a evitar que o problema aconteça de novo. Como ter uma visão clara de tudo que acontece na sua casa.

---

## 2. Escopo e Metodologia

### Escopo:

Esta consultoria aborda a segurança da infraestrutura pública da Loja Sales, focando em:

* Proteção da aplicação web (Node.js) e camada de dados (PostgreSQL);
* Gerenciamento de identidades e acessos (IAM);
* Monitoramento centralizado e alertas acionáveis;
* Procedimentos de resposta a incidentes;
* Recomendações estratégicas (80/20) com plano de 30, 90 e 180 dias.

**Fora do escopo:** revisão de código-fonte, análise profunda de segurança física ou pentest ofensivo (embora riscos tenham sido simulados para proposta).

### Metodologia:

* Levantamento de informações com base no briefing;
* Avaliação de riscos seguindo princípios do NIST CSF e OWASP Top 10;
* Proposta de arquitetura defensiva baseada em práticas de segurança em camadas;
* Priorização 80/20 das recomendações com foco em ganhos rápidos e de alto impacto;
* Aplicação do ciclo de resposta a incidentes conforme NIST SP 800-61 rev. 2.

### Responsabilidades:

* O ambiente descrito (stack, estrutura de times, incidentes) representa a realidade atual;
* A equipe da Loja Sales está disponível para execução gradual das recomendações;
* Há abertura para uso de ferramentas open-source ou freemium onde possível.

---

## 3. Arquitetura de Defesa (Camadas)

* **Internet → WAF (Web Application Firewall / CRS)**
    * **Internet:** Representa o tráfego que vem de fora, ou seja, de qualquer usuário ou hacker na internet.
    * **WAF:** O WAF é um "filtro" ou "barreira" de segurança que analisa o tráfego da internet e bloqueia ataques comuns, como SQL Injection e Cross-Site Scripting (XSS). O CRS (Core Rule Set) é um conjunto de regras de segurança que o WAF usa para identificar ataques.

* **WAF → Load Balancer (LB)**
    * Após o WAF filtrar o tráfego, ele é direcionado para o Load Balancer. O Load Balancer distribui o tráfego para várias instâncias da aplicação (em caso de alta demanda), garantindo que nenhum servidor fique sobrecarregado.

* **LB → App (Node.js)**
    * O Load Balancer envia o tráfego para a aplicação Node.js. O Node.js é o sistema responsável por rodar a lógica do e-commerce, como exibir produtos, processar compras, etc.

* **App → DB (PostgreSQL)**
    * A aplicação (Node.js) interage com o Banco de Dados (PostgreSQL) para armazenar informações, como dados de usuários, produtos, transações, etc.

* **SIEM → Logs de APP e DB**
    * O SIEM (Security Information and Event Management) coleta e correlaciona logs (registros de eventos) gerados pela aplicação e pelo banco de dados. Ele ajuda a identificar atividades suspeitas e a gerar alertas de segurança em tempo real.

* **IAM → App (Node.js)**
    * O IAM (Identity and Access Management) controla o acesso dos usuários à aplicação. Isso garante que apenas as pessoas certas (como clientes ou administradores) possam acessar determinadas funcionalidades da aplicação, utilizando autenticação (como senhas ou MFA).

### Camadas de Defesa:

* **Perímetro (WAF):** Implementação de um WAF com regras OWASP CRS (documento padrão onde se encontramos riscos de segurança mais críticos) para mitigar ataques como SQLi e XSS na borda.
* **Load Balancer:** Separação de tráfego para múltiplas instâncias de aplicação, com TLS ativo e monitoramento básico de disponibilidade.
* **Hardening de instâncias:** Atualizações automáticas, desativação de serviços não utilizados, SSH com autenticação por chave e restrição de IP.
* **Aplicação (Node.js):** Validação de entrada, sanitização, limites de requisição, autenticação robusta e rate limiting (técnica que limita o número de requisições, evitando ataques como DDoS).
* **Banco de Dados (PostgreSQL):** Controle de acesso por roles (funções/cargos), criptografia em repouso, e auditoria básica de queries suspeitas (consultas maliciosas).
* **IAM:** Uso de MFA (autenticação multifatorial) para acessos administrativos e revisão de permissões com base no princípio do menor privilégio.
* **Backups:** Garantia de snapshots regulares com verificação periódica de integridade e testes de restauração programados.

---

## 4. Monitoramento & SIEM

### Fontes de Logs

Para garantir um monitoramento centralizado e acionável, será necessário coletar logs (registros) das seguintes fontes:

* **Nginx:** Logs de acesso e erro para detectar comportamentos anômalos no tráfego, como picos de requisições suspeitas e tentativas de acesso a recursos não autorizados.
* **Aplicação (Node.js):** Logs de aplicação para identificar falhas de autenticação, exceções, tentativas de SQLi/XSS, e erros no processamento de requisições.
* **Banco de Dados (PostgreSQL):** Logs de consultas SQL para detectar padrões incomuns, como tentativas de SQLi ou queries que possam indicar exploração de vulnerabilidades.
* **Sistema Operacional (SO):** Logs de auditoria de eventos críticos do sistema, como modificações nos arquivos de configuração, falhas de segurança, ou alteração de permissões.

### Correlação de Logs (SIEM)

* **Ferramenta recomendada:** Considerando o orçamento limitado, a Loja Sales pode adotar uma solução open-source como ELK Stack (Elasticsearch, Logstash, Kibana), Graylog ou Wazuh, que é um sistema de detecção de intrusão de código aberto focado em coleta de logs. Para centralizar logs e criar painéis de monitoramento.
* **Correlação:** Utilizar regras de correlação simples para identificar padrões de ataques comuns, como SQLi e brute-force. Alertas acionáveis serão configurados para eventos como múltiplas falhas de login em um curto espaço de tempo ou tráfego malicioso detectado pelo WAF.

### Alertas e Casos de Uso

* **Tentativas de SQLi:** Acionado quando uma tentativa de injeção SQL for detectada no tráfego web.
* **Tentativas de XSS:** Alerta para qualquer entrada com scripts potencialmente maliciosos.
* **Força bruta no login:** Alerta quando ocorrer um número excessivo de falhas consecutivas no login administrativo.
* **Anomalias em Banco de Dados:** Identificação de consultas SQL anômalas ou tentativas de acesso a tabelas sensíveis.

### KPIs/Métricas

* **MTTD (Mean Time to Detect):** Tempo médio para detectar eventos de segurança críticos.
* **MTTR (Mean Time to Respond):** Tempo médio para responder a um incidente identificado.
* **Tentativas bloqueadas:** Percentual de tentativas de ataque (SQLi, XSS, brute-force) bloqueadas por regras do WAF ou por autenticação multifator.
* **Cobertura de Logs:** Percentual de instâncias que estão gerando logs e sendo monitoradas. A meta é 100% de cobertura.

---

## 5. Resposta a Incidentes (NIST IR)

A resposta a incidentes será baseada no framework NIST SP 800-61 ver. 2, com foco em procedimentos claros e simples para permitir que a equipe da Loja Sales atue de forma rápida e eficaz, considerando o time reduzido e a falta de um sistema resistente de SIEM.

### Ciclo de Resposta a Incidentes

1.  **Detecção:**
    * Identificação de incidentes a partir de alertas de monitoramento (ex.: múltiplas tentativas de login mal-sucedidas, tráfego anômalo detectado pelo WAF, erros de SQL no banco de dados).
    * Validação da origem e natureza do ataque (tentativas de SQLi, brute-force, XSS).

2.  **Contenção:**
    * Isolamento imediato das partes afetadas (ex.: bloquear IPs suspeitos, desativar endpoints vulneráveis).
    * Implementação de restrições temporárias de tráfego em caso de ataques em larga escala, enquanto o ataque é analisado.

3.  **Erradicação:**
    * Remoção de quaisquer scripts maliciosos ou acessos não autorizados.
    * Correção das vulnerabilidades exploradas, como aplicação de patches de segurança (atualização de software) e ajustes de configuração no banco de dados ou na aplicação.

4.  **Recuperação:**
    * Restauração dos sistemas a partir de backups verificados.
    * Reestabelecimento da operação normal, com monitoramento contínuo intensificado para garantir que o incidente não se repita.

5.  **Lições Aprendidas:**
    * Após o incidente, será realizada uma análise detalhada para identificar a origem e o ponto de falha.
    * A equipe deve ajustar as medidas de defesa e os processos de resposta, com foco na melhoria contínua.

### Runbooks

Serão elaborados runbooks (guias detalhados de instruções passo a passo para execução de tarefas e procedimentos operacionais repetitivos) simplificados para os incidentes mais críticos, com passos claros:

* **SQLi:** Detecção, mitigação (bloqueio de IPs, remoção de entradas maliciosas), correção de código.
* **XSS:** Identificação da origem, desinfecção de dados, patching.
* **Brute-force:** Bloqueio de IPs, notificação para o administrador de sistemas, reforce autenticação (MFA).
* **Indisponibilidade de serviço:** Passos para restaurar a operação rapidamente, com failover (transferir automaticamente as operações para o backup quando o sistema primário falha).

---

## 6. Recomendações (80/20) e Roadmap (30/90/180 dias)

### 80/20 – Foco em Resultados Rápidos

A proposta de segurança é estruturada para trazer resultados de alto impacto de forma ágil, com foco nas ações mais simples e eficazes no curto prazo (30 dias) e no médio/longo prazo (90 e 180 dias). As recomendações são divididas por fases:

### Quick Wins (30 dias)

* **WAF (Web Application Firewall):** Implementação imediata do WAF (ex.: ModSecurity com OWASP CRS) para mitigar ataques SQLi e XSS, especialmente nas interfaces públicas (login, formulários de entrada de dados).
* **Fortalecimento da autenticação:** Adição de MFA nas áreas administrativas e no painel de login, prevenindo ataques de força bruta.
* **Logs e Monitoramento Básico:** Configuração de logs centralizados usando ELK Stack, Graylog ou Wazuh para coleta dos logs de Nginx, aplicação e banco de dados.
* **Backups e Testes de Restauração:** Realização de testes periódicos de restauração de backups, garantindo que os dados possam ser recuperados com sucesso em caso de incidentes.
* **Correção de vulnerabilidades críticas:** Aplicação de patches de segurança urgentes para as versões de Node.js e PostgreSQL em uso.

### Médio Prazo (90 dias)

* **Melhoria de visibilidade (SIEM):** Expansão do monitoramento com alertas mais avançados e a implementação de correlação de logs para detectar padrões mais complexos de ataques (ex.: tentativas de escalonamento de privilégios, varredura de vulnerabilidades).
* **Revisão de Permissões de Acesso (IAM):** Reforço nas políticas de gestão de identidades (controle de privilégios mínimos e ajustes nas permissões de acesso ao banco e à aplicação).
* **Hardening da Infraestrutura:** Realização de hardening das instâncias de servidores e do banco de dados (desabilitar serviços desnecessários, configurar firewalls internos, proteger dados sensíveis).
* **Treinamento de resposta a incidentes:** Treinamento da equipe para atuar rapidamente em incidentes com base nos runbooks criados (SQLi, XSS, brute-force).

### Longo Prazo (180 dias)

* **Automação de resposta a incidentes:** Implementação de automações simples para mitigação imediata de ataques (ex.: bloqueio automático de IPs após um número XPTO de falhas de login).
* **Auditoria de Segurança Contínua:** Criação de processos contínuos de auditoria para avaliar a postura de segurança (testes periódicos de penetração, revisões de código).
* **Escalabilidade do Monitoramento:** Expansão do SIEM para monitoramento de mais fontes e integração com ferramentas avançadas de Machine Learning (aprendizado de máquina) para prever comportamentos anômalos.
* **Testes de Recuperação Completa (DRP):** Desenvolvimento e realização de testes completos de Plano de Recuperação de Desastres (DRP), simulando falhas críticas e verificando a resiliência da infraestrutura.

### Roadmap – Ações por Período

| Período | Ação Principal | Responsáveis | Status |
| :--- | :--- | :--- | :--- |
| **30 dias** | Implementação do WAF + MFA + Logs Centralizados | Equipe de DevOps/Infra | Em andamento |
| | Teste de restauração de backups | Equipe de Infra | Pendente |
| | Correção de vulnerabilidades críticas | Devs + Ops | Pendente |
| **90 dias** | Expansão do monitoramento e correlação de logs | DevOps + Security | Pendente |
| | Revisão de permissões de acesso e hardening da infra | Ops + Devs | Pendente |
| | Treinamento básico de resposta a incidentes | DevOps + Segurança | Pendente |
| **180 dias** | Automação de resposta a incidentes + auditoria contínua | Security + DevOps | Pendente |
| | Escalabilidade do monitoramento + DRP completo | Segurança + DevOps | Pendente |

---

## 7. Riscos, Custos e Responsabilidades

### Riscos

* **Orçamento limitado:** A implementação de ferramentas pode ser restringida por questões orçamentárias. Será priorizado o uso de soluções open-source e freemium.
* **Capacidade da equipe:** O time pequeno pode limitar a rapidez na execução das ações, especialmente em áreas que exigem mais tempo, como hardening de infraestrutura e automação de incidentes.
* **Dependência de recursos externos:** Algumas recomendações (como treinamentos ou ferramentas específicas) podem depender da contratação de fornecedores ou consultores externos, o que pode afetar o cronograma.

### Custos Estimados

* **WAF:** Custo de implementação de ferramentas open-source (ex.: ModSecurity) ou solução SaaS básica.
* **SIEM:** Ferramentas como ELK Stack, Graylog ou Wazuh têm custo baixo para pequenas empresas, mas podem exigir mais recursos de manutenção.
* **Autenticação Multifatorial (MFA):** Custo de implementação da solução MFA, podendo ser open-source ou solução SaaS de baixo custo.
* **Backups:** Custo de soluções de backup e armazenamento em nuvem (mínimo viável).

### Responsabilidades

* A Loja Sales tem recursos limitados, mas está disposta a adotar soluções open-source ou de baixo custo para garantir a segurança.
* A equipe está comprometida em seguir as diretrizes de segurança propostas e investir tempo para treinamento e implementação.

---

## 8. Conclusão

Esta proposta visa oferecer uma solução prática e escalável para melhorar a segurança da Loja Sales com o mínimo de investimento, maximizando a proteção em áreas críticas, como aplicação web, banco de dados e gestão de identidades. O plano 80/20 foca em quick wins e mudanças rápidas para reduzir riscos imediatos, seguidas de melhorias a médio e longo prazo.

### Próximos Passos

1.  Aprovação da proposta e orçamento.
2.  Execução das ações de 30 dias (WAF, MFA, logs centralizados).
3.  Treinamento da equipe sobre os procedimentos de segurança e resposta a incidentes.
4.  Acompanhamento contínuo e melhorias progressivas no monitoramento e infraestrutura.

### Critérios de Sucesso:

* Redução dos incidentes de segurança em 50% já no primeiro trimestre.
* Implementação de backups testados e MFA em áreas críticas dentro de 30 dias.
* Estabelecimento de um processo contínuo de monitoramento de segurança e auditoria interna.