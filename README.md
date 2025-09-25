# Consultoria – Desafio Final – Módulo II

**Aluno:** Lucas Ribeiro
**Cliente:** Loja Sales
**Data:** 26-09-2025

---

## 1. Sumário

A Loja Sales é um e-commerce em expansão hospedado em infraestrutura IaaS, que enfrenta desafios crescentes de segurança relacionados a ataques de SQL injection (SQLi), Cross-Site Scripting (XSS) e tentativas de força bruta em endpoints sensíveis. Com um time enxuto e orçamento limitado, a empresa precisa de uma abordagem prática e eficaz para cobrir os principais vetores de ataque.

### Riscos-chave identificados:

* Ataques persistentes à camada de aplicação (SQLi, XSS).
* Tentativas de acesso não autorizado por força bruta no `/login`.
* Logs descentralizados, que dificultam a detecção e resposta.
* Backups realizados sem testes de restauração, aumentando o risco de perda de dados.

### Solução definitiva: Segurança em Camadas

A segurança em camadas protege o sistema com várias barreiras, como uma cebola com várias cascas, para bloquear diferentes tipos de ataques.

* **Perímetro (WAF):** O **WAF** (Web Application Firewall) atua como uma barreira que impede que ataques comuns cheguem ao site.
* **Identidade (IAM):** O **IAM** (Identity and Access Management) gerencia quem pode acessar o quê no site ou banco de dados, garantindo que apenas as pessoas certas tenham acesso.
* **Monitoramento Centralizado (SIEM):** O **SIEM** (Security Information and Event Management) coleta e centraliza todos os logs do sistema, facilitando a detecção de problemas e ataques.
* **Hardening:** É o processo de "fortificar" o sistema, removendo o que é desnecessário para o funcionamento e fechando brechas.
* **Controle de Acesso:** Garante que apenas usuários e funcionários autorizados tenham acesso a informações sensíveis.
* **Runbooks Simplificados de Resposta a Incidentes:** São manuais com instruções claras para reagir rapidamente a problemas e minimizar danos.

### Ganhos Esperados durante o processo

* **Redução do Tempo de Detecção e Resposta (MTTD/MTTR):** Permite perceber e corrigir problemas de segurança mais rapidamente.
* **Aumento da Proteção Contra Ataques Automatizados:** As camadas de segurança aumentam a capacidade de impedir ataques autom
